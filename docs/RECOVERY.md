# Recovery and Reconciliation

## Core rule

Recover the **same logical `intent_id`**. Never infer `timeout == failure`, never
mint a new intent because a worker restarted, and never trust absence while the
venue can still act on a permit.

## Submission ordering

FAAR persists `SUBMITTED`, increments the durable submission counter, mints the
permit, and records `submission_started` before invoking the adapter. A crash can
therefore leave either:

```text
SUBMITTED + external effect occurred
SUBMITTED + no external effect occurred
```

Both reconcile first. Submitter output never decides which.

## Transition table

| Observation (independent settlement verifier) | Precondition | Result |
|---|---|---|
| `FINALIZED`, authoritative, bound to this request, valid effect id, amount inside envelope | | `FINALIZED`, usage COMMITTED |
| `CONFIRMED`, same conditions | | `CONFIRMED` (reconciles again later) |
| `PARTIALLY_FILLED`, authoritative, bound, valid effect id, 0 < amount <= authorized | | `CONFIRMED (SETTLEMENT_PARTIAL_FILL_OPEN)`, usage HELD; reconciled again later, never resubmitted |
| `CANCELLED`, authoritative, filled amount > 0 | | `FINALIZED (SETTLEMENT_CANCELLED_AFTER_PARTIAL_FILL)`, usage COMMITTED |
| `CANCELLED`, authoritative, nothing filled | no fill recorded | `FAILED_SAFE (SETTLEMENT_CANCELLED_UNFILLED)`, usage RELEASED, no resubmission under this intent |
| `CANCELLED`, authoritative, nothing filled | a fill was recorded | `STOPPED (SETTLEMENT_CANCEL_CONTRADICTS_RECORDED_EFFECT)`, usage HELD |
| `CONFIRMED`/`FINALIZED`/`PARTIALLY_FILLED`, not authoritative | | `UNKNOWN (SETTLEMENT_POSITIVE_NOT_AUTHORITATIVE)`, usage HELD |
| `CANCELLED`, not authoritative | | `UNKNOWN (SETTLEMENT_CANCEL_NOT_AUTHORITATIVE)`, usage HELD |
| `NONE`, not authoritative | | `UNKNOWN (SETTLEMENT_NONE_NOT_AUTHORITATIVE)`, usage HELD |
| `NONE`, authoritative | last attempt's permit window still open | `UNKNOWN (SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW)`, usage HELD |
| `NONE`, authoritative | window closed, a permit of this intent was consumed | `STOPPED (SETTLEMENT_NONE_AFTER_PERMIT_CONSUMED)`, usage HELD; unconsumed permits voided |
| `NONE`, authoritative | window closed, no permit consumed, resubmission blocked | `FAILED_SAFE` (deterministic adapter failure) or `STOPPED` (grant not active), usage RELEASED; unconsumed permits voided |
| `NONE`, authoritative | window closed, retry predicates hold | new submission attempt |
| `NONE`, authoritative | window closed, a retry predicate fails | `STOPPED` with the failing predicate, usage RELEASED |
| `UNKNOWN` (including a quorum short of votes because sources were unreachable) | | `UNKNOWN (SETTLEMENT_UNKNOWN)`, usage HELD |
| `CONTRADICTORY` | any authority | `STOPPED (SETTLEMENT_CONTRADICTORY)`, usage HELD |
| verifier raised (including a record that fails its own bounds) | | `UNKNOWN (RECONCILIATION_EXCEPTION)`, usage HELD |
| verifier returned something other than a `SettlementRecord`, or a record the chain cannot carry | | `STOPPED (SETTLEMENT_RECORD_MALFORMED)`, usage HELD |
| authoritative record bound to a different request | | `STOPPED (SETTLEMENT_REQUEST_BINDING_MISMATCH)`, usage HELD |
| authoritative positive record with malformed effect id | | `STOPPED (SETTLED_EFFECT_ID_INVALID)`, usage HELD |
| authoritative record contradicting a recorded effect | previous effect id known | `STOPPED (SETTLEMENT_LOST_PREVIOUS_EFFECT / SETTLEMENT_EFFECT_ID_MISMATCH)`, usage HELD |
| effect id already owned by another intent on the same venue | | `STOPPED (EFFECT_ID_ALREADY_CLAIMED)`, usage HELD |
| settled amount outside envelope | | `STOPPED (SETTLED_AMOUNT_* / PAYMENT_AMOUNT_MISMATCH)`, usage HELD |

Pre-settlement terminal paths:

| Event | Result |
|---|---|
| permit issuance refused / raised | `FAILED_SAFE (EXECUTION_PERMIT_REJECTED / EXECUTION_PERMIT_EXCEPTION)`, usage RELEASED (no capability was transported) |
| permit issuance refused because an earlier permit for this intent is still live | `UNKNOWN (EXECUTION_PERMIT_REJECTED, PERMIT_PREVIOUS_ATTEMPT_LIVE)`, usage HELD; reconcile after the recorded window |
| evidence chain refuses an append | no transition; result `EVIDENCE_INTEGRITY_FAILURE` (operator: `rebuild-evidence-head`) |
| too many abandoned adapter calls still running in this process | `STOPPED (ADAPTER_ORPHAN_LIMIT_REACHED)`, usage RELEASED (no permit was minted) |
| scope exposure cap would be exceeded | `DEFERRED (EXPOSURE_CAP_EXCEEDED)` at reservation time |
| grant not ACTIVE (paused, revoked, halted, regressed) before submission | `STOPPED (GRANT_RUNTIME_<STATUS>)`, usage RELEASED |
| grant not ACTIVE while an attempt is in flight | reconcile with resubmission blocked; effect is still recorded if found |
| adapter missing | `STOPPED (ADAPTER_NOT_CONFIGURED)`; usage RELEASED only from PROPOSED/AUTHORIZED/RESERVED |

`FAILED_SAFE` means "no effect, by independent evidence, and no retry will be
made". `STOPPED` means "a human must look". Both are terminal.

## The permit window

While a permit is unexpired, the venue may still act on it, whatever the adapter
reported: timeout, exception, deterministic rejection, receipt, or garbage. The
store writes `permit.expires_at` as `ambiguity_until` in the same transaction as
the permit and refuses to treat absence as authoritative until that instant plus
the grant's `max_clock_skew_seconds`. A new attempt therefore never overlaps an
attempt the venue may still execute: `begin_submission` resets the window, the
new permit sets it again, and the store refuses to record a second live permit
for one intent. A later permit supersedes the earlier one at consumption.

## Before resubmission

Even authoritative absence after the window does not preserve old permission.
Recheck:

- intent TTL;
- grant expiry and ACTIVE status;
- fresh authority attestation bound to the same intent;
- fresh risk attestation bound to the same intent (an older risk state version
  than one already consumed is refused);
- capability/risk gates;
- durable submission-attempt budget;
- no durable resubmission block (`EXECUTION_DETERMINISTIC_FAILURE*` persisted on
  the intent row survives across calls and workers).

If any predicate fails, do not resubmit.

## Previously observed effect disappears or changes

```text
previous_effect_id != null
AND authoritative new_effect_id != previous_effect_id
=> STOP
```

and:

```text
previous_effect_id != null
AND reconcile == authoritative NONE
=> STOP
```

A **non-authoritative** observation after a recorded effect leaves the intent
UNKNOWN; it can neither confirm nor erase history.

## Why usage remains held during ambiguity

If a $50 action may already have occurred, releasing its budget can authorize
additional exposure beyond the grant. Ambiguous reservations remain conservative
until authoritative absence after the permit window, or terminal settlement, is
proven. Turnover is a trailing 24 h window, so a held amount stops counting on its
own after a day; velocity ages out after `action_window_seconds`.

Terminalizing an intent and releasing its hold happen in one transaction. A replay
of a terminal intent whose `submission_count` is zero releases an orphaned hold
(no adapter call can have happened).

## Stale worker leases

`process()`/`reconcile()` run under a durable per-intent lease with no automatic
takeover. A worker that dies holding it leaves every later call returning
`INTENT_BUSY`. Recovery is an explicit operator action after confirming the owner
is dead and reconciling external settlement: see [`OPERATIONS.md`](OPERATIONS.md) §2.

## Restored backups

A restored store cannot know which permits and risk states were consumed in the
lost history. With an authority anchor configured, affected grant versions report
`REGRESSED` and must be closed with `revoke_after_restore`; in-flight intents from
the lost history are reconciled by hand. See [`OPERATIONS.md`](OPERATIONS.md) §5.

## Retry budget

`submission_count` is persisted so restarting the process does not reset retry
authority. The default reference limit is intentionally small.

## Crash recovery at every persistence boundary

`FINALIZED` and the usage commit are one store transaction, as are every
terminal transition and its release. `evals/run_crash_injection.py` (`make crash`)
kills a worker process immediately before each store call a clean run makes, for
six scenarios (success, timeout before and after the effect, ambiguous venue,
deterministic rejection, partial fill then cancel), then recovers exactly as
`OPERATIONS.md` §2 prescribes and asserts: at most one effect and two adapter
calls, an effect implies `FINALIZED` with usage `COMMITTED`, a terminal intent
without an effect has released its budget (unless the stop is settlement-derived),
and recovery never raises or ends non-terminal. A replay of a `FINALIZED` intent
whose budget is still `HELD` (a row written by an older version) commits it.
