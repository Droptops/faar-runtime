# FAAR Invariants

These are design targets for the reference runtime. A passing test is evidence for the tested implementation/model, not universal proof over every venue or deployment architecture. Where an invariant is enforced by a specific test it is named; the complete mapping from attack classes to tests lives in `evals/run_redteam.py`, which fails if any mapped test is missing.

## I-1 — Stable logical identity

A retry, restart, duplicate queue message, or transport error must reuse the same canonical `intent_id` for the same logical economic action. The whole `Intent`, including `metadata`, is part of the canonical identity: a retry carrying different metadata is an `IntentConflict`, not a second intent (`test_mutation_gaps.RecoveryPathTests.test_retry_with_changed_metadata_is_a_conflict_not_a_second_intent`).

## I-2 — Immutable intent semantics

Once an `intent_id` is stored, materially different canonical contents under that ID are rejected, and an id already owned by another principal is rejected before the payload is compared.

## I-3 — At-most-one successful effect per intent

For a logical intent `I`:

```text
successfulEconomicEffects(I) <= 1
```

within the semantics provided by the selected adapter/idempotency mechanism. The adversarial harness measures adapter calls and consumed permits as well as effects, because an idempotent mock venue cannot reveal a runtime double-submission on its own.

## I-4 — Denial cannot reach execution

If authority, capability, or risk evaluation denies/stops/defers an intent, the adapter must not receive a submission for that decision path. Every capability scope check, every risk limit, and every authority posture/primitive combination has a runtime-level test asserting zero adapter calls (`test_mutation_gaps`).

## I-5 — Grant contents cannot be substituted

A provisioned `(grant_id, version)` is bound to the complete canonical grant hash and principal. The parser rejects unknown grant and limit keys, so a misspelled limit cannot silently become "unbounded" inside a valid fingerprint.

## I-6 — Authority does not self-escalate

The autonomous proposal source cannot provision, broaden, unpause, or un-revoke its own grant. The runtime module contains no call to `provision_grant` or `set_grant_status`; an unprovisioned grant is `GRANT_NOT_PROVISIONED`.

## I-7 — Revocation is irreversible for a grant version

`REVOKED` cannot transition back to ACTIVE. New authority requires a new version.

## I-8 — Ambiguity is not failure

Timeouts, RPC exceptions, adapter deadlines, and non-authoritative observations are treated as UNKNOWN until reconciled. A non-authoritative observation carries no weight in either direction: it can neither confirm an effect nor erase a recorded one.

## I-9 — Authoritative absence before retry

Resubmission after ambiguity requires an adapter-independent verifier result equivalent to:

```text
status = NONE
and authoritative = true
and now > ambiguity_until + max_clock_skew_seconds
```

A weak RPC/API "not found" does not satisfy this invariant, and neither does an authoritative "not found" issued while the venue can still consume the last attempt's permit.

## I-10 — Effect identity continuity

CONFIRMED/FINALIZED settlement requires a bounded, non-empty `effect_id`. Once observed, that identity may not silently disappear or change under authoritative observation.

## I-11 — External effect identity is unique per venue

The same effect ID on the same venue cannot be claimed as the successful effect of two different FAAR intents. Identifiers are a per-venue namespace; the same string on two venues is two effects. Rows written before the namespace existed are backfilled from their canonical payload when the database is first opened, or the open fails (`test_store_hardening.SchemaMigrationTests`).

## I-12 — Retry remains authorized

Before resubmission, FAAR rechecks intent expiry, grant expiry/status, signed authority, signed risk state (monotonic version), capability/risk gates, the durable retry budget, and any durable resubmission block. A retry is a new execution attempt, not a free continuation of old authority.

## I-13 — Aggregate usage is atomic

Turnover and velocity constraints are reserved transactionally across distinct intents. Both are trailing windows (24 h and `action_window_seconds`), never calendar buckets. A money-moving intent whose amount cannot be parsed as a bounded decimal cannot reserve.

## I-14 — Risk state is single-consumption and monotonic

A `(grant_id, version, risk_scope, state_version)` authorizes at most one new economic intent, and a version older than one already consumed by any intent or retry is refused in both ledgers.

## I-15 — Upstream decisions are intent-bound

Authority and risk attestations authenticate kind, key identity, key lifecycle window, subject hash, exact intent hash, `issued_at` and `expires_at`. Expiry is exact (skew tolerance applies to issuance drift only). Signatures accept exactly one canonical encoding. Forged, stale, future, revoked-key, or cross-intent replayed attestations fail closed.

## I-16 — Raw execution material is not agent authority

The model cannot smuggle low-level authority through typed fields such as calldata, signed transactions, signing payloads, key material, delegatecall, or unlimited approvals; unknown payload fields are denied; a payload that is not a JSON object fails at construction.

## I-17 — Revocation acts as a submission fence

In-process: once `set_grant_status(REVOKED)` returns, no later adapter submission under that grant version can begin through any store instance on the same database within that process. Across processes: every lifecycle change (pause, revoke, halt) advances the grant's runtime epoch, and permit consumption re-checks that epoch in the same transaction domain, so an in-flight attempt in another process is refused at the venue (`test_multiprocess.test_revocation_in_other_process_during_submission_prevents_effect`). The fence is as strong as the store's transactional guarantee and as the venue's permit verification.

## I-18 — Malformed numeric/time data fails closed

NaN, infinity, invalid negative ages/limits, naive timestamps, impossible TTLs, over-long identifiers, oversized integers, non-canonical numeric strings, and amounts beyond canonical precision/exponent bounds cannot be interpreted as a permissive value or exhaust memory.

## I-19 — Evidence is append-linked and head-committed

Intent evidence events are hash-linked and start atomically with registration. In keyed mode each event carries a MAC and a signed head commitment binds the chain length and tail; an append refuses to extend a chain whose head no longer matches (`EvidenceIntegrityError`), so truncation cannot be laundered by later activity. Verification reads chain and head in one transaction and fails closed for unknown or deleted chains. Rollback of the whole database to an older valid snapshot is not detectable by the chain alone (see I-33).

## I-20 — Settlement is not definition of done

```text
FINALIZED(effect) != objective_met
```

Task completion is evaluated against criteria fixed before execution, authenticated independently of the agent, and bound to the settlement of **this** intent's execution request.

## I-21 — Availability loses to authority preservation

When FAAR cannot prove safe authorization/recovery, it may stop or defer even if that loses an opportunity. Unknown state must not be optimized into execution merely for liveness.

## I-22 — Financial grants are bounded by construction

For any grant that permits `PAY`, `SWAP`, `BUY`, `SELL`, or `PLACE_ORDER`, missing bounds are not interpreted as infinity. The grant requires an explicit asset scope, positive per-action cap, positive daily aggregate cap, and action-velocity bound. `PAY` and `SWAP` additionally require explicit target allowlists.

## I-23 — Positive settlement must be authoritative

A reconciliation observation of `CONFIRMED` or `FINALIZED` cannot advance the state machine unless the verifier marks that lookup authoritative for the stable intent identity and binds it to the exact execution request hash.

## I-24 — Settled economic amount cannot exceed authorization

For money-moving primitives, positive settlement must include a finite positive `amount_usd`. `PAY` must match the authorized amount exactly; trading/swap/order effects may not exceed the authorized amount. A mismatch stops reconciliation and keeps ambiguous usage held.

## I-25 — Executor input is capability-minimized

Execution adapters receive a sanitized `ExecutionRequest` containing only `principal_id`, `intent_id`, economic primitive, venue, and the post-gate payload, plus a signed `ExecutionPermit` scoped to exactly that request. Model metadata, grant documents, authority/risk objects, and raw signing material are structurally excluded from the adapter interface.

## I-26 — Permits are single use and epoch fenced

A signed permit binds one request hash, one grant envelope, one grant epoch, and one fence token; it is consumed at most once and only while the grant is ACTIVE at the same epoch, not halted, and not regressed (`test_permits`, `test_mutation_gaps.EpochFenceTests`, `test_controls`).

## I-27 — Submitter receipts are telemetry

Only the configured independent settlement verifier, a distinct object with a trusted `SettlementSecurityProfile`, can advance an intent to CONFIRMED/FINALIZED. The runtime refuses to construct without one per adapter.

## I-28 — Trust entering the execution domain is verify-only

The runtime, the permit authority and the permit gateway reject any trust object that exposes a signing API. Permit signatures cover the signer identity and algorithm.

## I-29 — Intent identity is principal-namespaced

An `intent_id`, its usage reservation, its permits and its evidence belong to one principal; a second principal presenting the same id is refused before any payload comparison.

## I-30 — In-flight attempts are bounded by their permit

Any attempt can be acted on by the venue until its permit expires, whatever the adapter reported (timeout, exception, deterministic rejection, receipt, or an uninterpretable value). The store persists that instant together with the permit, the runtime neither trusts absence nor retries before it has passed, the store refuses a second live permit for one intent, and a later permit supersedes an earlier one at consumption (`test_runtime_hardening`, `test_permits`, `evals/model_check_permit_protocol.py`).

## I-31 — Adapter calls are bounded

With `adapter_deadline_seconds` configured, a hung adapter call cannot hold the revocation fence or the intent lease past the deadline; the abandoned call is governed by I-30.

## I-32 — An emergency halt fences everything in scope

`halt(scope)` advances every affected grant epoch in one transaction; outstanding permits are unconsumable immediately and stay so after `resume`. A halt does not wait for in-flight adapter calls.

## I-33 — Consumed authority cannot be resurrected by restore

With an authority anchor kept outside the backup set, a grant version whose `(runtime_epoch, fence_counter)` regressed behind the anchor is `REGRESSED`: no permit is issued or consumed under it and its lifecycle cannot be changed except by `revoke_after_restore`. The fence counter advances at issuance and at consumption, so a snapshot between the two is detected. Once a database has been opened with an anchor, an instance without one cannot consume or change authority (`ANCHOR_REQUIRED`), and an unreadable anchor fails closed (`ANCHOR_UNAVAILABLE`). Without an anchor this invariant does not hold; the test suite documents that ceiling.

## I-34 — Key lifecycle is enforced at verification

Attestation keys and permit signers carry optional validity windows and a revocation flag; artifacts issued outside a window or under a revoked key are rejected, unknown key ids are always rejected, and an artifact issued inside a window remains verifiable for its own lifetime after the window closes. Because `issued_at` is signer-controlled, verifiers also bound each artifact's lifetime (`ATTESTATION_TTL_EXCEEDED`, `PERMIT_TTL_EXCEEDED`), capping a retired key's exposure to `not_after + lifetime`; revocation remains the hard control.

## I-35 — Partial fills and cancellations never create a second attempt

An authoritative `PARTIALLY_FILLED` record confirms the intent with the order's effect id and is reconciled again later; the unfilled remainder is never resubmitted. `CANCELLED` is terminal: with a fill it finalizes the intent, without one it fails safe and releases the budget, and it never contradicts a recorded fill silently (`test_partial_fills`).

## I-36 — Abandoned adapter calls are bounded

A call abandoned at the adapter deadline keeps running; the runtime counts them and refuses to submit (`ADAPTER_ORPHAN_LIMIT_REACHED`, budget released, no permit minted) while more than `max_orphaned_adapter_calls` are outstanding in the process (`test_orphan_cap`).

## I-37 — Fleet exposure is capped independently of grants

An operator cap on trailing-window turnover per scope (`global`, `principal:<id>`) is enforced atomically inside `reserve_usage` across every grant and principal in the scope (`EXPOSURE_CAP_EXCEEDED`); tightening or loosening it is an authority change and requires the anchor on an anchored database (`test_exposure_cap`).

## I-38 — Every persistence boundary is crash-safe

Finalize-and-commit and terminalize-and-release are single store transactions, and a worker killed before any store call can be recovered by the documented runbook without a duplicate effect, a lost effect, or stranded budget (`evals/run_crash_injection.py`).
