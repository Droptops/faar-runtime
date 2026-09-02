# Store Contract

What a datastore must guarantee to replace `SQLiteIntentStore` (release gate
6.4). The reference store is a single SQLite file in WAL mode; a production
deployment that needs failover must reproduce every guarantee below on its own
datastore, and the same tests and evals must pass against it. This document is
the checklist for that port and for the independent review of it.

Terminology: **txn** means one atomic, isolated, durable transaction on the
datastore (SQLite `BEGIN IMMEDIATE ... COMMIT`). **Linearization point** means
the single txn whose commit order decides a race.

## 1. Global properties

| Property | Requirement | Exercised by |
|---|---|---|
| Atomicity per method | Every mutating method below is exactly one txn; it commits fully or not at all, whatever exception interrupts it. No method may leave a transaction open. | `evals/run_crash_injection.py` (191 kill points), `test_store_hardening` |
| Cross-process isolation | Two processes on the same datastore observe the same linearization order for every method marked **LP**. | `test_multiprocess` |
| Durability before return | A committed txn is durable before the method returns (permits, fences, consumption, evidence). | crash injection |
| Fail closed on ambiguity | A datastore error surfaces as an exception; the runtime never converts one into success, release, or a retry. | `test_runtime_hardening`, `test_live_money_redteam` |
| Migration is one txn | Schema upgrades and legacy backfills run in one txn; an unmigratable row fails the open (`MigrationError`). | `test_store_hardening.SchemaMigrationTests` |
| Anchor binding | Once opened with an authority anchor, the datastore records that fact durably and refuses authority changes from instances opened without one (`ANCHOR_REQUIRED`). | `test_controls.AuthorityAnchorTests` |

## 2. Intent state

| Method | Guarantee | Notes |
|---|---|---|
| `register(intent, hash)` | First writer wins per `intent_id`; a different canonical hash or another principal under the same id is `IntentConflict`, never a replacement. Writes the `intent_registered` evidence event in the same txn. | I-1, I-2, I-29 |
| `transition(id, expected, new, *, reason_codes, effect_id, release_usage, commit_usage, ambiguity_until)` | Compare-and-set on the stored state; only transitions in `_ALLOWED_TRANSITIONS`; `release_usage`/`commit_usage` update the reservation in the same txn; setting `effect_id` enforces uniqueness per `(venue, effect_id)` (`EffectConflict`). **LP** for terminalization. | I-3, I-11, I-38 |
| `begin_submission(id, expected, *, max_attempts)` | CAS into SUBMITTED and increment the durable attempt counter atomically; resets `ambiguity_until`; refuses past the attempt limit. **LP** for "an attempt began". | I-5 |
| `get(id)` | Reads the row; unknown ids raise `UnknownIntent`. | |
| `intent_guard(id, wait_seconds)` | Durable per-intent lease: at most one worker inside an intent's state machine across processes; a dead worker's lease is never taken over automatically (`IntentBusy`); `clear_stale_intent_lease` needs the exact owner token. | I-6, OPERATIONS §2 |

## 3. Budget and risk ledger

| Method | Guarantee | Notes |
|---|---|---|
| `reserve_usage(intent, grant, risk, now)` | One txn that checks and inserts: risk-state version uniqueness and monotonicity across both risk ledgers, trailing-window turnover over HELD+COMMITTED rows, sliding-window velocity, scope exposure caps; inserts the HELD reservation and the risk claim together. **LP** for aggregate limits. | I-13, I-37 |
| `commit_usage(id)` / `release_usage(id)` | Idempotent status changes on the HELD row only. | |
| `claim_permit_risk_state(...)` | Permit-time risk ledger: one state version per intent per scope, monotonic across intents. | I-14 |
| `set_exposure_cap(scope, max)` / `exposure_caps()` | Caps are read inside `reserve_usage`'s txn; changing a cap requires the anchor on an anchored datastore. | I-37 |

## 4. Authority, permits, controls

| Method | Guarantee | Notes |
|---|---|---|
| `provision_grant(grant, hash)` | Immutable per `(grant_id, version)`; a different hash or principal is `GrantConflict`; records `(epoch 1, fence 0)` to the anchor after commit. | I-16 |
| `verify_grant`, `get_grant_control` | Read-only; effective status folds in halt (`HALTED`), anchor regression (`REGRESSED`), missing anchor (`ANCHOR_REQUIRED`) and an unreadable anchor (`ANCHOR_UNAVAILABLE`). | I-32, I-33 |
| `set_grant_status(...)` | One txn; every real lifecycle change advances `runtime_epoch`; serialized with `next_execution_fence` and `consume_execution_permit` by the per-grant execution guard plus the datastore txn. **LP** for revocation. | I-17 |
| `next_execution_fence(grant)` | Allocates a strictly increasing fence under an ACTIVE, unhalted, unregressed grant; the fence counter also advances at consumption; both are pushed to the anchor after commit. | I-33 |
| `record_execution_permit(...)` | Records the permit and sets the intent's `ambiguity_until` to its expiry in the same txn; refuses a second live permit per intent (`PermitConflict`). | I-30 |
| `consume_execution_permit(...)` | **LP** for execution authorization: ledger binding, not consumed, not voided, not superseded, grant ACTIVE with the same epoch, not halted, anchor consulted; marks consumed and advances the fence in the same txn. | I-19, I-30 |
| `void_unconsumed_permits(id)` | Marks every unconsumed permit of the intent voided in one txn; consumption after that is `PERMIT_VOIDED` regardless of clocks. | I-30 |
| `halt(scope)` / `resume(scope)` | One txn that records the control and advances every affected grant epoch; requires the anchor on an anchored datastore. | I-32 |
| `revoke_after_restore(grant, version)` | Advances the epoch past the anchored mark and revokes the version; resets the anchor. | I-33 |

## 5. Evidence

| Method | Guarantee | Notes |
|---|---|---|
| `add_evidence(id, type, payload)` | Appends one hash-linked (and, when keyed, MAC'd) event and updates the signed head in the same txn; refuses when the tail no longer matches the head (`EvidenceIntegrityError`). | I-27 |
| `assert_evidence_appendable(id)` | Read-only pre-check the runtime runs before advancing state. | I-27 |
| `evidence_status(id)` / `verify_evidence_chain(id)` | Single read txn; fails closed for unknown or deleted chains; distinguishes `head_missing` from tampering. | I-27 |
| `rebuild_evidence_head(s)` | Operator-only; never adopts a chain that does not verify. | OPERATIONS §6 |

## 6. Porting checklist

1. Map each method to one transaction in the target datastore with at least
   read-committed isolation plus the row locks the SQL above implies; where the
   datastore cannot give `BEGIN IMMEDIATE` semantics, use `SELECT ... FOR UPDATE`
   on the grant row, the intent row and the permit row inside each **LP** method.
2. Keep the per-grant execution guard (`execution_guard`) as a datastore-level
   lock or advisory lock shared by every process; the in-process registry is not
   enough across hosts.
3. Keep the authority anchor outside the datastore's backup and failover set;
   after a failover, run `list-grants` and confirm no `REGRESSED` version before
   resuming.
4. Run `make check` against the port with the reference tests pointed at it, then
   `evals/run_crash_injection.py` with the worker killed at every datastore call.
5. Record the result in the deployment repository as evidence for gate 6.4; the
   in-repo status stays OPEN until then.
