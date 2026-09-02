# Changelog

## Unreleased

Paper gateway venue (not a live-money adapter):

- `faar/paper_gateway.py`: venue-side permit consumption, `limit_price` envelope, GTC cancel-never-fills, and a query credential that cannot submit. Optional loopback HTTP (`127.0.0.1` only) with a 2 s client timeout.
- Capability gate denies a present but non-canonical `limit_price` (`LIMIT_PRICE_INVALID`).
- Review record: `docs/adapters/PAPER_GATEWAY.md`. Tests in `test/test_paper_gateway.py`.
- In-repo evidence for paper-gateway rows of gates 4.2, 4.9, 6.7 and residual R-12. Gate 8, live venues, and funded credentials remain closed.
- Suite now 277 unit/invariant tests (1 skipped); red-team matrix 104 classes / 137 mapped tests.

## 0.4.0 — 2026-09-02

Third adversarial pass over v0.3.1 plus the operator controls a first bounded deployment needs, followed by an independent five-lens review of the change set itself. Still **pre-alpha and not approved for live funds or production credentials**. See [`docs/RED_TEAM_REPORT.md`](docs/RED_TEAM_REPORT.md) findings RT-42..RT-79 and [`docs/GO_LIVE_CHECKLIST.md`](docs/GO_LIVE_CHECKLIST.md).

**Exactly-once and recovery**

- Permit-bounded ambiguity window (RT-42, RT-67): the store records the permit expiry as the intent's `ambiguity_until` in the same transaction as the permit, so every adapter outcome (timeout, exception, deterministic rejection, receipt, uninterpretable value) is covered; an authoritative `NONE` inside that window is not trusted (`SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW`) and no retry is issued until the venue can no longer consume the permit. The store refuses a second live permit per intent (`PERMIT_PREVIOUS_ATTEMPT_LIVE`) and a later permit supersedes an earlier one at consumption (`PERMIT_SUPERSEDED`). The bounded model shows duplicate effects are reachable without this rule.
- Non-authoritative positive or `NONE` observations never STOP an intent or invalidate a recorded effect (RT-43); a `CONTRADICTORY` record stops regardless of authority.
- The deterministic-failure resubmission block is durable across calls and workers (RT-44).
- Settlement verification and retries run outside the per-grant revocation fence; `FAARRuntime(adapter_deadline_seconds=...)` bounds the adapter call (RT-45).
- Every terminal decision is recorded in the evidence chain; recovered authorizations record the `authorized` event (RT-61).
- Terminalize-and-release is one transaction; replaying a terminal never-submitted intent releases an orphaned hold (RT-59) unless the stop was derived from settlement evidence (RT-75). A durable deterministic-failure block survives a halt (RT-74). A non-receipt adapter return is ambiguous, not a crash (RT-73).
- If the evidence chain refuses an append, no state advances and the result is `EVIDENCE_INTEGRITY_FAILURE` (RT-72).

**Emergency controls, restore safety, key lifecycle**

- `halt(scope)` / `resume(scope)` (global or per principal) advance every affected grant epoch so outstanding permits die immediately and stay dead after resume; effective status `HALTED` (RT-63).
- `AuthorityAnchor` (`faar/anchor.py`): an external high-water mark of grant epoch and fence counter; the fence counter advances at permit issuance and at consumption (RT-69). A restored backup whose authority state regressed reports `REGRESSED`, refuses permit issuance and consumption, and is recovered only by `revoke_after_restore` (RT-62). The first anchored open binds the database: unanchored instances report `ANCHOR_REQUIRED` and cannot consume or change authority (RT-70); an unreadable anchor is `ANCHOR_UNAVAILABLE`; the file anchor is locked across processes (RT-68). `checkpoint()` for WAL-mode backups.
- `KeyValidity(not_before, not_after, revoked)` for attestation keys and permit signers; the permit gateway accepts several signer ids for overlap-window rotation and rejects unknown, revoked, or out-of-window signers (RT-64); verifiers bound artifact lifetime (`ATTESTATION_TTL_EXCEEDED`, `PERMIT_TTL_EXCEEDED`; RT-76). The gateway reports `PERMIT_HALTED` / `PERMIT_AUTHORITY_REGRESSED`; the permit authority refuses symmetric signers (RT-78).
- Operator CLI: `halt`, `resume`, `controls`, `list-grants`, `list-intents`, `held-usage`, `list-leases`, `clear-lease`, `rebuild-evidence-head [--all] [--adopt-empty]`, `revoke-after-restore`, `checkpoint`; `verify-evidence` takes the MAC key from an environment variable and reports a `status`; `--anchor` opens the store with a file anchor; typed refusals exit 2 as JSON. Runbook in `docs/OPERATIONS.md`, including the 0.3.x upgrade procedure.

**Trust boundaries**

- One bounded amount parser (plain ASCII decimal grammar, canonical precision/exponent bounds) shared by gates, usage reservation, permit signer, settlement integrity and reference venues; `1e-999999999` could previously make the store allocate gigabytes (RT-50).
- Attestation expiry is exact; permits never outlive the attestations they derive from (RT-46). Ed25519 signatures accept one canonical encoding (RT-47). Permit signatures cover signer id and algorithm (RT-48). The permit verifier returns `PERMIT_MALFORMED` instead of raising.
- Parsers reject unknown document/limit keys and falsy timestamps (RT-49); payloads must be JSON objects; identifiers are bounded (`intent_id` 16..128); `schema_version` must be `0.3`; `Attestation.kind` is coerced; naive datetimes and oversized ints fail at construction; effect ids are validated at the trust boundary (RT-52).
- BUY/SELL/PLACE_ORDER payloads with both `amount_usd` and `notional_usd` are denied (RT-51); `target` is the only counterparty key; SWAP identical-asset check uses normalized presence; proven risk-limit breaches DENY while missing/stale data DEFERs.
- Quorum settlement votes numerically, tolerates a raising minority source, and carries agreeing evidence forward (RT-54); one uncontested vote short of quorum is a retriable non-authoritative UNKNOWN, never a terminal CONTRADICTORY (RT-71); paper venue reconcile binds the effect to the executing request.
- The attested outcome verifier binds the settlement to this intent's execution request (RT-53); `eq` compares numbers numerically without conflating booleans; issuance tolerates clock skew.

**Store**

- v0.3.0 databases open again (velocity index created after migration); migration is transactional with busy retry (RT-55) and backfills legacy rows: intent venue from the canonical payload (RT-66), velocity timestamps and a 60 s ambiguity window for in-flight attempts (RT-77); a row that cannot be migrated fails the open (`MigrationError`).
- Daily turnover is a trailing 24 h window (RT-56). Effect ids are unique per `(venue, effect_id)` (RT-58).
- Evidence: appends refuse to re-commit the head over a truncated chain, verification is single-transaction and fails closed for unknown or deleted chains, every chain starts at registration, `rebuild_evidence_head(s)` is an explicit operator migration and `evidence_status` distinguishes `head_missing` from tampering (RT-57, RT-72).
- `intent_guard` honours `wait_seconds` in-process; per-intent locks are reference-counted; execution fences are shared per database path (RT-60). `reserve_usage` rejects malformed amounts on monetary primitives; the monotonic risk ceiling spans both ledgers. `UnknownIntent` is a typed `KeyError`.

**Evidence and packaging**

- `evals/run_redteam.py` maps every attack class to named unit tests, loads the suite in-process, and fails on unmapped tests (100 classes, 131 tests). `run_adversarial.py` measures adapter calls and permits issued/consumed. `run_state_fuzz.py` advances a shared clock. The model checker models two permits, in-flight submission, expiry, halt and resume, and reports the without-rule counterexample.
- New test modules: `test_store_hardening` (including real 0.3-shape databases and legacy chains), `test_runtime_hardening`, `test_boundary_hardening`, `test_mutation_gaps` (kills the 17 mutants that previously survived), `test_controls` (including a cross-process anchor test), `test_key_lifecycle`, `test_schemas`, plus a cross-process revocation test. 261 unit tests; the suite no longer leaks temporary files (RT-79).
- Schemas describe 0.3 documents (`principal_id`, `algorithm`+`signature`); examples validate in the unit suite when `jsonschema` is installed (`pip install -e ".[dev]"`). CI job timeout; Python 3.12/3.13 classifiers; full Apache-2.0 license text.
- Documentation rewritten to match the code: architecture, trust and threat models, adapter/verifier contract, recovery table, invariants I-1..I-34, execution permits, operations runbook, go-live checklist; stale v0.2/HMAC statements removed.

Unreleased in 0.3.1 but merged before it (PR #3): permit signing and verification split into `PermitSigner`/`PermitVerifier` and `Ed25519AttestationVerifier`, with the runtime, permit authority and gateway rejecting signing-capable trust.

These are regression results, not formal verification, an independent audit, or a production-safety claim.

## 0.3.1 — 2026-08-31

Red-team patch over v0.3.0 from a second adversarial review pass. Still **pre-alpha and not approved for live funds or production credentials**. See [`docs/RED_TEAM_REPORT.md`](docs/RED_TEAM_REPORT.md) findings RT-36..RT-41.

- **Settlement quorum fails closed (RT-36):** `QuorumSettlementVerifier` returns `CONTRADICTORY` when two distinct authoritative facts each reach quorum (e.g. a 2-2 split), instead of resolving the contest by iteration order.
- **Capability asset scope (RT-37):** falsy-but-present asset values (e.g. integer `0`) are validated against `allowed_assets` instead of being dropped by a truthiness check.
- **Capability target scope (RT-38):** falsy-but-present targets are checked against `denied_targets` / `TARGET_REQUIRED` instead of coalescing to `None`.
- **Action-velocity limit (RT-39):** the per-grant velocity reservation uses a sliding window over the trailing `action_window_seconds` instead of a fixed tumbling bucket that allowed up to 2x the limit across a boundary.
- **Evidence tamper-evidence (RT-40):** a signed per-intent head commitment lets a keyed verifier detect tail-truncation and whole-chain deletion, which the prev-hash chain alone could not.
- **Supply chain (RT-41):** GitHub Actions pinned to commit SHAs; the `cryptography` dependency range loosened from the over-tight `>=46,<47`.

Unit/invariant suite expanded to 125 tests. The adversarial, red-team, fuzz, demo, and bounded-model gates are unchanged in count and remain green. These are regression results, not formal verification, an independent audit, or a production-safety claim.

## 0.3.0 — 2026-08-31

v0.3.0 reference runtime. Still **pre-alpha and not approved for live funds or production credentials**.

- package version `0.3.0`
- expanded deterministic unit/invariant suite to 105 tests
- expanded targeted red-team matrix to 59 attack classes
- bounded permit protocol model checker included in `make check`
- adversarial headline results unchanged in count: 160 denial cases with 0 unauthorized economic effects; 100 same-intent replay attempts with 1 valid economic effect
- seeded fuzz: 96 scenarios with 0 duplicate-effect and 0 aggregate-budget violations
- bounded permit model: max depth 10, 12 unique states, 15 transitions, 0 invariant violations; stale permit consumable after revoke = false

These are deterministic regression, adversarial, fuzz, and bounded-model results. They are not formal verification, an independent security audit, or a production-safety claim. Live-money adapters remain blocked on [`docs/V0_2_RELEASE_GATES.md`](docs/V0_2_RELEASE_GATES.md).

## 0.2.1 — 2026-08-30

Outcome-control red-team patch over v0.2.0:

- definition-of-done requires authoritative FINALIZED settlement;
- normalized settlement fields (`effect_id`, `amount_usd`, `status`) override same-named adapter evidence;
- signed task-contract issue/expiry windows are enforced;
- explicit regression coverage for future/stale task contracts and exact PAY settlement amounts;
- expanded reviewer-facing matrix to 41 named attack classes and 75 unit/invariant tests.

No live-money adapter or production-safety claim is introduced.

## 0.2.0 — 2026-08-30

Hardening release for the FAAR reference runtime. This release is still **pre-alpha and not approved for live funds**.

- signed, intent-bound authority and risk attestations with signer-role scoping;
- deep-immutable canonical intent inputs and strict JSON/parser boundaries;
- monotonic risk-state version consumption to prevent stale shared-risk races;
- atomic cross-intent turnover/velocity reservations and orphan-reservation recovery;
- submission-time freshness revalidation and local revocation fencing;
- authoritative reconciliation requirements, effect-ID uniqueness, and contradictory-settlement STOP semantics;
- settlement amount envelope checks and non-authoritative positive/negative reconciliation rejection;
- signed task contracts separating economic settlement from definition-of-done;
- explicit trust model, risk-engine contract, unplug test, adapter contract, and live-money release gates;
- 73 deterministic unit tests, 39 named red-team attack classes, 160 denial mutations with 0 unauthorized effects, 100 same-intent retries with 1 effect, and 96 seeded state-machine fuzz scenarios with 0 duplicate-effect or aggregate-budget violations.

These results are regression evidence only; they are not formal verification, an external security audit, or a live-venue security claim.

## 0.1.0 — 2026-08-30

Initial executable FAAR reference runtime:

- typed authority/capability/risk/intent models;
- canonical fingerprints;
- immutable grant registry;
- deterministic gates and reason codes;
- atomic grant usage reservations;
- SQLite intent state machine;
- reconciliation-first retry semantics;
- mock and paper-trading adapters;
- hash-chained evidence integrity log;
- CLI, CI, schemas, adversarial harness, and invariant tests.
