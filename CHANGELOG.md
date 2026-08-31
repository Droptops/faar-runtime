# Changelog

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
