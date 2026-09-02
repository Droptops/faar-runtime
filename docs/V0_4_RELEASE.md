# FAAR v0.4.0 Release Note

**v0.4.0 pre-alpha reference runtime. Not approved for live funds or production credentials.**

This note describes the current validated reference state. Historical notes: [`V0_3_RELEASE.md`](V0_3_RELEASE.md).

## Scope

v0.4.0 is the packaged reference runtime (`faar-runtime` 0.4.0): a deterministic authority and economic-execution kernel for mock/paper adapters, plus the operator controls a first bounded deployment would need.

In scope:

- canonical intent, capability/risk gating, and durable intent-state handling
- Ed25519 attestations and execution permits with signer/verifier separation and key lifecycle
- the permit-bounded ambiguity window and bounded adapter deadlines
- emergency halt/resume, scope exposure caps, the external authority anchor, and the operator CLI
- partial-fill and cancellation semantics for order venues
- replay, concurrency, revocation, restore and settlement-evidence checks in the reference model
- the release gate (`make check`), including the mapped red-team matrix and the bounded permit protocol model

Out of scope:

- live-money adapters, production credentials, or funded venues
- formal verification or independent security audit
- production-safety or exactly-once claims outside the tested mock/paper model

## What changed since v0.3.1

See [`RED_TEAM_REPORT.md`](RED_TEAM_REPORT.md) RT-42..RT-116 and the CHANGELOG. Breaking changes for integrators:

- a grant that sets `max_slippage_bps` now requires `max_slippage_bps` in every SWAP/BUY/SELL/PLACE_ORDER payload (orders may carry `limit_price` instead); the bound is inside the permit's request hash and the adapter must enforce it (I-39);
- JSON-number amounts are admitted only when their shortest form fits the money grammar;
- intent payload and metadata carry a 64 KiB string-content budget each.

- `schema_version` must be `"0.3"`; unknown document/limit keys are rejected; `intent_id` is 16..128 characters; payloads must be JSON objects; amount strings must be plain ASCII decimals with at most 8 fraction digits; BUY/SELL/PLACE_ORDER payloads carry exactly one amount field.
- Proven risk-limit breaches are `DENIED` (were `DEFERRED`); missing or stale data still defers.
- Permit signatures cover signer id and algorithm (permits are 5 s artifacts; no stored permit survives an upgrade).
- Non-authoritative positive or `NONE` settlement records never STOP an intent; `CONTRADICTORY` stops regardless of authority. A quorum short of votes without a contest is a retriable non-authoritative UNKNOWN (was CONTRADICTORY).
- `FAARRuntime(..., adapter_deadline_seconds=...)`, `SQLiteIntentStore(..., authority_anchor=...)`, `ExecutionPermitVerifier({signer_id: verifier, ...}, key_validity=..., max_permit_lifetime_seconds=60)`, `Ed25519AttestationVerifier(..., max_attestation_lifetime_seconds=86400)`.
- A database opened with an authority anchor once is bound to it: instances opened without one cannot issue, consume, or change authority. A store implementing `PermitControlStore.record_execution_permit` must accept `expires_at` and `now` and refuse a second live permit per intent.
- Effect ids are unique per `(venue, effect_id)`; daily turnover is a trailing 24 h window. Opening a 0.3.x database migrates and backfills it once; follow `OPERATIONS.md` §8 (stop 0.3.x workers first, then `rebuild-evidence-head --all` for keyed stores).

## Validation evidence

Current `make check` headline results:

| Gate | Result |
|---|---|
| Unit/invariant tests | 339/339 pass |
| Targeted red-team | 148 attack classes mapped to 207 named tests, 0 unmapped |
| Adversarial denial cases | 160; 0 unauthorized economic effects; 0 adapter calls |
| Same-intent replay attempts | 100; 1 effect, 1 adapter call, 1 permit issued and consumed |
| Seeded fuzz scenarios | 96; 0 duplicate-effect violations; 0 aggregate-budget violations |
| Bounded permit model | 3940 states, 10047 transitions, 0 violations; stale permit unconsumable after revoke and after halt/resume; 223 violations without the permit-window rule, 399 without the consumed-permit ledger check |
| Demo | mock execution FINALIZED once; keyed evidence chain and head commitment valid |
| Crash injection | 191 worker kills before every store call across 6 scenarios; 0 duplicate effects, 0 lost effects, 0 stranded budget, every recovery terminal |

## Claim boundary

These are deterministic regression, adversarial, fuzz, mutation-derived, and bounded-model results for the reference implementation and its encoded fault classes.

Do **not** describe FAAR v0.4.0 as formally verified, independently audited, production-safe, or approved for live funds. The bounded permit checker explores a small abstract state space; it is not a proof of the Python runtime or of any external venue.

## Explicitly not tested in-repo

- datastore failover (the reference store is SQLite);
- a real venue's cancel/fill ordering (the model relies on the venue reporting `CANCELLED` only once no further fill is possible);
- venue-side permit verification against a real venue;
- key custody in KMS/HSM;
- authenticated ingress.

## Remaining blockers before live-money use

[`GO_LIVE_CHECKLIST.md`](GO_LIVE_CHECKLIST.md) maps every gate in [`V0_2_RELEASE_GATES.md`](V0_2_RELEASE_GATES.md) and every residual risk to its status and evidence. The OPEN rows are datastore failover beyond SQLite and the independent security review; the DEPLOYMENT rows are key custody, venue-side permit verification, credential scoping, authenticated ingress, anchor placement, the funded balance at the venue, and each venue's cancel terminality. Do not add a real-money adapter, seed phrase, private key, or production credential to this repository until those are met.
