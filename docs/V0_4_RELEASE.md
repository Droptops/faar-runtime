# FAAR v0.4.0 Release Note

**v0.4.0 pre-alpha reference runtime. Not approved for live funds or production credentials.**

This note describes the current validated reference state. Historical notes: [`V0_3_RELEASE.md`](V0_3_RELEASE.md).

## Scope

v0.4.0 is the packaged reference runtime (`faar-runtime` 0.4.0): a deterministic authority and economic-execution kernel for mock/paper adapters, plus the operator controls a first bounded deployment would need.

In scope:

- canonical intent, capability/risk gating, and durable intent-state handling
- Ed25519 attestations and execution permits with signer/verifier separation and key lifecycle
- the permit-bounded ambiguity window and bounded adapter deadlines
- emergency halt/resume, the external authority anchor, and the operator CLI
- replay, concurrency, revocation, restore and settlement-evidence checks in the reference model
- the release gate (`make check`), including the mapped red-team matrix and the bounded permit protocol model

Out of scope:

- live-money adapters, production credentials, or funded venues
- formal verification or independent security audit
- production-safety or exactly-once claims outside the tested mock/paper model

## What changed since v0.3.1

See [`RED_TEAM_REPORT.md`](RED_TEAM_REPORT.md) RT-42..RT-65 and the CHANGELOG. Breaking changes for integrators:

- `schema_version` must be `"0.3"`; unknown document/limit keys are rejected; `intent_id` is 16..128 characters; payloads must be JSON objects; amount strings must be plain ASCII decimals with at most 8 fraction digits; BUY/SELL/PLACE_ORDER payloads carry exactly one amount field.
- Proven risk-limit breaches are `DENIED` (were `DEFERRED`); missing or stale data still defers.
- Permit signatures cover signer id and algorithm (permits are 5 s artifacts; no stored permit survives an upgrade).
- Non-authoritative settlement records never STOP an intent.
- `FAARRuntime(..., adapter_deadline_seconds=...)`, `SQLiteIntentStore(..., authority_anchor=...)`, `ExecutionPermitVerifier({signer_id: verifier, ...}, key_validity=...)`.
- Effect ids are unique per `(venue, effect_id)`; daily turnover is a trailing 24 h window.

## Validation evidence

Current `make check` headline results:

| Gate | Result |
|---|---|
| Unit/invariant tests | 237/237 pass |
| Targeted red-team | 86 attack classes mapped to 104 named tests, 0 unmapped |
| Adversarial denial cases | 160; 0 unauthorized economic effects; 0 adapter calls |
| Same-intent replay attempts | 100; 1 effect, 1 adapter call, 1 permit issued and consumed |
| Seeded fuzz scenarios | 96; 0 duplicate-effect violations; 0 aggregate-budget violations |
| Bounded permit model | 1766 states, 4304 transitions, 0 violations; stale permit unconsumable after revoke and after halt/resume; 187 violations without the permit-window rule |
| Demo | mock execution FINALIZED once; keyed evidence chain and head commitment valid |

## Claim boundary

These are deterministic regression, adversarial, fuzz, mutation-derived, and bounded-model results for the reference implementation and its encoded fault classes.

Do **not** describe FAAR v0.4.0 as formally verified, independently audited, production-safe, or approved for live funds. The bounded permit checker explores a small abstract state space; it is not a proof of the Python runtime or of any external venue.

## Explicitly not tested in-repo

- datastore failover (the reference store is SQLite);
- partial fill and cancellation races;
- venue-side permit verification against a real venue;
- key custody in KMS/HSM;
- authenticated ingress.

## Remaining blockers before live-money use

[`GO_LIVE_CHECKLIST.md`](GO_LIVE_CHECKLIST.md) maps every gate in [`V0_2_RELEASE_GATES.md`](V0_2_RELEASE_GATES.md) and every residual risk to its status and evidence. The OPEN rows are partial-fill/cancel semantics, datastore failover, and the independent security review; the DEPLOYMENT rows are key custody, venue-side permit verification, credential scoping, authenticated ingress, anchor placement, and a capped first exposure. Do not add a real-money adapter, seed phrase, private key, or production credential to this repository until those are met.
