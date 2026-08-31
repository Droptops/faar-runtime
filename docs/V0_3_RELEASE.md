# FAAR v0.3.0 Release Note

**v0.3.0 pre-alpha reference runtime. Not approved for live funds or production credentials.**

This note describes the current validated reference state. It does not replace historical v0.2 documents.

## Scope

v0.3.0 is the current packaged reference runtime (`faar-runtime` 0.3.0). It is a deterministic authority and economic-execution kernel for mock/paper adapters.

In scope:

- canonical intent, capability/risk gating, and durable intent-state handling
- signed attestations and grant fingerprinting
- replay, concurrency, revocation, and settlement-evidence checks in the reference model
- the standard release gate (`make check`), including the bounded permit protocol model checker

Out of scope:

- live-money adapters, production credentials, or funded venues
- formal verification or independent security audit
- production-safety or exactly-once claims outside the tested mock/paper model

## Major security properties

The reference runtime is still built around the core invariants in `INVARIANTS.md`:

- at most one successful economic effect per logical `intent_id`
- unauthorized, denied, deferred, or stopped paths must not reach execution
- grants cannot be silently substituted or self-escalated
- revocation is irreversible for a grant version
- ambiguity fails closed
- money-moving grants remain bounded by construction
- adapters receive a sanitized `ExecutionRequest`, not model metadata or policy objects
- positive settlement is not trusted merely because it is positive

v0.3.0 additionally runs a bounded abstract model of permit issuance, revocation, consumption, and settlement as part of `make check`.

## Validation evidence

Current `make check` headline results:

| Gate | Result |
|---|---|
| Unit/invariant tests | 105/105 pass |
| Targeted red-team | 59 attack classes pass |
| Adversarial denial cases | 160 |
| Unauthorized economic effects | 0 |
| Same-intent replay attempts | 100 |
| Valid economic effects from those replays | 1 |
| Seeded fuzz scenarios | 96 |
| Duplicate-effect violations | 0 |
| Aggregate-budget violations | 0 |
| Bounded permit model | max depth 10; 12 unique states; 15 transitions; 0 invariant violations; stale permit consumable after revoke = false |

`make check` now runs: unit tests, adversarial, red-team, fuzz, demo, and `modelcheck`.

## Claim boundary

These are deterministic regression, adversarial, fuzz, and bounded-model results for the reference implementation and its encoded fault classes.

Do **not** describe FAAR v0.3.0 as:

- formally verified
- independently audited
- production-safe
- approved for live funds

The bounded permit checker explores a small abstract state space. It is not a proof of the Python runtime or of any external venue.

## Remaining blockers before live-money use

A green reference suite is necessary but not sufficient for real funds. Live-money credentials and adapters remain prohibited until the gates in [`V0_2_RELEASE_GATES.md`](V0_2_RELEASE_GATES.md) are satisfied and independently reviewed, including:

- production signing / key isolation (signer/verifier separation)
- distributed datastore fencing and revocation
- authoritative risk-state semantics across processes
- reviewed venue reconciliation and independent settlement verification
- authenticated ingress and intent-identity administration
- failure injection beyond the in-repo mock/paper model
- independent security review
- an explicitly capped first funded exposure

Do not add a real-money adapter, seed phrase, private key, or production credential to this repository until those gates are met.
