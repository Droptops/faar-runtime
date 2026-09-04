# FAAR public roadmap

FAAR is developed in public as pre-alpha security-sensitive financial
infrastructure. This roadmap communicates direction; it does not authorize live
funds and is not a promise of delivery dates.

## Current milestone: independent-review handoff

The current target is commit
`491bed3f3a0fc0c9463c1af7c65b4b852082abfe`, tracked in
[Gate 8 issue #12](https://github.com/Droptops/faar-runtime/issues/12).

Implemented evidence includes:

- deterministic authorization, bounded permits, settlement checks, replay
  protection, emergency controls, and restore fencing;
- a SQLite reference store and PostgreSQL 16 contract candidate;
- paper/loopback and fixed-origin Hyperliquid testnet candidates;
- unit, adversarial, mapped red-team, seeded fuzz, bounded-model, and
  crash-injection suites.

This evidence is self-produced. Gate 8 remains open until a qualifying
independent human reviews a pinned commit and publishes a report using
`docs/INDEPENDENT_SECURITY_REVIEW.md`.

## Next in-repository priorities

1. Resolve and regression-test every material independent-review finding.
2. Exercise managed PostgreSQL 16 failover against the complete store contract.
3. Add an independent settlement data source for testnet verification.
4. Expand credentialed testnet fault injection without enabling live funds.
5. Keep each new economic stop machine-readable and mutation-tested.

## Deployment work

The following cannot be established by this repository alone:

- venue-side permit consumption, stable effect identity, finality, and
  cancellation semantics;
- KMS/HSM custody, signer process isolation, scoped trading credentials, and
  disabled withdrawals;
- authenticated intent and operator ingress with no alternate execution path;
- serializable managed-database operation and observed failover behavior;
- an authority anchor outside the backup set;
- a venue-funded balance capped to the first permitted exposure.

The authoritative row-by-row record is
`docs/GO_LIVE_CHECKLIST.md`. None of these rows may be inferred from a green
unit or CI suite.

## Good public contributions

- a failing invariant or adversarial regression test;
- a datastore-contract portability or failover harness;
- independent settlement verification;
- bounded-model or crash-injection coverage;
- clearer machine-readable denial and recovery behavior;
- documentation that narrows a claim to its actual evidence.

Real-money adapters are out of scope until every release gate is closed and the
target has completed independent review.

## Claims

Until the evidence changes, describe FAAR as a **pre-alpha reference runtime
being built in public**. Do not describe it as audited, formally verified,
production-safe, or exactly-once in production.
