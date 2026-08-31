# Tests

Run:

```bash
make test
```

The v0.2 deterministic suite covers capability/risk gating, signed intent-bound attestations, immutable grant fingerprints, runtime pause/revoke, revocation fencing, same-intent and cross-intent concurrency, aggregate turnover reservations, single-consumption risk-state versions, timeout/crash recovery, authoritative reconciliation, durable retry budgets, effect identity continuity/uniqueness, malformed/non-finite input, bounded grant construction, canonical resource bounds, sanitized adapter inputs, positive-settlement authority, settled-amount envelopes, paper-trading effects, evidence-chain/MAC integrity, and signed definition-of-done criteria.

The unit suite is complemented by:

```bash
make adversarial
make redteam
```

These tests are regression evidence for the reference model, not a formal proof or live-venue certification.
