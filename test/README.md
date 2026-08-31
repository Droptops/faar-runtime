# Tests

Run:

```bash
make test
```

The deterministic suite covers capability/risk gating, signed intent-bound attestations, isolated permit mint vs verify, key lifecycle (active/retired/revoked), principal-bound ingress, immutable grant fingerprints, runtime pause/revoke, revocation fencing, same-intent and cross-intent concurrency, multiprocess permit consume, aggregate turnover reservations, crash/restart of consumed and revoked authority, timeout/crash recovery, authoritative reconciliation, durable retry budgets, effect identity continuity/uniqueness, malformed/non-finite input, bounded grant construction, sanitized adapter inputs, positive-settlement authority, paper-trading effects, evidence-chain/MAC integrity, and signed definition-of-done criteria. Counts change as tests are added; `make check` is the live gate.

The unit suite is complemented by:

```bash
make adversarial
make redteam
```

These tests are regression evidence for the reference model, not a formal proof or live-venue certification.
