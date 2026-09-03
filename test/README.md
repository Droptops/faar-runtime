# Tests

Run:

```bash
make test
```

The deterministic suite discovers 428 unit/invariant tests. Nine integration tests require the PostgreSQL 16 service job and are reported as conditional skips in the SQLite reference job. The suite covers capability/risk gating and every capability scope and risk limit at runtime level, signed intent-bound attestations with exact expiry and key lifecycle, canonical signature encodings, immutable grant fingerprints and strict document parsing, runtime pause/revoke/halt, in-process and cross-process revocation fencing (epoch at permit consumption), same-intent and cross-intent concurrency, aggregate turnover (trailing window) and sliding-window per-attempt velocity reservations, monotonic single-consumption risk-state versions, timeout/crash/deadline recovery with the permit-bounded ambiguity window, authoritative reconciliation and the weak-observation rules, settlement-quorum contradiction and fault tolerance, durable retry budgets and resubmission blocks, effect identity continuity and per-venue uniqueness, malformed/non-finite/non-canonical input and amount grammar, bounded grant construction, canonical resource bounds, sanitized adapter inputs, positive-settlement authority, settled-amount envelopes, PAY end to end, paper-trading effects, the fixed-origin Hyperliquid testnet candidate's limit-IOC translation and independent order/fill read path (with deterministic fakes only), evidence-chain/MAC/head-commitment integrity including append refusal, restore detection through the authority anchor (issuance and consumption, cross-process anchor updates, unanchored and unreadable anchors), real 0.3-shape database upgrades and legacy evidence chains, artifact lifetime bounds, operator queries and CLI refusals, schema/example consistency, signed definition-of-done criteria bound to the intent, and the economic-logic, state-machine and resource red-team personas (`test_economic_redteam`, `test_state_machine_redteam`: velocity across attempts, releases and grant versions, executor-side slippage bounds, fill monotonicity and open orders, JSON-number grammar, the durable block on every entry point, permit voiding on every stop, reason-code and document byte bounds, index coverage, the process-wide orphan cap), plus the self-review of that pass (`test_selfreview_redteam`: atomic identity claims, principal-scoped windows, anchor repair and stop-direction commits under an unreadable anchor, instance-bound leases, the born-with-head watermark, bounded authority reason codes and outcome evaluations, mandatory slippage caps, read-only store opens), paper-gateway hardening for principal/target binding, cross-principal cancellation, namespace-safe order ids, exact order and wire semantics, fill-time evidence, atomic balance legs, terminal failed matches, and loopback credential confinement, plus the PostgreSQL schema, transaction, multiprocess and crash-recovery contract. Every test writes only inside a per-test temporary directory or a disposable PostgreSQL test schema.

`test_live_money_redteam.py` holds the regressions from the compromised-adapter and malicious-settlement-source personas (venue-bound permits, voided permits, bounded settlement content, finality lag, garbage quorum members); `test_partial_fills.py` models resting orders, completion and cancellation; `test_exposure_cap.py` the fleet-wide turnover ceiling; `test_orphan_cap.py` the bound on abandoned adapter calls. `test_mutation_gaps.py` exists because a mutation sweep showed 17 security checks could be deleted without a test failing; each of its tests kills one of those mutants. `evals/run_redteam.py` maps every attack class to tests in this directory.

`test_hyperliquid.py` exercises the first external testnet adapter contract with
fake transports and a fake venue ledger. It never opens a network connection and
does not certify Hyperliquid testnet behavior.

`test_paper_gateway.py` exercises the paper / loopback venue: venue-bound
permit consume, the request `limit_price` envelope, submit/query credential
split (in-process and loopback HTTP), open-order confirmation, and the
guarantee that a cancelled GTC never fills later. It is not a live venue.

The unit suite is complemented by:

```bash
make adversarial
make redteam
make fuzz
make modelcheck
```

These tests are regression evidence for the reference model, not a formal proof or live-venue certification.
