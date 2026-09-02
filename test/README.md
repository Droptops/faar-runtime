# Tests

Run:

```bash
make test
```

The v0.4.0 deterministic suite (339 unit/invariant tests) covers capability/risk gating and every capability scope and risk limit at runtime level, signed intent-bound attestations with exact expiry and key lifecycle, canonical signature encodings, immutable grant fingerprints and strict document parsing, runtime pause/revoke/halt, in-process and cross-process revocation fencing (epoch at permit consumption), same-intent and cross-intent concurrency, aggregate turnover (trailing window) and sliding-window velocity reservations, monotonic single-consumption risk-state versions, timeout/crash/deadline recovery with the permit-bounded ambiguity window, authoritative reconciliation and the weak-observation rules, settlement-quorum contradiction and fault tolerance, durable retry budgets and resubmission blocks, effect identity continuity and per-venue uniqueness, malformed/non-finite/non-canonical input and amount grammar, bounded grant construction, canonical resource bounds, sanitized adapter inputs, positive-settlement authority, settled-amount envelopes, PAY end to end, paper-trading effects, evidence-chain/MAC/head-commitment integrity including append refusal, restore detection through the authority anchor (issuance and consumption, cross-process anchor updates, unanchored and unreadable anchors), real 0.3-shape database upgrades and legacy evidence chains, artifact lifetime bounds, operator queries and CLI refusals, schema/example consistency, signed definition-of-done criteria bound to the intent, and the economic-logic, state-machine and resource red-team personas (`test_economic_redteam`, `test_state_machine_redteam`: velocity across releases and grant versions, executor-side slippage bounds, fill monotonicity and open orders, JSON-number grammar, the durable block on every entry point, permit voiding on every stop, reason-code and document byte bounds, index coverage, the process-wide orphan cap). Every test writes only inside a per-test temporary directory that is removed at cleanup.

`test_live_money_redteam.py` holds the regressions from the compromised-adapter and malicious-settlement-source personas (venue-bound permits, voided permits, bounded settlement content, finality lag, garbage quorum members); `test_partial_fills.py` models resting orders, completion and cancellation; `test_exposure_cap.py` the fleet-wide turnover ceiling; `test_orphan_cap.py` the bound on abandoned adapter calls. `test_mutation_gaps.py` exists because a mutation sweep showed 17 security checks could be deleted without a test failing; each of its tests kills one of those mutants. `evals/run_redteam.py` maps every attack class to tests in this directory.

The unit suite is complemented by:

```bash
make adversarial
make redteam
make fuzz
make modelcheck
```

These tests are regression evidence for the reference model, not a formal proof or live-venue certification.
