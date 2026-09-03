# FAAR Evals

The eval surface is deterministic first.

```bash
make adversarial
make redteam
make fuzz
make modelcheck
# or everything:
make check
```

## Adversarial smoke

`run_adversarial.py` checks:

- 160 denial mutations across target, asset, amount, NaN, raw execution material, stale/contradictory risk, circuit breakers, and non-EXECUTE authority, asserting 0 economic effects **and 0 adapter calls**;
- a forged authority attestation;
- 100 repeated calls on one stable logical intent, asserting 1 effect, 1 adapter call, and exactly 1 permit issued and consumed (the mock venue is idempotent by construction, so effects alone cannot reveal a runtime double-submission);
- timeout after an external effect (1 effect, 1 call);
- keyed evidence-chain integrity.

Headline result:

```text
unauthorized_economic_effects = 0
unauthorized_adapter_calls = 0
replay_successful_effects = 1, replay_adapter_calls = 1, replay_permits_consumed = 1
timeout_after_effect_successful_effects = 1
```

## Targeted red team

`run_redteam.py` maps named attack classes to concrete unit tests, loads the suite in-process, asserts that every mapped test exists and passes, and reports any `unmapped_tests`. The headline count therefore cannot drift from real coverage: deleting a mapped test fails the gate. Environment-gated PostgreSQL tests are reported separately as `conditional_mapped_tests_not_exercised`; the PostgreSQL CI job must reduce that list to zero. RT-128..RT-134 cover the fixed-origin Hyperliquid testnet candidate (fakes only). RT-135..RT-153 cover the paper gateway and its post-merge hardening (not live-money); RT-154 covers PostgreSQL revocation availability.

## Crash injection

`run_crash_injection.py` (`make crash`) spawns a worker that runs `process()` for
one intent against a file-backed store and a file-backed mock venue, and kills it
(`os._exit`) immediately before its N-th store call, for every N a clean run makes,
in nine scenarios: success, timeout before the effect, timeout after the effect,
ambiguous venue that later recovers, deterministic rejection, partial fill then
cancel, open order then cancel, contradictory settlement, and cumulative-fill
regression. The parent recovers exactly as `docs/OPERATIONS.md` §2 says (clear the dead
worker's lease with its owner token, process again with fresh attestations past the
permit window) and asserts: at most one effect and the scenario-specific adapter-call
ceiling; an uncontested effect implies `FINALIZED` with usage `COMMITTED`; a
settlement contest or regressed cumulative fill implies `STOPPED` with the full
budget `HELD`; other terminal intents release their budget unless the stop is
settlement-derived; evidence verifies; and recovery never raises or ends
non-terminal. Headline: 309 crash points, 0
violations. This is a statement about the reference store and mock venue, not a
proof.

## Seeded state-machine fuzz

`run_state_fuzz.py` executes 64 randomized retry/ambiguity sequences (with a shared clock advancing 0..8 s per step, every mock venue mode including admission timeouts and partial fills, and venue-side completion or cancellation of resting orders between calls, so the permit-bounded ambiguity window, the retry path and the order lifecycle are all exercised; after each sequence it checks that budget is never released while an effect exists and that FINALIZED implies a committed reservation and exactly one effect) and 32 randomized concurrent-budget scenarios using deterministic seeds. It asserts no duplicate effect for one intent and no aggregate turnover oversubscription. It broadens state-space regression coverage but is not exhaustive property testing.

## Bounded permit protocol model

`model_check_permit_protocol.py` exhaustively explores a bounded abstract permit/revocation/halt/settlement state space with up to two permits per intent, in-flight submission, permit expiry and voiding, and settlement lag (the venue consumed a permit and created the effect before the verifier observed it). Current result: 3940 states, 10047 transitions, 0 invariant violations; a stale permit is unconsumable after revoke, after halt/resume and after voiding. The same model **without** the rule "issue a new permit only once every earlier permit is consumed, expired or voided" reaches 223 violations (first: `issue, issue, submit0, consume0, submit1, consume1`), and **without** the rule "never act on absence while the ledger shows a consumed permit" reaches 399 violations (first: `issue, submit0, consume0, issue, submit1, consume1`), which is why the runtime waits for the permit window and stops with `SETTLEMENT_NONE_AFTER_PERMIT_CONSUMED`. This is bounded-state exploration of the protocol rules, not verification of the Python implementation or of any venue.

## Claim boundary

These scripts are regression evidence for the reference implementation. They are not property-complete proofs, venue sandbox certification, formal verification, or an independent audit.
