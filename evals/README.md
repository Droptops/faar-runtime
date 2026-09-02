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

`run_redteam.py` maps 100 named attack classes to 131 concrete unit tests, loads the suite in-process, asserts that every mapped test exists and passes, and reports any `unmapped_tests`. The headline count therefore cannot drift from real coverage: deleting a mapped test fails the gate.

## Seeded state-machine fuzz

`run_state_fuzz.py` executes 64 randomized retry/ambiguity sequences (with a shared clock advancing 0..8 s per step, so the permit-bounded ambiguity window and the retry path are both exercised) and 32 randomized concurrent-budget scenarios using deterministic seeds. It asserts no duplicate effect for one intent and no aggregate turnover oversubscription. It broadens state-space regression coverage but is not exhaustive property testing.

## Bounded permit protocol model

`model_check_permit_protocol.py` exhaustively explores a bounded abstract permit/revocation/halt/settlement state space with up to two permits per intent, in-flight submission and permit expiry. Current result: 1766 states, 4304 transitions, 0 invariant violations; a stale permit is unconsumable after revoke and after halt/resume. The same model **without** the rule "issue a new permit only once every earlier permit is consumed or expired" reaches 187 violations (first: `issue, issue, submit0, consume0, submit1, consume1`), which is why the runtime waits for the permit window. This is bounded-model regression evidence, not formal verification of the Python runtime or any external venue.

## Claim boundary

These scripts are regression evidence for the reference implementation. They are not property-complete proofs, venue sandbox certification, formal verification, or an independent audit.
