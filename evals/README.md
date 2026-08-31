# FAAR Evals

The eval surface is deterministic first.

```bash
make adversarial
make redteam
make fuzz
# or everything:
make check
```

## Adversarial smoke

`run_adversarial.py` currently checks:

- 160 denial mutations across target, asset, amount, NaN, raw execution material, stale/contradictory risk, circuit breakers, and non-EXECUTE authority;
- a forged authority attestation;
- 100 repeated calls on one stable logical intent;
- timeout after an external effect;
- evidence-chain integrity.

Headline result:

```text
unauthorized_economic_effects = 0
same_intent_successful_effects = 1
timeout_after_effect_successful_effects = 1
```

## Targeted red team

`run_redteam.py` exercises 41 named attack classes, including cross-intent attestation replay, risk-state reuse, concurrent budget oversubscription, effect-identity/amount mutation, weak positive/negative settlement evidence, expiry/revocation races, grant substitution, unbounded-grant construction, confused-deputy payloads, evidence tampering, and post-hoc definition-of-done rewrite.

## Claim boundary

These scripts are regression evidence for the reference implementation. They are not property-complete proofs, venue sandbox certification, formal verification, or an independent audit.

## Seeded state-machine fuzz

`run_state_fuzz.py` executes 64 randomized retry/ambiguity sequences and 32 randomized concurrent-budget scenarios using deterministic seeds. It asserts no duplicate effect for one intent and no aggregate daily-turnover oversubscription. It broadens state-space regression coverage but is not exhaustive property testing.
