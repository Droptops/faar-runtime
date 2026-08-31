# FAAR Evals

The eval surface is deterministic first.

```bash
make adversarial
make redteam
make fuzz
make modelcheck
make faults
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

`run_redteam.py` exercises the v0.4 attack class set (v0.3.0 baseline 59 plus isolated-authority cases). Coverage includes cross-intent attestation replay, concurrent budget oversubscription, revocation races, grant substitution, revoked-key resurrection, principal substitution, cross-principal intent squat, and multiprocess permit double-consume.

## Seeded state-machine fuzz

`run_state_fuzz.py` executes 64 randomized retry/ambiguity sequences and 32 randomized concurrent-budget scenarios using deterministic seeds. It asserts no duplicate effect for one intent and no aggregate daily-turnover oversubscription. It broadens state-space regression coverage but is not exhaustive property testing.

## Bounded permit protocol model

`model_check_permit_protocol.py` exhaustively explores a bounded abstract permit/key/revocation/settlement state space. It is included in `make check`. The v0.4 model adds key ACTIVE/RETIRED/REVOKED, issued/consumed/settled, and no-resurrection properties. Latest bounded result: max depth 10, 36 unique states, 76 transitions, 0 invariant violations. This is bounded-model regression evidence, not formal verification of the Python runtime or any external venue.

## Claim boundary

These scripts are regression evidence for the reference implementation. They are not property-complete proofs, venue sandbox certification, formal verification, or an independent audit.
