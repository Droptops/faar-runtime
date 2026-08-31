# FAAR v0 Build Spec

## Objective

Build a deterministic financial-authority runtime that can safely sit between an autonomous agent and an economic executor.

The first milestone is **not** profitable trading. It is proving that an untrusted proposal source cannot create an economic effect outside a predeclared capability envelope and cannot double-execute one logical intent under retry/concurrency faults.

## v0 deliverables

### 1. Domain model

Implement typed models for:

- `AuthorityDecision`
- `Intent`
- `CapabilityGrant`
- `RiskSnapshot`
- `Decision`
- `ExecutionRecord`
- `SettlementRecord`

### 2. Canonical intent

Requirements:

- durable caller-supplied/generated `intent_id`
- immutable economic fields after authorization
- explicit expiry
- grant/version binding
- adapter/venue binding
- canonical serialization for hashing/evidence

### 3. Capability evaluator

Pure deterministic function:

```text
evaluateCapability(intent, grant, now) -> decision
```

Initial checks:

- actor
- primitive
- venue
- target/counterparty
- asset
- amount/order notional
- expiry
- per-action cap
- allow/deny lists

### 4. Risk evaluator

Pure deterministic function:

```text
evaluateRisk(intent, grant, riskSnapshot) -> decision
```

Initial checks:

- max position
- max order
- daily turnover
- daily loss
- market-data freshness
- slippage
- price impact
- velocity
- circuit breaker

### 5. Durable intent state machine

Use a transactional store with a unique constraint on `intent_id`.

Prove behavior under two concurrent execution attempts for the same intent.

### 6. Mock executor

Create a deterministic fake venue that supports:

- success
- timeout-before-effect
- timeout-after-effect
- duplicate submission
- partial/ambiguous response
- settlement reconciliation

No real funds.

### 7. Adversarial invariant suite

Must include:

- duplicate logical request
- fresh transport IDs for same logical intent
- concurrent worker race
- crash after effect before local persistence
- unknown settlement followed by retry
- prompt-injected transfer to unapproved recipient
- amount over max
- unknown asset
- unknown venue/contract
- stale market data
- circuit breaker active

Headline metric:

```text
unauthorized_economic_effects = 0
and
duplicate_successful_effects_per_intent = 0
```

### 8. AAR integration boundary

Treat AAR/ConstraintGate output as an upstream authorization signal. Do not make natural-language model output a trusted financial-policy input.

If posture != `EXECUTE` or primitive != an execution-capable primitive, FAAR must not proceed to economic execution.

## Explicit non-goals for v0

- real-money deployment
- profitability/alpha testing
- production key management
- leverage
- bridging
- arbitrary smart contracts
- generalized compliance engine
- GUI

## Release gate for first live adapter

Do not add a live-money adapter until:

- invariant suite is deterministic and green
- concurrent intent reservation has been tested against a real transactional database
- recovery/reconciliation semantics are documented
- adapter threat model is complete
- maximum funded test balance is explicitly capped
