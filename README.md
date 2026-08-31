# FAAR — Financial Agent Authority Router

> **Models propose. FAAR authorizes. Deterministic executors act.**

FAAR is a runtime authority layer for autonomous financial agents. It converts an agent's proposed economic action into a canonical intent, checks that action against deterministic capability and risk constraints, and only then permits an executor to create an economic effect.

FAAR is intentionally separate from model reasoning. A model may recommend or request an action; it does not get to expand its own authority, bypass limits, or decide that an ambiguous state is safe enough to execute.

## Why FAAR

Agent wallets and spending limits solve only part of the problem. Autonomous systems also need a durable answer to:

- **What work is this agent authorized to perform?**
- **Which economic primitive is permitted?**
- **Under what asset, venue, amount, counterparty, time, and risk limits?**
- **Has this logical intent already produced an economic effect?**
- **What evidence proves what actually settled?**

FAAR treats those as runtime invariants rather than prompt instructions.

## Relationship to ConstraintGate / AAR

[ConstraintGate](https://github.com/Droptops/constraint-enumeration-eval) evaluates whether an agent selected the correct **Work Unit → Authority Posture → Primitive**.

FAAR operationalizes the consequential execution boundary:

```text
ConstraintGate / AAR
  ADVISE | EXECUTE | DEFER | STOP
                 │
                 │ EXECUTE_ACTION
                 ▼
              FAAR
        canonical intent
                 │
       capability + risk gate
                 │
          ALLOW | DENY
                 │
       deterministic executor
                 │
         settlement evidence
```

AAR answers: **is EXECUTE the licensed work primitive?**

FAAR answers: **is this specific economic execution within the granted capability envelope?**

Both must pass before money moves.

## Core invariants

FAAR is built around five non-negotiable properties:

1. **Exactly-once economic intent**
   - For every logical `intent_id`, successful economic effects must be `<= 1`.
   - Retries, crashes, timeouts, concurrent workers, duplicate messages, and ambiguous RPC responses must not create a second valid execution.

2. **Unauthorized means no economic effect**
   - If authority, capability, or risk evaluation denies an intent, the executor must be unable to create the requested effect.

3. **Authority is non-self-escalating**
   - An agent cannot modify its own capability grant, limits, approved assets, approved venues, or circuit breakers.

4. **Ambiguity fails closed**
   - Stale market data, contradictory settlement evidence, unknown contracts, RPC disagreement, and unresolved prior execution state route to `DEFER` or `STOP`, never optimistic execution.

5. **Settlement is evidence-driven**
   - API success is not settlement. The system records and verifies external execution evidence appropriate to the venue or chain.

See [`docs/INVARIANTS.md`](docs/INVARIANTS.md).

## First vertical: autonomous trading

The first reference client is an autonomous trading agent. A grant may constrain:

```yaml
authority:
  actions: [swap, place_order, cancel_order]
  venues: [approved_dex]
  quote_assets: [USDC]

risk:
  max_order_usd: 75
  max_position_usd: 250
  max_daily_turnover_usd: 1500
  max_daily_loss_usd: 100
  max_slippage_bps: 75
  max_price_impact_bps: 100

execution:
  intent_ttl_seconds: 15
  require_fresh_market_data: true

prohibited:
  - arbitrary_transfer
  - withdraw
  - unlimited_approval
  - unknown_contract
  - bridge
```

The model may propose a trade outside that envelope. FAAR must still deny it deterministically.

## Initial architecture

```text
Strategy / LLM
      │ proposed intent
      ▼
Authenticated Ingress
      ▼
Authority Router (AAR semantics)
      ▼
Canonical Intent + intent_id
      ▼
Capability + Risk gates
      ▼
Permit Authority → Isolated Signer
      ▼
Verify-only Execution Plane
      ▼
Deterministic Adapter
      ▼
Independent Settlement Verifier
      ▼
Evidence Log
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Repository layout

```text
faar/
  descriptors.py      # serialized public verifier descriptors
  signing.py          # SigningKeyProvider (authority process only)
  authority_service.py# out-of-process permit mint
  executor.py         # verify-only execution plane
  gateway.py          # financial side-effect choke point
  ledger.py           # authority ledger contract (SQLite reference)
  treasury.py         # fake-money PAY adapter
  runtime.py          # v0.4 in-process authority/risk/execution state machine
  gates.py            # deterministic policy gates
  attestation.py      # scoped signed attestations
  permits.py          # isolated permit mint vs verify-only execution
  keys.py             # ACTIVE/RETIRED/REVOKED verification-key lifecycle
  ingress.py          # principal-bound authenticated reference ingress
  store.py            # durable SQLite reference store
  adapters.py         # execution/reconciliation contract
  faults.py           # deterministic failure-injection catalog
  paper.py            # safe paper-trading adapter
  outcomes.py         # definition-of-done verification

docs/
  ARCHITECTURE.md
  INVARIANTS.md
  THREAT_MODEL.md
  TRUST_MODEL.md
  RISK_ENGINE_CONTRACT.md
  ADAPTER_CONTRACT.md
  RED_TEAM_REPORT.md
  DEFINITION_OF_DONE.md
  UNPLUG_TEST.md
  V0_5_AUTHORITY_SERVICE.md
  V0_4_AUTHORITY_PLANE.md
  V0_3_RELEASE.md
  V0_2_RELEASE_GATES.md

schemas/              # intent, grant, risk, attestation, task contracts
evals/                 # adversarial, red-team, fuzz, and bounded-model harnesses
test/                  # deterministic unit/invariant suite
examples/              # non-production fixtures
```

## MVP sequence

1. Freeze canonical `Intent` and `CapabilityGrant` schemas.
2. Build deterministic capability evaluation with explicit reason codes.
3. Build a durable intent state machine with a unique `intent_id` constraint.
4. Add an execution adapter interface and a fully deterministic mock venue.
5. Add adversarial tests for retries, races, crashes, stale data, prompt injection, and contradictory settlement evidence.
6. Add one real low-risk adapter only after the invariant suite is green.
7. Integrate AAR/ConstraintGate as an upstream authority signal without making model output a security boundary.

## Status

**v0.4.0 pre-alpha reference runtime. Not approved for live funds or production credentials.**

See [`docs/V0_4_AUTHORITY_PLANE.md`](docs/V0_4_AUTHORITY_PLANE.md) and [`docs/V0_3_RELEASE.md`](docs/V0_3_RELEASE.md). v0.3.0 remains frozen at `3bb828fe6b599c31e6adf87b2643215d318d9403`.

The current deterministic release gate is `make check` (unit/invariant tests, adversarial, red-team, fuzz, demo, bounded permit/key model, and in-process failure injection).

These are deterministic regression, adversarial, fuzz, bounded-model, and fault-catalog results. They are not formal verification, an independent security audit, or a production-safety claim.

Before any live-money adapter, the repository still requires the production gates in [`docs/V0_2_RELEASE_GATES.md`](docs/V0_2_RELEASE_GATES.md), including production signing/key isolation, distributed datastore fencing, authoritative risk-state semantics, reviewed venue reconciliation, authenticated ingress, failure injection, and independent security review.
