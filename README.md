# FAAR — Financial Agent Authority Router

> **Models propose. FAAR authorizes. Deterministic executors act.**

FAAR is a runtime authority layer for autonomous financial agents. It converts an agent's proposed economic action into a canonical intent, checks that action against deterministic capability and risk constraints, mints a narrowly scoped signed execution permit, and only then lets an executor create an economic effect that an independent verifier must confirm.

FAAR is intentionally separate from model reasoning. A model may recommend or request an action; it does not get to expand its own authority, bypass limits, or decide that an ambiguous state is safe enough to execute.

## Why FAAR

Agent wallets and spending limits solve only part of the problem. Autonomous systems also need a durable answer to:

- **What work is this agent authorized to perform?**
- **Which economic primitive is permitted?**
- **Under what asset, venue, amount, counterparty, time, and risk limits?**
- **Has this logical intent already produced an economic effect, or might it still?**
- **What evidence proves what actually settled?**
- **How do we stop everything, and what survives a restore from backup?**

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
        signed execution permit
                 │
       deterministic executor
                 │
   independent settlement evidence
```

AAR answers: **is EXECUTE the licensed work primitive?**

FAAR answers: **is this specific economic execution within the granted capability envelope, and did it happen exactly once?**

Both must pass before money moves.

## Core invariants

FAAR is built around five non-negotiable properties:

1. **Exactly-once economic intent**
   - For every logical `intent_id`, successful economic effects must be `<= 1`.
   - Retries, crashes, timeouts, concurrent workers, duplicate messages, and ambiguous RPC responses must not create a second valid execution. A retry is never issued while a venue can still act on a previous attempt's permit.

2. **Unauthorized means no economic effect**
   - If authority, capability, or risk evaluation denies an intent, the executor must be unable to create the requested effect: no permit is minted, and a permit-verifying venue refuses unsigned requests.

3. **Authority is non-self-escalating**
   - An agent cannot modify its own capability grant, limits, approved assets, approved venues, or circuit breakers. The runtime cannot provision grants or change their lifecycle.

4. **Ambiguity fails closed**
   - Stale market data, contradictory settlement evidence, unknown contracts, RPC disagreement, and unresolved prior execution state route to `DEFER` or `STOP`, never optimistic execution.

5. **Settlement is evidence-driven**
   - API success is not settlement. Submitter receipts are telemetry; only an independent verifier's authoritative, request-bound record advances an intent.

See [`docs/INVARIANTS.md`](docs/INVARIANTS.md) (I-1..I-38).

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

## Architecture

```text
Strategy / LLM                      (untrusted)
      │
      ▼
Authority Router (AAR semantics)    Ed25519-signed authority attestation
      │
      ▼
Canonical Intent + intent_id        principal-namespaced, schema 0.3
      │
      ▼
Capability Gate ── Risk Gate        deterministic, machine-readable reason codes
      │
      ▼
Intent Reservation / Replay Guard   atomic turnover + velocity, risk-state claim, durable lease
      │
      ▼
Constrained Permit Authority        independent re-check, signed single-use permit
      │
      ▼
Deterministic Executor ──► venue / gateway verifies & consumes the permit
      │                     (grant epoch, halt, authority anchor)
      ▼
Independent Settlement Verifier     authoritative, request-bound; permit-bounded ambiguity window
      │
      ▼
Evidence Log                        hash chain + MAC + signed head
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/EXECUTION_PERMITS.md`](docs/EXECUTION_PERMITS.md).

## Repository layout

```text
faar/
  runtime.py          # authority/risk/execution state machine, ambiguity window, adapter deadline
  gates.py            # deterministic policy gates
  models.py           # typed domain model, construction-time validation, KeyValidity
  parsing.py          # strict JSON document parsers
  canonical.py        # canonical serialization, hashing, bounded amount grammar
  attestation.py      # Ed25519 role-scoped attestations, signer/verifier split, key lifecycle
  permits.py          # constrained permit authority and permit-verifying gateway
  store.py            # durable SQLite reference store: intents, usage, permits, evidence, halt
  anchor.py           # external authority high-water mark (restore safety)
  adapters.py         # execution adapter contract and deterministic mock venue
  settlement.py       # independent settlement verifiers (mock, quorum)
  paper.py            # safe paper-trading adapter
  paper_gateway.py    # paper / loopback venue with split submit/query credentials
  hyperliquid.py      # fixed-origin, limit-IOC Hyperliquid testnet candidate + verifier
  outcomes.py         # definition-of-done verification
  cli.py              # demo, provisioning, and operator commands

docs/
  ARCHITECTURE.md         EXECUTION_PERMITS.md     OPERATIONS.md
  STORE_CONTRACT.md
  INVARIANTS.md           THREAT_MODEL.md          TRUST_MODEL.md
  RISK_ENGINE_CONTRACT.md ADAPTER_CONTRACT.md      RECOVERY.md
  GRANT_PROVISIONING.md   DEFINITION_OF_DONE.md    UNPLUG_TEST.md
  RED_TEAM_REPORT.md      GO_LIVE_CHECKLIST.md     V0_4_RELEASE.md
  HYPERLIQUID_TESTNET_ADAPTER_REVIEW.md
  V0_2_RELEASE_GATES.md   V0_3_RELEASE.md (historical)

schemas/              # intent, grant, risk, attestation, task contract (0.3 documents)
evals/                # adversarial, mapped red-team matrix, fuzz, bounded-model harnesses
test/                 # deterministic unit/invariant suite
examples/             # non-production fixtures
```

## Running it

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install -e ".[dev]"
make check      # unit tests, adversarial, red-team matrix, fuzz, demo, bounded model, crash injection
```

Operator commands (`python -m faar.cli --help`): `provision-grant`, `set-grant-status`, `halt`, `resume`, `controls`, `set-exposure-cap`, `exposure-caps`, `list-grants`, `list-intents`, `held-usage`, `list-leases`, `clear-lease`, `inspect`, `verify-evidence`, `rebuild-evidence-head`, `revoke-after-restore`, `checkpoint`, `evaluate`, `mock-run`. Procedures: [`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## Status

**v0.4.0 pre-alpha reference runtime. Not approved for live funds or production credentials.**

The repository now includes a first external-venue **testnet candidate** for a
narrow Hyperliquid spot BUY limit-IOC path. Its endpoint is fixed to testnet, its
tests use deterministic fakes, and its venue review explicitly leaves custody,
durable nonce allocation, independently operated settlement data, credentialed
testnet fault injection, datastore failover, and independent human review open.
It is not a live-money adapter approval. See
[`docs/HYPERLIQUID_TESTNET_ADAPTER_REVIEW.md`](docs/HYPERLIQUID_TESTNET_ADAPTER_REVIEW.md).

See [`docs/V0_4_RELEASE.md`](docs/V0_4_RELEASE.md). The deterministic release gate (`make check`) includes unit tests, adversarial denial/replay checks with adapter-call and permit-consumption metrics, a red-team matrix in which every attack class is mapped to named tests, seeded state-machine fuzz with an advancing clock, the demo CLI path with keyed evidence verification, and the bounded permit protocol model checker. Headline results:

- 412 unit/invariant tests run (411 pass, 1 optional-dependency skip)
- 183 targeted red-team attack classes mapped to 261 named tests, 0 unmapped
- 160 adversarial denial cases with 0 unauthorized economic effects and 0 adapter calls
- 100 same-intent replay attempts with 1 economic effect, 1 adapter call, 1 permit issued and consumed
- 96 seeded fuzz scenarios with 0 duplicate-effect and 0 aggregate-budget violations
- bounded permit model: 3940 states, 10047 transitions, 0 invariant violations; stale permits unconsumable after revoke and after halt/resume; 223 violations without the permit-window rule and 399 without the ledger check that stops on a consumed permit
- crash injection: a worker killed before every one of 309 store-call boundaries across 9 scenarios, including contradictory settlement and cumulative-fill regression; recovery produced 0 duplicate effects, 0 unsafe budget releases, and no non-terminal outcomes

These are deterministic regression, adversarial, fuzz, mutation-derived, and bounded-model results. They are not formal verification, an independent security audit, or a production-safety claim.

Before any live-money adapter, the repository still requires the gates in [`docs/V0_2_RELEASE_GATES.md`](docs/V0_2_RELEASE_GATES.md); [`docs/GO_LIVE_CHECKLIST.md`](docs/GO_LIVE_CHECKLIST.md) records which are closed in-repo (key rotation, cross-process fencing, restore safety, kill switch, exposure caps, velocity that counts venue actions, executor-side slippage bounds, bounded deadlines and abandoned-call cap, ambiguity window, partial fills, open orders and cancellation, crash recovery), which belong to a deployment (key custody, venue-side permit verification, credential scoping, authenticated ingress, anchor placement, capped exposure), and which remain open (datastore failover beyond SQLite, independent security review). Do not add a real-money adapter until every row is closed and independently reviewed.
