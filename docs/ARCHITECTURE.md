# FAAR v0.2 Architecture

## Security objective

FAAR narrows the path from an untrusted agent proposal to an external economic effect. The model is allowed to be wrong, manipulated, overconfident, or malicious; the security claim lives in deterministic code and separately trusted evidence domains.

```text
                     UNTRUSTED
              Strategy / LLM / tools
                       │ proposal
                       ▼
              Canonical economic Intent
                       │ stable hash
       ┌───────────────┴────────────────┐
       │                                │
       ▼                                ▼
 Authority signer                  Risk signer
 AAR posture/primitive             portfolio state
       │ signed attestation             │ signed attestation
       └───────────────┬────────────────┘
                       ▼
                 FAAR Runtime
       ┌───────────────┼──────────────────────┐
       │               │                      │
 grant registry    deterministic gates   transactional store
 fingerprint       capability + risk     intent/usage/risk claim
 runtime status           │                      │
       └───────────────┬───┴──────────────────────┘
                       ▼
               submission fence
                       │
                       ▼
               reviewed adapter
                       │
                       ▼
              external venue/chain
                       │
                       ▼
          authoritative reconciliation
                       │
                       ▼
              economic settlement
                       │
                       ▼
             signed task contract
                       │
                       ▼
          deterministic outcome check
             MET / NOT_MET / UNKNOWN
```

## Why split the trust domains

A single LLM-generated object such as:

```json
{"authorized": true, "risk_ok": true, "amount": 1000}
```

is not a security boundary. If the coordinator or model can fabricate both authorization and risk evidence, deterministic downstream checks provide little protection.

v0.2 therefore binds two upstream decisions to the exact canonical intent:

- **authority attestation**: posture and work primitive;
- **risk attestation**: portfolio/market state and risk-state version.

The reference implementation uses HMAC-SHA256 because it is dependency-free and easy to test. Production should normally separate signing and verification with KMS/HSM-backed asymmetric keys.

## Intent lifecycle

The durable state machine distinguishes authorization, reservation, submission, ambiguity, reconciliation, and settlement. Important properties:

- storing `SUBMITTED` happens before the external adapter call;
- a process restart resumes the same intent;
- ambiguous execution never creates a new logical intent;
- resubmission requires authoritative proof of absence, fresh authorization/risk, unexpired authority, ACTIVE grant status, and remaining retry budget.

## Grant lifecycle

The complete grant document is fingerprinted:

```text
(grant_id, version) -> SHA256(canonical grant)
```

Runtime status is separate:

```text
ACTIVE <-> PAUSED
ACTIVE/PAUSED -> REVOKED
REVOKED -X-> ACTIVE
```

A revoked version cannot be resurrected. New authority requires a new grant version.

Money-moving grants are bounded by construction: explicit asset scope, positive per-action and daily-turnover caps, and an action-velocity limit are mandatory; PAY/SWAP also require target allowlists.

## Risk-state concurrency

Per-order checks are not enough. Two different intents can each look safe against the same portfolio snapshot and jointly exceed a limit.

Every trusted risk snapshot therefore carries:

```text
scope
state_version
observed_at
```

FAAR atomically claims one state version for one new intent. A second intent must obtain a newer trusted state version. The risk engine is responsible for advancing versions only after incorporating prior reservations/effects; see `RISK_ENGINE_CONTRACT.md`.

## Adapter boundary

The adapter is not a generic tool pass-through. FAAR converts the authorized `Intent` into a minimized `ExecutionRequest`; the adapter never receives model metadata, the capability grant, or the authority/risk decision objects. Agent-supplied calldata, raw transactions, signing payloads, key material, delegatecall, unlimited approvals, and unknown execution fields are rejected before this boundary.

The runtime also requires the adapter to declare stable intent identity, idempotent submission, authoritative reconciliation, and stable effect identity. That declaration is not a security proof; the adapter remains part of the reference trusted computing base.

Positive reconciliation is required to be authoritative. For money-moving effects FAAR also checks that a settled amount exists and does not exceed the authorized notional (`PAY` requires exact equality).

## Settlement vs outcome

Settlement answers:

> Did the economic effect occur?

Outcome verification answers:

> Did that effect satisfy the objective fixed before execution?

Those are intentionally separate. A finalized payment can still fail to purchase the desired service; a filled trade can still fail a strategy-level objective.
