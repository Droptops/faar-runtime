# Definition of Done for Economic Agents

## Problem

Agent systems often have multiple layers of apparent completion:

```text
model produced a plan
adapter submitted a request
venue accepted it
money moved
business objective occurred
```

These are not equivalent.

For FAAR, a financial effect is a mechanism. It is not automatically the user's outcome.

## Separate state machines

### Economic settlement

```text
SettlementStatus: NONE | UNKNOWN | CONFIRMED | FINALIZED | CONTRADICTORY
IntentState:      SUBMITTED -> UNKNOWN -> RECONCILING -> CONFIRMED -> FINALIZED
```

Answers: **did this economic effect occur?**

### Task outcome

```text
UNKNOWN -> MET | NOT_MET
```

Answers: **did the effect satisfy criteria fixed before execution?**

## Signed task contract

A task contract contains:

```text
task_id
intent_id
objective
criteria[]
issued_at
expires_at
```

The criteria are authenticated before execution. The agent cannot observe a poor result and redefine “done.” The task contract also has an explicit validity window so stale success criteria cannot be replayed indefinitely.

Example:

```json
{
  "objective": "buy at most $75 of TOKEN_X and receive settlement evidence",
  "criteria": [
    {"path": "amount_usd", "op": "lte", "value": "75"},
    {"path": "asset_out", "op": "eq", "value": "TOKEN_X"},
    {"path": "fill_qty", "op": "gte", "value": "1"}
  ]
}
```

A venue response with `FINALIZED` but missing `fill_qty` yields `NOT_MET`; it does not become successful merely because the transaction exists. A non-authoritative `FINALIZED` observation, a record without an effect id, or a record bound to a different intent's execution request is not eligible for outcome promotion at all (`UNKNOWN`).

Standard settlement fields (`effect_id`, `amount_usd`, `status`) are normalized by FAAR and override same-named adapter evidence before criteria are evaluated. This prevents an adapter evidence blob from redefining the meaning of those control fields.

Criterion semantics:

- `present`: the path exists and is neither `null` nor `""` (the criterion `value` is ignored);
- `eq`: numeric equality when both sides are numbers (`"50"` equals the normalized `Decimal("50")` and `"50.00"`), never a boolean/number conflation, otherwise same-type equality;
- `gte` / `lte`: numeric only.

The attested verifier (`verify_attested_task_outcome`) binds the settlement record to the canonical hash of this intent's `ExecutionRequest`; a settlement produced for any other intent is `UNKNOWN` (`TASK_SETTLEMENT_INTENT_MISMATCH`). Behind a `QuorumSettlementVerifier`, agreeing sources' evidence is merged into the record (and always available under `source_evidence`) so evidence-path criteria remain evaluable.

## Why this matters for autonomous finance

Without an outcome boundary, an agent can optimize proxy metrics:

- “submitted order” instead of “obtained intended exposure”;
- “sent payment” instead of “service delivered”;
- “created campaign” instead of “acquired customers”;
- “closed position” instead of “risk actually neutralized.”

The runtime should measure the terminal condition the principal actually cares about, using external evidence whenever possible.

## Design influence

This distinction was reinforced by the linked discussion about agents that produce process/artifacts versus agents that deliver measurable outcomes. FAAR applies that idea narrowly: **settlement evidence and definition-of-done evidence are different control objects.**
