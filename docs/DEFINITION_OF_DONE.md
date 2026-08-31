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
NONE -> SUBMITTED -> UNKNOWN/CONFIRMED -> FINALIZED
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

A venue response with `FINALIZED` but missing `fill_qty` yields `UNKNOWN`/`NOT_MET` depending on the criterion semantics; it does not become successful merely because the transaction exists. A non-authoritative `FINALIZED` observation is not eligible for outcome promotion at all.

Standard settlement fields (`effect_id`, `amount_usd`, `status`) are normalized by FAAR and override same-named adapter evidence before criteria are evaluated. This prevents an adapter evidence blob from redefining the meaning of those control fields.

## Why this matters for autonomous finance

Without an outcome boundary, an agent can optimize proxy metrics:

- “submitted order” instead of “obtained intended exposure”;
- “sent payment” instead of “service delivered”;
- “created campaign” instead of “acquired customers”;
- “closed position” instead of “risk actually neutralized.”

The runtime should measure the terminal condition the principal actually cares about, using external evidence whenever possible.

## Design influence

This v0.2 distinction was reinforced by the linked discussion about agents that produce process/artifacts versus agents that deliver measurable outcomes. FAAR applies that idea narrowly: **settlement evidence and definition-of-done evidence are different control objects.**
