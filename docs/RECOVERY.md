# Recovery and Reconciliation

## Core rule

Recover the **same logical `intent_id`**. Never infer `timeout == failure`, and never mint a new intent solely because a worker restarted.

## Submission ordering

FAAR persists `SUBMITTED` and increments a durable submission counter before invoking the adapter. A crash can therefore leave either:

```text
SUBMITTED + external effect occurred
SUBMITTED + no external effect occurred
```

Both reconcile first.

## Reconciliation contract

### FINALIZED / CONFIRMED

Requires an authoritative positive lookup, a non-empty stable `effect_id`, and—when the primitive moves money—a finite positive settled amount within the authorized economic envelope. `PAY` must match exactly; trading/swaps/orders may not exceed the authorized notional.

Persist the stable effect identity. If another intent already owns that effect ID, STOP. A non-authoritative positive observation remains UNKNOWN.

### NONE, authoritative=true

The adapter has positive authoritative evidence that no effect exists for this stable intent identity. Only then may a bounded resubmission be considered.

### NONE, authoritative=false

Treat as UNKNOWN. A weak provider/RPC not finding the effect is not proof of absence.

### UNKNOWN

Do not resubmit. Keep usage held and reconcile later or DEFER.

### CONTRADICTORY

STOP.

## Before resubmission

Even authoritative absence does not preserve old permission forever. Recheck:

- intent TTL;
- grant expiry and ACTIVE status;
- fresh authority attestation bound to the same intent;
- fresh risk attestation bound to the same intent;
- capability/risk gates;
- durable submission-attempt budget.

If any predicate fails, do not resubmit.

## Previously observed effect disappears or changes

```text
previous_effect_id != null
AND new_effect_id != previous_effect_id
=> STOP
```

and:

```text
previous_effect_id != null
AND reconcile == authoritative NONE
=> STOP
```

Reconciliation cannot erase history and thereby authorize a duplicate.

## Why usage remains held during ambiguity

If a $50 action may already have occurred, releasing its budget can authorize additional exposure beyond the grant. Ambiguous reservations remain conservative until authoritative absence or terminal settlement is proven.

## Retry budget

`submission_count` is persisted so restarting the process does not reset retry authority. The default reference limit is intentionally small.
