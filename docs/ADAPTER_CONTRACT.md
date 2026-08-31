# FAAR Adapter Contract

A live adapter is a security boundary, not a convenience integration.

## 1. Stable logical identity

Every external action must carry a venue-recognized stable identity derived from FAAR `intent_id` whenever supported: idempotency key, client order ID, payment-intent ID, contract intent hash/nonce, etc.

## 2. Authoritative reconciliation

An adapter may return:

```text
SettlementRecord(state=NONE, authoritative=true)
```

only if its lookup is authoritative enough to prove that the action represented by the stable intent identity did not create an effect.

A single RPC/provider “not found,” transient 404, cache miss, or timeout is normally `authoritative=false`/UNKNOWN.

If an adapter cannot provide venue idempotency or authoritative reconciliation, unattended retry must be disabled and the intent should DEFER.

## 3. Stable effect identity and authoritative positive evidence

CONFIRMED/FINALIZED must include an `effect_id` whose semantics are documented. Examples include transaction hash + canonical event, exchange fill/order identity, or provider payment-intent/ledger identity.

An effect identity may not silently change across reconciliation. Positive reconciliation (`CONFIRMED` / `FINALIZED`) must also be authoritative; a weak observation cannot finalize an effect any more than a weak `not found` can prove absence.

For money-moving primitives the record must include a finite positive `amount_usd`. FAAR rejects a settled amount above the authorized notional and requires exact amount equality for `PAY`.

## 4. Exact request construction and minimized input

The adapter receives a sanitized `ExecutionRequest`, not the full model `Intent`. It contains only the stable intent ID, primitive, venue, and post-gate economic payload. Model metadata, grant contents, authority/risk objects, and signing material are not present at this boundary.

The adapter may translate representation but cannot broaden economic meaning. Material changes require a new intent and authorization pass.

Forbidden examples:

- increasing notional to hit a venue minimum;
- selecting another target/router silently;
- adding leverage/bridge behavior;
- enabling unlimited approvals;
- using agent-provided raw calldata/transaction blobs.

## 5. Declared recovery semantics

The reference runtime refuses an adapter unless its `AdapterSecurityProfile` declares all four properties:

```text
stable_intent_identity
idempotent_submission
authoritative_reconciliation
stable_effect_identity
```

This declaration is a compatibility gate, **not proof** that a live adapter actually satisfies those semantics. A production adapter still needs failure injection and independent review.

## 6. Failure classes

Adapters distinguish:

- deterministic failure: known no effect occurred;
- ambiguous failure: effect may have occurred;
- confirmed/finalized success;
- contradictory evidence.

Generic exceptions default to ambiguity, not optimistic failure.

## 7. Partial fills and cancellation

Order adapters document:

- how partial fills map to `effect_id` and settlement evidence;
- whether cancel is idempotent;
- late-fill-after-cancel behavior;
- when held usage may be committed/released;
- how the risk engine receives partial-fill reservations/effects.

## 8. Authentication/key scope

The model cannot access venue signing credentials. Keys should have the narrowest enforceable venue authority; a trading adapter should not hold withdrawal authority where avoidable.

## 9. Revocation/fencing

A production adapter path must participate in the deployment's distributed execution fence so an old worker cannot submit after revocation has completed.

## Required review document

Before merge, every live adapter must document:

```text
venue/authentication
credential permissions
stable intent identity
submission idempotency
reconciliation lookup + why it is authoritative
settlement/effect identity
finality definition
partial fills
cancellation
rate limits/outages
retry budget
revocation/fencing
known venue failure modes
```
