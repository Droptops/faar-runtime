# FAAR Adapter and Settlement Verifier Contract

A live adapter is a security boundary, not a convenience integration. Since v0.3
the execution side and the settlement side are two different components with two
different contracts, and the runtime refuses to start unless both are present.

```text
ExecutionAdapter.execute(request, permit) -> ExecutionReceipt      (submitter; untrusted telemetry)
SettlementVerifier.verify(request)        -> SettlementRecord      (independent; the only source of economic truth)
```

## Part A — Execution adapter

### A1. Input is minimized

The adapter receives a sanitized `ExecutionRequest` (`principal_id`, `intent_id`,
`primitive`, `venue`, post-gate `payload`) and a `SignedExecutionPermit`. It never
receives the model `Intent`, its metadata, the capability grant, or the
authority/risk decision objects. See [`EXECUTION_PERMITS.md`](EXECUTION_PERMITS.md).

The adapter may translate representation but cannot broaden economic meaning.
Material changes require a new intent and a new authorization pass. Forbidden:

- increasing notional to hit a venue minimum;
- selecting another target/router silently;
- adding leverage/bridge behaviour;
- enabling unlimited approvals;
- using agent-provided raw calldata/transaction blobs.

The payload carries exactly one economic amount field; a BUY/SELL/PLACE_ORDER
payload with both `amount_usd` and `notional_usd` is denied before the adapter
sees it. Amount strings are plain ASCII decimals (`50`, `50.00`, `0.5`).

### A2. Stable logical identity

Every external action must carry a venue-recognized stable identity derived from
FAAR `intent_id` whenever supported: idempotency key, client order ID,
payment-intent ID, contract intent hash/nonce.

### A3. The permit must be consumed before any effect

The venue, or a capability gateway in front of it, calls
`ExecutionPermitVerifier.consume(permit, request, now=...)` and creates an effect
only on success. A rejected permit is a `DeterministicFailure`. Consumption is
single use and checks the grant epoch, halt state and authority anchor in the
shared store; this is the cross-process revocation fence.

### A4. Receipts are telemetry

Whatever `execute` returns is recorded as `adapter_receipt_untrusted` and moves the
intent to `UNKNOWN (AWAITING_INDEPENDENT_SETTLEMENT)`. A receipt never advances the
state machine, never sets the effect id, and cannot crash the runtime: a malformed
effect id is recorded as such.

### A5. Failure classes

| Adapter raises | Runtime records | Then |
|---|---|---|
| `AmbiguousExecution` (incl. `AdapterDeadlineExceeded`) | `UNKNOWN (EXECUTION_AMBIGUOUS / EXECUTION_DEADLINE_EXCEEDED)` with `ambiguity_until = permit.expires_at` | independent reconciliation; absence is not trusted until the permit window closes |
| `DeterministicFailure` | `UNKNOWN (EXECUTION_DETERMINISTIC_FAILURE_UNVERIFIED)` | independent reconciliation; on authoritative NONE the intent ends `FAILED_SAFE` with usage released and no resubmission. A new intent is required. The permit may legitimately show `consumed_at` with no effect. |
| any other exception | `UNKNOWN (ADAPTER_EXECUTION_EXCEPTION)` with the ambiguity window | as for ambiguous |
| returns a receipt | `UNKNOWN (AWAITING_INDEPENDENT_SETTLEMENT)` | independent reconciliation |

Generic exceptions default to ambiguity, never to optimistic failure. A
deterministic rejection is not trusted as proof of non-execution either: the
verifier decides.

### A6. Deadlines

The runtime can bound `execute` with `adapter_deadline_seconds`. A Python call
cannot be cancelled, so an overrunning call is abandoned and its permit window
governs what the venue may still do. Adapters should additionally set their own
network timeouts below the permit TTL.

### A7. Declared security profile

The runtime refuses an adapter unless `AdapterSecurityProfile` declares all five
properties:

```text
stable_intent_identity
idempotent_submission
stable_effect_identity
permit_enforced
single_use_permit_consumption
```

This declaration is a compatibility gate, **not proof**. A production adapter
still needs venue-specific failure injection and independent review.

### A8. Authentication / key scope

The model cannot access venue signing credentials. Keys should have the narrowest
enforceable venue authority; a trading adapter should not hold withdrawal
authority where avoidable. If the venue cannot verify permits itself, the adapter
process is part of the trusted computing base and must be isolated accordingly.

## Part B — Settlement verifier

### B1. Independence

The verifier is a distinct object from the adapter with a
`SettlementSecurityProfile` whose four properties (`authoritative`,
`independent_from_submitter`, `stable_effect_identity`, `amount_evidence`) are all
true; the runtime refuses anything else. In production it should read the venue
through an independently authenticated path, a chain verifier, a clearing
record, or a quorum of sources (`QuorumSettlementVerifier`), not through the
submitter's own client.

### B2. Records

```python
SettlementRecord(
    status=SettlementStatus.NONE | UNKNOWN | CONFIRMED | FINALIZED | CONTRADICTORY,
    effect_id=str | None,
    amount_usd=Decimal | None,
    evidence={...},
    authoritative=bool,
    verified_request_hash=str,   # required whenever authoritative=True
)
```

`verified_request_hash` must be the canonical hash of the exact `ExecutionRequest`
the effect was produced for. A record bound to any other request is a
`SETTLEMENT_REQUEST_BINDING_MISMATCH` stop.

### B3. Authoritative absence

`NONE, authoritative=True` may be returned only if the lookup is authoritative
enough to prove that the action represented by the stable intent identity did not
create an effect. A single RPC/provider "not found", a transient 404, a cache miss
or a timeout is `authoritative=False`.

Even an authoritative NONE is ignored by the runtime while the last attempt's
permit is still live (see the ambiguity window in `EXECUTION_PERMITS.md`).

### B4. Authoritative positive evidence

`CONFIRMED`/`FINALIZED` must be authoritative, must carry a non-empty stable
`effect_id` (a bounded string), and for money-moving primitives a finite positive
`amount_usd`. FAAR rejects a settled amount above the authorized notional and
requires exact equality for `PAY`. An effect identity may not change across
observations.

Non-authoritative observations carry no weight in either direction: they leave the
intent `UNKNOWN`, never confirm, and never invalidate a previously recorded effect.
`CONTRADICTORY` stops the intent regardless of authority.

### B5. Quorum semantics

`QuorumSettlementVerifier` votes on `(status, effect_id, numeric amount)`; two
sources reporting `50` and `50.00` agree. A source that raises contributes a
non-authoritative UNKNOWN and is listed under `evidence["errors"]`. Two distinct
authoritative facts, whether or not either reaches quorum, or any authoritative
record bound to another request, are `CONTRADICTORY` (authoritative; the runtime
stops). One uncontested fact short of quorum is insufficient evidence, reported
as a non-authoritative UNKNOWN (`quorum-not-reached`) that the runtime retries;
a single transient source error therefore never terminally stops an intent.
Agreeing sources' evidence is merged into the record when identical and always
available under `evidence["source_evidence"]`, so definition-of-done criteria
remain evaluable.

## Part C — Partial fills and cancellation

Order adapters must document:

- how partial fills map to `effect_id` and settlement evidence;
- whether cancel is idempotent;
- late-fill-after-cancel behaviour;
- when held usage may be committed/released;
- how the risk engine receives partial-fill reservations/effects.

The reference runtime has no partial-fill state: any authoritative FINALIZED
amount at or below the authorized notional finalizes the intent and the ledger
commits the **authorized** notional, never less (conservative for turnover). Cancel
and late-fill linkage is out of scope for v0.4 and is an open go-live item.

## Required review document

The paper gateway (`faar/paper_gateway.py`) is the in-repo example of this
split: venue-side permit consumption, a `limit_price` envelope, and a query
credential that cannot submit. Its review record is
[`adapters/PAPER_GATEWAY.md`](adapters/PAPER_GATEWAY.md). It is not a live-money
adapter.

Before merge, every live adapter and its verifier must document:

```text
venue/authentication
credential permissions
stable intent identity
submission idempotency
permit verification point (venue or gateway)
reconciliation lookup + why it is authoritative
settlement/effect identity
finality definition
partial fills
cancellation
rate limits/outages
network timeouts vs permit TTL
retry budget
revocation/fencing
known venue failure modes
```
