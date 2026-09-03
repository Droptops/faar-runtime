# Paper Gateway Adapter Review

Paper / loopback venue. **Not a live-money adapter.** No production credential,
seed phrase, or funded account is used. This document is the review record
required by [`ADAPTER_CONTRACT.md`](../ADAPTER_CONTRACT.md).

The pair is `PaperGatewayAdapter` (submit) + `PaperGatewayVerifier` (query) in
`faar/paper_gateway.py`. They never share a client object or a credential. The
venue process (`PaperVenueService`) is the only holder of the book.

## venue/authentication

- Venue name: `paper-gateway`.
- Transport: in-process role-split clients, or loopback HTTP (`127.0.0.1` only).
- Authentication: two bearer tokens minted by the operator when the venue
  process starts. The submit token is accepted only on `POST /v1/orders`. The
  query token is accepted only on `POST /v1/reconcile`. A crossed token is
  `CREDENTIAL_DENIED` (HTTP 403). Health is unauthenticated and reveals no
  book state.

## credential permissions

- Submit credential: create or idempotently replay an order. Cannot read the
  book through the query API.
- Query credential: read one order by the sanitized `ExecutionRequest`. Cannot
  consume a permit or create an effect.
- Neither credential is a wallet, withdrawal, or transfer key. The venue has
  no withdraw path.

## stable intent identity

`client_order_id = "{principal_id}:{intent_id}"`. The venue treats that string
as the idempotency key and as the lookup key. Gate 4.2 for this venue.

## submission idempotency

A second submit of the same `client_order_id` with the same request hash
returns the stored receipt and does not consume another permit. A rebound
payload is `ORDER_REQUEST_BINDING_MISMATCH`. A cancelled or rejected order
refuses a new fill (`ORDER_ALREADY_CANCELLED` / `ORDER_ALREADY_REJECTED`).

## permit verification point (venue or gateway)

`ExecutionPermitVerifier.consume(..., venue=self.name)` runs inside
`PaperVenueService.submit` before any balance change. A permit minted for
another venue is `PERMIT_VENUE_MISMATCH` and creates no order. The adapter
process does not consume the permit. A rejected permit is
`PERMIT_REJECTED:<codes>` and creates no order. Cancel of a filled or missing
order is refused before consume.

## reconciliation lookup + why it is authoritative

`PaperGatewayVerifier.verify` uses the query credential only. For this paper
book the lookup is the venue's own order index keyed by `client_order_id`:

| Book state | Settlement | Authoritative | Why |
|---|---|---|---|
| absent | `NONE` | yes | the identity was searched and is not present |
| `REJECTED` / `CANCELLED` | `CANCELLED` (amount 0) | yes | admitted, then unfilled; consumed permit is not paired with absence |
| `PENDING` | `PARTIALLY_FILLED` (amount 0) | yes | open GTC; runtime CONFIRMS and never resubmits |
| `FILLED` | `FINALIZED` | yes | fill, effect id, amount, request hash |
| stored hash ≠ request | `CONTRADICTORY` | yes | rebound payload |

A transport or credential failure is non-authoritative `UNKNOWN`.
`effect_id` is the order identity from admission and does not change on fill.

## settlement/effect identity

A fill's `effect_id` is the order identity assigned at admission
(`pg_` + SHA-256(`venue`, `client_order_id`, `"order"`)[:24]). A later fill
does not mint a second id. A cancel is a separate intent with its own
`effect_id` and `amount_usd=None`.

## finality definition

Paper fills have no clearing delay. A fill is immediately `FINALIZED`. A
resting GTC is authoritative `PARTIALLY_FILLED` with amount 0 (open). An
admit-then-reject (worse than `limit_price`, insufficient balance) is
authoritative `CANCELLED` with amount 0. Gate 4.9 for this venue.

## partial fills

A marketable order fills completely at the book's fill price or not at all.
An unmarketable IOC is admitted then `CANCELLED` (`LIMIT_PRICE_EXCEEDED`).
A resting GTC is an open order (`PARTIALLY_FILLED` / amount 0) until a later
match or cancel. This exercises the runtime open-order path; it does not
model a partial economic fill.

## cancellation

`CANCEL_ORDER` consumes its own permit, then:

- `PENDING` → `CANCELLED`. Later `match_pending` / quote moves skip it.
  `_fill` also refuses `CANCELLED`. Gate 6.7 for this venue.
- `FILLED` → `ORDER_ALREADY_FILLED` before consume. Balances are not unwound.
- already `CANCELLED` → cancel is idempotent (state stays `CANCELLED`).
- missing → `ORDER_NOT_FOUND` before consume.

A cancelled order's original intent reconciles as authoritative `CANCELLED`
with amount 0.

## rate limits/outages

None beyond the HTTP client timeout. A transport error is
`AmbiguousExecution` (`PAPER_GATEWAY_TRANSPORT_ERROR:*`).

## network timeouts vs permit TTL

Default HTTP timeout is 2 s. Reference permits expire in 5 s. The client
timeout is below the permit TTL so a hung call becomes ambiguity bounded by
the permit window (A6).

## retry budget

The venue does not retry. FAAR's `max_submission_attempts` still applies.
Resubmitting a cancelled `client_order_id` is `ORDER_ALREADY_CANCELLED`.

## revocation/fencing

Permit consumption re-checks grant epoch, halt, and the authority anchor in
the shared store. A revoked or halted grant cannot fill.

## known venue failure modes

- Fill price can be configured worse than the displayed quote; the request
  `limit_price` is then the only envelope that stops the fill.
- GTC orders rest; FAAR sees non-authoritative `UNKNOWN` until fill or cancel.
  The runtime still has no open-order state (R-14).
- SQLite failover is not exercised here (gate 6.4).
- Tokens are process-local strings, not KMS credentials (R-03).
- The adapter process that holds the submit token remains in the TCB for
  submission (R-04). The verifier is not.

## What this does not claim

This is not an independent security review (gate 8), not a live venue, and not
a production-safety claim. It turns the paper-gateway rows for gates 4.2, 4.4
(open-order), 4.9, 6.7 and residual R-12 into in-repo tests. A real venue
still needs its own review document and the remaining DEPLOYMENT rows. Live
funds remain prohibited.
