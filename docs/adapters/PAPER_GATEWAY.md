# Paper Gateway Adapter Review

Paper / loopback venue. **Not a live-money adapter.** No production credential,
seed phrase, or funded account is used. This document is the review record
required by [`ADAPTER_CONTRACT.md`](../ADAPTER_CONTRACT.md).

The pair is `PaperGatewayAdapter` (submit) + `PaperGatewayVerifier` (query) in
`faar/paper_gateway.py`. They do not share a client object or role credential,
but both reach the same `PaperVenueService` and in-memory book. This exercises
role separation and the runtime's distinct-object requirement; it is not an
independently operated settlement source.

## venue/authentication

- Venue name: `paper-gateway`; each service instance is pinned to one principal
  and one target.
- Transport: in-process role-split clients, or numeric loopback HTTP
  (`127.0.0.1` by the bundled server). HTTP clients reject DNS names, non-loopback
  addresses, HTTPS, userinfo, path prefixes, query strings and missing ports
  before sending a bearer token or permit.
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
- In-process objects share one Python interpreter, so attribute access is not
  credential isolation. The loopback routes demonstrate role checks, not OS
  process isolation, secret custody, or an independent data source.

## stable intent identity

`client_order_id` is `pco_` plus SHA-256 over a canonical, domain-separated object
containing `principal_id` and `intent_id`. It is stable, does not expose either
identifier, and delimiter-containing identity pairs have distinct preimages. The
venue treats it as both idempotency and lookup key.

## supported order semantics

This reference gateway accepts only signed `BUY` or `SELL` limit orders quoted
in `USDC`, with `IOC` (the default) or `GTC` time in force. `PLACE_ORDER` is
rejected because its payload has no signed side; interpreting it as `BUY` would
broaden the request. `SWAP`, `PAY`, market/FOK orders, non-USDC quote assets and
requests carrying both an absolute limit and `max_slippage_bps` are refused
before permit consumption. The service also checks its pinned principal and
target before consumption.

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

`PaperGatewayVerifier.verify` uses the query credential only. For this running
paper process, lookup reads the venue's own order index keyed by
`client_order_id`:

| Book state | Settlement | Authoritative | Why |
|---|---|---|---|
| absent | `NONE` | yes | the identity was searched and is not present |
| `REJECTED` / `CANCELLED` | `CANCELLED` (amount 0) | yes | admitted, then unfilled; consumed permit is not paired with absence |
| `PENDING` | `PARTIALLY_FILLED` (amount 0) | yes | open GTC; runtime CONFIRMS and never resubmits |
| `FILLED` | `FINALIZED` | yes | fill, effect id, amount, request hash |
| stored hash ≠ request | `CONTRADICTORY` | yes | rebound payload |

A transport or credential failure is non-authoritative `UNKNOWN`. Malformed
wire types are rejected rather than coerced; in particular, the string
`"false"` can never become an authoritative record. `effect_id` is the order
identity from admission and does not change on fill.

"Authoritative" here means authoritative for the lifetime of this exact
in-memory test process. The book is not durable. After a restart it cannot prove
absence for pre-restart activity; a consumed permit plus reported absence still
causes the FAAR runtime to STOP. This does not satisfy production failover or
independent-source evidence.

## settlement/effect identity

A fill's `effect_id` is the order identity assigned at admission (`pg_` plus
SHA-256 over a canonical domain-separated tuple of venue, client order id and
`"order"`). A later fill
does not mint a second id. Quantities and price evidence are computed atomically
from the executable quote at actual fill time, not cached when a GTC order is
admitted. A cancel is a separate intent with its own `effect_id` and
`amount_usd=None`.

## finality definition

Paper fills have no clearing delay. A fill is immediately `FINALIZED`. A
resting GTC is authoritative `PARTIALLY_FILLED` with amount 0 (open). An
admit-then-reject (worse than `limit_price`, insufficient balance) is
authoritative `CANCELLED` with amount 0. Gate 4.9 for this venue.

## partial fills

A marketable order fills completely at the book's fill price or not at all.
An unmarketable IOC is admitted then `CANCELLED` (`LIMIT_PRICE_EXCEEDED`).
A resting GTC is an open order (`PARTIALLY_FILLED` / amount 0) until a later
match or cancel. If that later match cannot apply both balance legs, it becomes
an authoritative unfilled `CANCELLED` record rather than remaining open. This
exercises the runtime open-order path; it does not model a partial economic fill.

## cancellation

`CANCEL_ORDER` consumes its own permit, then:

- `PENDING` → `CANCELLED`. Later `match_pending` / quote moves skip it.
  `_fill` also refuses `CANCELLED`. Gate 6.7 for this venue.
- `FILLED` → `ORDER_ALREADY_FILLED` before consume. Balances are not unwound.
- already `CANCELLED` → cancel is idempotent (state stays `CANCELLED`).
- missing → `ORDER_NOT_FOUND` before consume.
- an order owned by another principal → `ORDER_NOT_OWNED` before consume.

A cancelled order's original intent reconciles as authoritative `CANCELLED`
with amount 0.

## rate limits/outages

None beyond the HTTP client timeout, which must be finite and at most 60 seconds.
A transport error is
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
- GTC orders reconcile as authoritative `PARTIALLY_FILLED` amount 0 while open;
  FAAR records `SETTLEMENT_ORDER_OPEN` and never resubmits them.
- The book and order index are volatile. Restart recovery and datastore failover
  are not implemented.
- SQLite failover is not exercised here (gate 6.4).
- Tokens are process-local strings, not KMS credentials (R-03).
- The adapter process that holds the submit token remains in the TCB for
  submission (R-04). The verifier route shares the venue process and economic
  ground truth (R-12); separate credentials alone do not remove it from the TCB.
- The bundled loopback server has no TLS, external authentication, durable rate
  limiter, or slow-client isolation. It must not be exposed outside the host.

## What this does not claim

This is not an independent security review (gate 8), not a live venue, and not
a production-safety claim. It provides in-repo model coverage for stable
identity, open orders, finality and cancellation, plus structural submit/query
role separation. It does not close those rows for a real venue and does not
close R-12. A real venue still needs its own review document, independently
authenticated settlement evidence, and every remaining DEPLOYMENT row. Live
funds remain prohibited.
