# Hyperliquid Testnet Adapter Review

Status: **testnet candidate; not approved for live funds or production credentials**.

This is the venue-specific review required by [`ADAPTER_CONTRACT.md`](ADAPTER_CONTRACT.md).
It covers `HyperliquidTestnetAdapter`, `HyperliquidTestnetHTTPTransport`, and
`HyperliquidTestnetSettlementVerifier` in `faar/hyperliquid.py`. The code is
hard-bound to `https://api.hyperliquid-testnet.xyz`; there is no configurable or
mainnet execution origin.

The implementation is deliberately narrower than FAAR's generic trading model:

- spot `BUY` only;
- `USDC` quote only;
- operator-pinned market id and `szDecimals` only;
- absolute limit price and `IOC` time in force only;
- no market, GTC, ALO, trigger, builder-fee, perpetual, HIP-3, outcome, sell,
  transfer, withdrawal, bridge, modify, or cancel action;
- no automatic application retry.

That scope is a testable first venue slice, not a claim that Hyperliquid as a
whole satisfies FAAR's contract.

## Venue and authentication

Orders are signed Hyperliquid L1 actions sent to the testnet `/exchange`
endpoint. `HyperliquidTestnetHTTPTransport` accepts a narrow
`HyperliquidTestnetActionSigner`; it does not load a private key, seed phrase, or
wallet file. The signer receives one already-bounded IOC action, its nonce, the
permit-bound `expiresAfter`, and the configured vault/subaccount address.
The transport signs a private copy and refuses to send if an in-process signer
mutates that copy while inspecting it.

The concrete signer is intentionally outside this repository. A deployment must
put it in an isolated process or KMS/HSM-backed service that independently
revalidates the exact action shape. Supplying a callback that can sign arbitrary
Hyperliquid actions does not close the signer-isolation or credential-scope gates.

Settlement reads use the credential-free testnet `/info` endpoint through a
different client object. The account address is operator configuration; an API
wallet address must not be substituted for the master/subaccount address.

## Credential permissions

Not proven in-repo. The deployment must use a dedicated API wallet and show that:

1. the model/runtime process cannot read its private material;
2. the signer accepts only the exact order action emitted by this adapter;
3. transfer, withdrawal, bridge, approval, account-administration, and alternate
   execution paths are unavailable;
4. the funded testnet account/subaccount is capped to the planned test exposure.

The Python interface narrows what this adapter asks a signer to sign. It does not
prove what the underlying key could sign if the signer service were compromised.

## Stable intent identity

`hyperliquid_cloid(request)` derives a lowercase 128-bit client order id from the
domain-separated pair `(principal_id, intent_id)`. The same logical intent always
gets the same `cloid`; another principal gets a different namespace. Hyperliquid's
order-status endpoint is queried by that `cloid`.

The request hash is not truncated into the id. Reusing an `intent_id` with a
different payload is already a durable FAAR conflict, while keeping the venue id
stable lets an ambiguous attempt be reconciled.

## Submission idempotency

There are three layers:

1. the capability gateway atomically consumes the signed FAAR permit immediately
   before submission, so a concurrent/replayed call cannot reach the transport;
2. the transport sends one POST and has no automatic application retry;
3. the Hyperliquid action uses the permit's millisecond `issued_at` as its nonce
   and signs `expiresAfter = permit.expires_at`. Hyperliquid rejects reuse of a
   nonce while its nonce state exists; after the short permit window, the signed
   expiry rejects the envelope even if an API wallet is later pruned.

The `cloid` is used for identity and lookup; this review does **not** rely on an
undocumented claim that duplicate `cloid` submission itself is idempotent.

Two permits issued in one millisecond for the same API wallet can collide on the
nonce. That is fail-safe (one or both orders are rejected), but it is an
availability problem. A real testnet deployment should dedicate one API wallet to
one signer process and replace the timestamp choice with an atomic, durable nonce
allocator that returns the same nonce for the same permit. That allocator must be
ported with the production datastore and tested under failover before live use.

Hyperliquid warns that deregistered/expired/unfunded API wallets may have nonce
state pruned and must not have their addresses reused. Operations must retain the
wallet registration until every signed action has expired and use a fresh address
after deregistration.

## Permit verification point

`HyperliquidTestnetAdapter.execute()` validates and translates the order first,
checks that enough permit lifetime remains, then calls
`ExecutionPermitVerifier.consume(..., venue="hyperliquid-testnet")`. Only a
successful, epoch-current, single-use consume reaches signing/submission.

This is a capability gateway in front of the venue, not native Hyperliquid permit
verification. The adapter/gateway and constrained signer therefore remain in the
trusted computing base (R-04).

## Price and notional enforcement

Only an absolute, request-hash-bound `limit_price` is accepted. Relative
`max_slippage_bps` is rejected because enforcing it would require an independently
trusted reference price at execution time. Hyperliquid's IOC limit is serialized
unchanged; a BUY fill above it is contradictory settlement.

Base size is rounded **down** to the pinned venue `szDecimals`. It is never rounded
up to meet the venue minimum. The maximum quote spend, conservatively rounded up
to FAAR's eight-decimal ledger unit, must remain at or below the authorized
notional. Orders below the pinned minimum are rejected before permit consumption.

SELL is excluded because converting a USD authorization into a safe base-asset
quantity needs a separately trusted valuation rule. PLACE_ORDER is excluded
because the current generic payload has no signed side field.

## Reconciliation and authority

The verifier does not read the submitter receipt. It independently:

1. derives the `cloid` from the execution request;
2. queries `orderStatus` by account and `cloid`;
3. reconstructs the expected coin, BUY side, absolute limit, size, limit type,
   IOC time in force, non-trigger, and non-reduce-only flags;
4. queries fills from the order timestamp and selects them by venue order id;
5. deduplicates by trade id and checks coin, side, positive size, and price at or
   below the signed limit;
6. checks that cumulative fill size equals `origSz - sz` and that quote notional
   remains inside the authorization.

Any order-term mismatch, conflicting trade id, regressing/impossible size,
above-limit fill, over-notional fill, or non-terminal IOC state is
`CONTRADICTORY`. Transport errors, unknown future statuses, incomplete fill
history, a possibly truncated page, and `unknownOid` are non-authoritative
`UNKNOWN`; a single API miss is never authoritative absence.

The public API is independent from the submitter object and reports committed L1
state, which is sufficient for this testnet candidate. A live design should read
an independently operated non-validating node or require a quorum with one. The
API exposes only recent fill history; recovery after the history horizon needs an
archival source.

## Settlement identity and amount

The effect id is `hyperliquid-testnet:order:<oid>`. It remains the order identity
across all fills. Each fill's `tid` is used only to deduplicate the cumulative
amount; it is not promoted to a second FAAR effect.

`amount_usd` is the sum of `fill.sz * fill.px`, rounded upward to eight decimals.
That conservative rounding is included in the pre-submit size bound, so it cannot
exceed the authorized notional on a conforming fill.

## Finality definition

For this candidate, a terminal order record returned by `/info` is final after the
order action is included in a committed Hyperliquid L1 block. Hyperliquid documents
that an API server waits for committed-block inclusion before replying and that
HyperCore orders have one-block finality under HyperBFT.

- `filled` with complete matching fills -> FAAR `FINALIZED`;
- documented cancellation statuses -> FAAR `CANCELLED`, preserving any fill;
- documented rejection statuses with zero fill -> FAAR `CANCELLED`;
- `open` or `triggered` for this IOC-only adapter -> `CONTRADICTORY`;
- an unrecognized status -> non-authoritative `UNKNOWN` pending review.

This mapping must be replayed against the real testnet before approval and
reviewed whenever Hyperliquid changes its status vocabulary.

## Partial fills and cancellation

IOC is the only admitted time in force. Hyperliquid specifies that its unmatched
remainder is canceled rather than rested, so a partially filled IOC is terminal:
the verifier returns `CANCELLED` with the cumulative quote fill. An unfilled IOC
rejection is `CANCELLED` with zero amount. The adapter never emits a separate
cancel action and does not support FAAR `CANCEL_ORDER`.

The venue's IOC atomicity is the cancellation-terminal guarantee for this slice.
An `open` order record or any later fill that contradicts the terminal cumulative
record is a contract violation and stops the intent; it is never retried.

## Rate limits and outages

Hyperliquid documents an aggregate REST weight budget of 1200 per minute per IP;
`orderStatus` has weight 2 and fill-history reads also consume item-weighted
capacity. The adapter deliberately performs no hidden retry or batching. The
deployment must provision request budgets for one submission plus repeated
reconciliation and treat 429, 5xx, DNS, TLS, timeout, malformed, and oversized
responses as unavailable/ambiguous.

The fill endpoint is bounded (2000 per response and only recent history). The
configured threshold cannot exceed 2000, and a page at that threshold gets no
settlement weight. High-volume accounts need a dedicated archival verifier
rather than raising this limit optimistically.

## Network timeouts versus permit TTL

The HTTP clients default to 2 seconds and refuse values above 10 seconds. The
reference permit TTL is 5 seconds. A deployment should configure:

```text
HTTP timeout < FAARRuntime adapter deadline < permit TTL
```

The adapter also refuses, before consumption, a permit with less than 250 ms left
by default. The exact permit expiry is signed into `expiresAfter`; a request that
arrives late is rejected by the venue and reconciled, never silently retried.

## Retry budget

The transport submits once. A timeout or malformed/error response after permit
consumption is `AmbiguousExecution`; only the independent verifier decides what
happened. Runtime resubmission remains governed by the existing permit window,
authoritative-absence, risk reauthorization, and `max_submission_attempts` rules.

Because this verifier never treats `unknownOid` as authoritative absence, the
current single-source candidate may sacrifice liveness rather than submit again.
An authoritative negative quorum/archival proof is required before enabling that
retry path for this venue.

## Revocation and fencing

Pause, revoke, halt, restored-authority regression, and permit-signer revocation
are checked by the shared control store when the adapter consumes the permit. A
successful lifecycle stop that races with submission linearizes against that
consume. Hyperliquid does not understand FAAR permits natively, so this guarantee
depends on there being no alternate route around the gateway/signer.

## Known venue and implementation failure modes

- testnet behavior and asset ids can differ from mainnet;
- operator-pinned `asset_id`, `coin`, and `szDecimals` can go stale;
- same-millisecond nonce collision can reject an otherwise valid order;
- API-wallet nonce state can be pruned; addresses must not be reused;
- `unknownOid` and transient API/cache misses cannot prove absence;
- fill history is finite and can be truncated;
- a pre-validation error may consume the FAAR permit but leave no authoritative
  venue record, causing a safe STOP/held budget;
- the separate `/info` path still shares Hyperliquid consensus ground truth; a
  compromised API operator is not an independent quorum;
- the signer implementation, custody, process isolation, and ingress are absent;
- no credentialed real-testnet transcript or kill/partition campaign is included;
- no claim is made for SELL, resting orders, explicit cancel, perps, HIP-3, or
  mainnet.

## Evidence in this repository

`test/test_hyperliquid.py` covers:

- exact fixed-origin limit-IOC serialization and signer input;
- rejection of mainnet/other origins and malformed signer output;
- rejection before permit consumption of unsupported primitives, targets,
  bounds, precision, markets, and venue-minimum rounding;
- single-use permit replay and one-shot transport behavior;
- lost-response recovery from a distinct verifier object;
- complete filled and canceled settlement;
- every order-term binding, fill-id contradiction, price/notional bound,
  non-terminal IOC, missing order, incomplete history, truncation, and provider
  outage.

All tests use deterministic fakes and no network, account, or signing secret.

## Required work before a funded testnet trial

1. Implement and separately deploy the constrained signer; record its exact
   allowed action schema and demonstrate all other action types are refused.
2. Provision a dedicated API wallet/subaccount with no alternate execution path.
3. Add a durable per-signer nonce allocator and run it against the chosen
   production datastore/failover implementation.
4. Pin market metadata from testnet and add a startup check that refuses drift.
5. Run a credentialed testnet matrix: fill, partial IOC, no-fill IOC, invalid tick,
   insufficient balance, timeout before/after committed inclusion, duplicate
   envelope, signer restart, API outage, stale status, and history truncation.
6. Add an independently operated node or quorum/archival settlement source.
7. Obtain the gate-8 human security review over core, adapter, signer, deployment,
   and the captured evidence.

## Primary venue references

- [API and testnet origin](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api)
- [Exchange endpoint, IOC, cloid, and expiresAfter](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/exchange-endpoint)
- [Info endpoint, order status, and fills](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint)
- [Nonces and API wallets](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets)
- [Tick and lot size](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/tick-and-lot-size)
- [API servers and committed-block responses](https://hyperliquid.gitbook.io/hyperliquid-docs/hypercore/api-servers)
- [Rate limits](https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/rate-limits-and-user-limits)
