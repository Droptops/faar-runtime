# Execution Permits

The execution permit is the object that crosses from FAAR's policy domain into the
execution transport. An adapter never receives a generic venue credential from
FAAR; it receives a sanitized `ExecutionRequest` plus a signed, narrowly scoped
`ExecutionPermit`, and the venue (or a capability gateway in front of it) must
verify and consume that permit before it creates an economic effect.

```text
FAARRuntime ──► ConstrainedPermitAuthority.issue() ──► SignedExecutionPermit
                     │ independent re-check                      │
                     │ (grant, attestations, gates,              ▼
                     │  usage HELD, risk claim, fence)   adapter.execute(request, permit)
                     ▼                                           │
              store.record_execution_permit                      ▼
                                                    ExecutionPermitVerifier.consume()
                                                        │ signature, request hash, identity,
                                                        │ expiry, grant epoch, halt, anchor
                                                        ▼
                                             store.consume_execution_permit  (single use)
```

## Envelope

`ExecutionPermit` binds exactly one execution:

| Field | Binds |
|---|---|
| `principal_id`, `intent_id` | the durable economic identity |
| `request_hash` | the canonical `ExecutionRequest` (primitive, venue, post-gate payload) |
| `grant_id`, `grant_version`, `grant_hash` | the immutable provisioned grant envelope |
| `authority_attestation_hash`, `risk_attestation_hash` | the signed upstream decisions the permit was derived from |
| `grant_epoch` | the grant's runtime lifecycle epoch at issuance |
| `fence_token` | a monotonically increasing per-grant token (one permit per token) |
| `max_amount_usd` | the authorized economic amount (None for non-monetary primitives) |
| `issued_at`, `expires_at` | a short validity window |

The signature covers the permit body **and** the `signer_id` and `algorithm`
(`signed_permit_payload`), so a permit cannot be relabelled to another key.

## Issuance preconditions

`ConstrainedPermitAuthority.issue` does not trust the runtime that calls it. It
independently verifies, and refuses (`PermitIssuanceError`) unless all hold:

- the request is exactly `ExecutionRequest.from_intent(intent)`;
- the presented grant matches the provisioned fingerprint and principal;
- both attestations verify against the verify-only trust store for this intent;
- authority, capability and risk gates all return ALLOW at issuance time;
- an atomic usage reservation is HELD for the intent;
- the intent and grant are unexpired;
- the amount is a bounded decimal within `max_order_usd`;
- the risk state version is claimed for this intent (a fresh version on retry is
  itself claimed so no other intent can reuse it);
- the grant is ACTIVE, not halted, not regressed behind its authority anchor, and
  its epoch did not change while the fence token was allocated.

The permit's expiry is the minimum of the intent expiry, the grant expiry, **both
attestation expiries**, and `max_permit_ttl_seconds` (5 s by default). A permit
never outlives the credentials it was derived from.

## Consumption is the linearization point

`ExecutionPermitVerifier.consume` verifies the signature and every binding, then
calls `store.consume_execution_permit`, one `BEGIN IMMEDIATE` transaction that:

1. finds the permit row written at issuance and checks the ledger binding
   (`permit_hash`, fence token, epoch);
2. rejects an already consumed permit (`PERMIT_ALREADY_CONSUMED`), a permit the
   runtime voided when it acted on authoritative absence (`PERMIT_VOIDED`), and a
   permit that a later permit for the same intent has superseded
   (`PERMIT_SUPERSEDED`);
3. re-reads the grant row and rejects unless it is ACTIVE with the same epoch
   (`PERMIT_GRANT_NOT_ACTIVE`, `PERMIT_GRANT_EPOCH_STALE`), the scope is not
   halted (`PERMIT_HALTED`), the store can consult its authority anchor
   (`PERMIT_ANCHOR_REQUIRED`, `PERMIT_ANCHOR_UNAVAILABLE`) and authority did not
   regress (`PERMIT_AUTHORITY_REGRESSED`);
4. marks the permit consumed and advances the grant's fence counter, which is
   pushed to the authority anchor.

The gateway's pre-check (`verify`) reports the same status-specific codes, so a
venue operator can tell a halt or a restore apart from an ordinary pause. Its
`max_clock_skew_seconds` (default 5 s, the grant default) must be at least the
largest grant skew the deployment issues, or a venue clock inside the grant's
allowance rejects every permit as `PERMIT_FROM_FUTURE`. It also
bounds the permit's own lifetime (`PERMIT_TTL_EXCEEDED`, 60 s by default) and,
when the gateway knows which venue it serves (`ExecutionPermitVerifier(...,
venue=...)` or `consume(..., venue=...)`), refuses a permit for a request
addressed to any other venue (`PERMIT_VENUE_MISMATCH`) before anything is
consumed.

Because `set_grant_status`, `halt`, and consumption all run as IMMEDIATE
transactions on the same store, a permit either consumes before a lifecycle change
commits or is refused after it. This is the durable fence that the in-process
`execution_guard` cannot provide across processes.

The verifier returns `(False, ("PERMIT_MALFORMED",))` for structurally invalid
transport input rather than raising; the venue turns any rejection into a
`DeterministicFailure`.

## Ambiguity window

From the moment a permit exists the venue may act on it, whatever the adapter
reports afterwards: a timeout, an exception, a deterministic-looking rejection
(the request may have been queued before the transport failed), a receipt for a
request the venue has merely accepted, or a value the runtime cannot interpret.
The store therefore records `permit.expires_at` as the intent's `ambiguity_until`
**in the same transaction as the permit itself**, and refuses to record a second
permit for an intent while an earlier one can still be honoured
(`PERMIT_PREVIOUS_ATTEMPT_LIVE`; the runtime keeps the budget held). Until that
instant plus the grant's `max_clock_skew_seconds` has passed:

When the window has closed and absence is about to be acted on, the runtime voids
every unconsumed permit of the intent first (so a venue whose clock lags cannot
consume it afterwards) and refuses to release or retry if the ledger shows a
permit of the intent was consumed (`SETTLEMENT_NONE_AFTER_PERMIT_CONSUMED`). Every
terminal stop voids the same way before it transitions, so no terminal intent
leaves a live capability behind.

- an authoritative `NONE` from the settlement verifier is **not** trusted
  (`SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW`), the reservation stays HELD, and no
  retry is issued;
- a positive settlement is processed normally.

Only after the window closes may a retry be considered, and the retry is a new
authorization with fresh attestations and risk state. The bounded model in
`evals/model_check_permit_protocol.py` shows a duplicate effect is reachable
without this rule and unreachable with it.

## Signer / verifier separation

- `Ed25519PermitSigner` holds the private key and mints signatures. Only the
  permit authority holds one.
- `Ed25519PermitVerifier` holds the public key and exposes no `sign()`.
  `ExecutionPermitVerifier` refuses any backend with a signing API unless the
  test-only override is set; `has_signing_api` is the structural check.
- `ExecutionPermitVerifier` accepts several signer ids at once and a
  `KeyValidity` map, so a signer can be rotated with an overlap window and then
  revoked (`PERMIT_SIGNER_UNKNOWN`, `PERMIT_SIGNER_REVOKED`,
  `PERMIT_SIGNER_NOT_YET_VALID`, `PERMIT_SIGNER_EXPIRED`). Validity is judged on
  the permit's `issued_at`, so revocation is immediate while rotation never
  invalidates authority already granted.

`HMACPermitSignature` remains only as a symmetric compatibility fixture for tests;
the permit authority and the gateway both refuse it unless the explicit test-only
override is passed.

## Claim boundary

A permit narrows what a compromised worker or adapter can ask the venue to do and
makes the venue-side check independent of the calling process. It does not make a
venue that ignores permits safe: the live-money gates require a venue or gateway
that actually verifies permits, and the adapter remains part of the trusted
computing base until then (see `THREAT_MODEL.md`).
