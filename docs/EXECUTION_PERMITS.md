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
2. rejects an already consumed permit (`PERMIT_ALREADY_CONSUMED`);
3. re-reads the grant row and rejects unless it is ACTIVE with the same epoch
   (`PERMIT_GRANT_NOT_ACTIVE`, `PERMIT_GRANT_EPOCH_STALE`), the scope is not
   halted (`PERMIT_HALTED`), and authority did not regress
   (`PERMIT_AUTHORITY_REGRESSED`);
4. marks the permit consumed.

Because `set_grant_status`, `halt`, and consumption all run as IMMEDIATE
transactions on the same store, a permit either consumes before a lifecycle change
commits or is refused after it. This is the durable fence that the in-process
`execution_guard` cannot provide across processes.

The verifier returns `(False, ("PERMIT_MALFORMED",))` for structurally invalid
transport input rather than raising; the venue turns any rejection into a
`DeterministicFailure`.

## Ambiguity window

If the adapter call does not return a definite result (timeout, exception, or the
runtime's `adapter_deadline_seconds` elapsed), the request may still be in flight.
The venue can act on it exactly until the permit expires. The runtime therefore
records `permit.expires_at` as the intent's `ambiguity_until` and, until that
instant plus the grant's `max_clock_skew_seconds` has passed:

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
the runtime rejects it at every boundary.

## Claim boundary

A permit narrows what a compromised worker or adapter can ask the venue to do and
makes the venue-side check independent of the calling process. It does not make a
venue that ignores permits safe: the live-money gates require a venue or gateway
that actually verifies permits, and the adapter remains part of the trusted
computing base until then (see `THREAT_MODEL.md`).
