# FAAR Invariants

These are design targets for the reference runtime. A passing test is evidence for the tested implementation/model, not universal proof over every venue or deployment architecture.

## I-1 — Stable logical identity

A retry, restart, duplicate queue message, or transport error must reuse the same canonical `intent_id` for the same logical economic action.

## I-2 — Immutable intent semantics

Once an `intent_id` is stored, materially different canonical contents under that ID are rejected.

## I-3 — At-most-one successful effect per intent

For a logical intent `I`:

```text
successfulEconomicEffects(I) <= 1
```

within the semantics provided by the selected adapter/idempotency mechanism.

## I-4 — Denial cannot reach execution

If authority, capability, or risk evaluation denies/stops/defer an intent, the adapter must not receive a submission for that decision path.

## I-5 — Grant contents cannot be substituted

A provisioned `(grant_id, version)` is bound to the complete canonical grant hash. The execution coordinator cannot silently replace it with broader contents.

## I-6 — Authority does not self-escalate

The autonomous proposal source cannot provision, broaden, unpause, or un-revoke its own grant.

## I-7 — Revocation is irreversible for a grant version

`REVOKED` cannot transition back to ACTIVE. New authority requires a new version.

## I-8 — Ambiguity is not failure

Timeouts, RPC exceptions, and missing non-authoritative observations are treated as UNKNOWN until reconciled.

## I-9 — Authoritative absence before retry

Resubmission after ambiguity requires an adapter result equivalent to:

```text
state = NONE
and authoritative = true
```

A weak RPC/API “not found” does not satisfy this invariant.

## I-10 — Effect identity continuity

CONFIRMED/FINALIZED settlement requires an `effect_id`. Once observed, that identity may not silently disappear or change.

## I-11 — External effect identity is unique

The same effect ID cannot be claimed as the successful effect of two different FAAR intents.

## I-12 — Retry remains authorized

Before resubmission, FAAR rechecks:

- intent expiry;
- grant expiry/status;
- signed authority;
- signed risk state;
- capability/risk gates;
- durable retry budget.

A retry is a new execution attempt, not a free continuation of old authority.

## I-13 — Aggregate usage is atomic

Turnover/velocity constraints are reserved transactionally across distinct intents so concurrent workers cannot each spend the same apparent remaining capacity.

## I-14 — Risk state is single-consumption

A `(grant_id, version, risk_scope, state_version)` authorizes at most one new economic intent. Another intent requires a newer trusted risk state.

## I-15 — Upstream decisions are intent-bound

Authority and risk attestations must authenticate:

```text
attestation kind
key identity
subject hash
exact intent hash
issued_at
expires_at
```

Forged, stale, future, or cross-intent replayed attestations fail closed.

## I-16 — Raw execution material is not agent authority

The model cannot smuggle arbitrary low-level authority through typed fields such as calldata, signed transactions, signing payloads, key material, delegatecall, or unlimited approvals.

## I-17 — Revocation acts as a submission fence

Once revocation completes, no later adapter submission under that grant version may begin in the reference single-process runtime. Distributed production deployments must provide equivalent fencing.

## I-18 — Malformed numeric/time data fails closed

NaN, infinity, invalid negative ages/limits, naive timestamps, or impossible TTLs cannot be interpreted as a permissive value.

## I-19 — Evidence is append-linked

Intent evidence events are hash-linked. The reference store can additionally MAC events to detect database-only rewriting where the MAC key is not compromised.

## I-20 — Settlement is not definition of done

```text
FINALIZED(effect) != objective_met
```

Task completion is evaluated against criteria fixed before execution and, when used as a security/control input, authenticated independently of the agent.

## I-21 — Availability loses to authority preservation

When FAAR cannot prove safe authorization/recovery, it may stop or defer even if that loses an opportunity. Unknown state must not be optimized into execution merely for liveness.


## I-22 — Financial grants are bounded by construction

For any grant that permits `PAY`, `SWAP`, `BUY`, `SELL`, or `PLACE_ORDER`, missing bounds are not interpreted as infinity. The grant requires an explicit asset scope, positive per-action cap, positive daily aggregate cap, and action-velocity bound. `PAY` and `SWAP` additionally require explicit target allowlists.

## I-23 — Positive settlement must be authoritative

A reconciliation observation of `CONFIRMED` or `FINALIZED` cannot advance the state machine unless the adapter marks that lookup authoritative for the stable intent identity. Non-authoritative positive observations remain UNKNOWN.

## I-24 — Settled economic amount cannot exceed authorization

For money-moving primitives, positive settlement must include a finite positive `amount_usd`. `PAY` must match the authorized amount exactly; trading/swap/order effects may not exceed the authorized amount. A mismatch stops reconciliation and keeps ambiguous usage held.

## I-25 — Executor input is capability-minimized

Execution adapters receive a sanitized `ExecutionRequest` containing only `intent_id`, economic primitive, venue, and the post-gate payload. Model metadata, grant documents, authority/risk objects, and raw signing material are structurally excluded from the adapter interface.

## I-26 — Verification keys have an irreversible lifecycle

Permit and attestation verification keys are named by explicit `key_id` and stored as `ACTIVE`, `RETIRED`, or `REVOKED`.

- `ACTIVE` keys may mint and verify.
- `RETIRED` keys must not mint. Artifacts issued at or before retirement may still verify.
- `REVOKED` keys must not mint or verify, including artifacts issued before revocation.
- A revoked key cannot be re-registered as active. Rotation uses a new `key_id`.

Status is re-read from the durable store on every decision so an in-process cache cannot keep a revoked key alive. The stored `material_hash` binds `key_id` to one public key; a different key cannot occupy the same identifier.

## I-27 — Untrusted ingress is principal-bound

Callers that are not the FAAR runtime itself must authenticate. A `PRINCIPAL` token can submit only for its own `principal_id` and only with a principal-namespaced or server-minted `intent_id`. Grant provision/pause/revoke requires a distinct `ADMIN` token. Security time is the server clock.

This is a reference control plane. Direct store access remains inside the TCB.

## Remaining after v0.4

- HMAC remains a local development option for attestations and evidence MACs, not for isolated permit minting
- `has_signing_api()` rejects exposed minting APIs; it does not prove an arbitrary object holds no private key
- SQLite is a reference local fence, not a distributed production datastore
- no independent production signer process / KMS / HSM
- no live-venue adapter
- no cryptographic audit
- no distributed production deployment
- retired-key acceptance uses signed `issued_at`; a backdated mint after retire is a residual if the signer is compromised after retirement
- authenticated ingress is a reference principal-binding layer, not an internet-facing production identity service

