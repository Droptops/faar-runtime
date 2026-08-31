# FAAR v0.5 Out-of-Process Authority

**v0.5 reference work. Not approved for live funds or production credentials.**
**Do not treat this as a v0.5.0 tag.**

v0.4 made Python objects encode trust roles (sign-only vs verify-only classes).
v0.5 makes **processes + serialized public material** encode trust roles.

## Acceptance criterion

The FAAR execution process can be started in an environment containing **zero
private signing material** and **zero signer implementation objects**, yet can
verify authority artifacts and safely execute an authorized, exactly-once mock
financial effect.

## Architecture

```text
agent / coordinator
        │ canonical intent
        ▼
faar-authority          (private keys; policy; permit mint)
        │ VerifierDescriptor[]  (public only)
        │ SignedExecutionPermit
        ▼
Verify-only executor    (no signer classes instantiated; no private keys)
        │
        ▼
ExecutionGateway
  ├─ idempotency fence
  ├─ permit verify + consume
  ├─ budget check
  ├─ venue/account binding
  ├─ beneficiary/amount/expiry preconditions
  ├─ execute
  └─ hash-linked effect receipt
        │
        ▼
Mock treasury (fake money)
```

## Serialized verifier descriptors

Runtime injection of arbitrary verifier objects is not the v0.5 execution API.
The executor is constructed from:

```text
VerifierDescriptor
  scheme:     "ed25519"
  key_id:     "..."
  public_key: urlsafe-base64 raw 32-byte Ed25519 public key
  purpose:    "permit" | "attestation"
  status:     ACTIVE | RETIRED | REVOKED
  material_hash: sha256(public_key_bytes)
```

FAAR constructs `Ed25519PermitVerifier` / `Ed25519AttestationVerifier`
internally. HMAC and private-key encodings are rejected. A `REVOKED`
descriptor cannot be loaded into the executor.

`has_signing_api()` remains defense-in-depth on the v0.4 in-process path. It is
not the v0.5 trust boundary.

## Authority service

`python -m faar.authority_service` is intentionally boring:

```text
canonical intent → policy/risk gates → constrained grant checks → signed permit
```

It holds `SigningKeyProvider` material. The executor never imports this module
and never receives private keys. Wire format is JSON-lines over a Unix socket.

## SigningKeyProvider

```text
sign(key_id, payload) -> bytes
public_descriptor(key_id) -> VerifierDescriptor
```

Backends in this tree:

- in-memory Ed25519 (tests)
- file-backed Ed25519 (local reference)
- KMS/HSM interface only — no AWS/GCP adapter ships

## Execution gateway

Every mock-treasury side effect goes through `ExecutionGateway`. Adapters still
receive only `ExecutionRequest` plus the already-signed permit.

Effect receipts are **ledger-committed and hash-linked**, not permit-minting
signatures. A production executor-attestation key would reintroduce private
material into the execution process and is out of scope for the v0.5
zero-signing-material criterion.

## Durable authority ledger

`AuthorityLedger` is the storage contract. The reference implementation is
SQLite with `BEGIN IMMEDIATE`. Semantics to preserve under Postgres:

- permit issuance (at most one outstanding permit per intent)
- permit consumption
- replay / idempotency fences
- authority lineage (grant + attestation hashes)
- effect receipts
- key lifecycle events
- principal ↔ account bindings

SQLite is not a multi-region production datastore.

## Mock treasury

Fake-money `PAY` only:

```text
transfer $X from bound account A
to allowlisted beneficiary B
within daily budget Y
before permit expiry T
exactly once per intent_id
```

Not a live payments adapter. Not a brokerage.

## Residuals

- The v0.4 `FAARRuntime` in-process path still exists and still holds a permit
  authority object. v0.5 is a parallel execution plane, not a rewrite of v0.4.
- `ExecutionPermitVerifier` still lives in `faar.permits` next to signer
  classes. The executor process must not instantiate signers; class objects may
  exist in memory if that module is imported for verify/consume.
- Shared SQLite between authority and executor is a reference fence, not a
  distributed production ledger.
- Compromise of `faar-authority` still mints in-policy permits while keys are
  ACTIVE.
- Retired-key backdating remains if a retired private key is stolen.

## Claim boundary

Deterministic tests and an in-process/subprocess eval only. Not formally
verified, not independently audited, not production-safe, not approved for
live funds.
