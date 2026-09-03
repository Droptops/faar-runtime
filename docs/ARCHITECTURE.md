# FAAR Architecture

## Security objective

FAAR narrows the path from an untrusted agent proposal to an external economic effect. The model is allowed to be wrong, manipulated, overconfident, or malicious; the security claim lives in deterministic code and separately trusted evidence domains.

```text
                     UNTRUSTED
              Strategy / LLM / tools
                       │ proposal
                       ▼
              Canonical economic Intent  (principal-namespaced, schema 0.3)
                       │ stable hash
       ┌───────────────┴────────────────┐
       │                                │
       ▼                                ▼
 Authority signer                  Risk signer
 AAR posture/primitive             portfolio state
       │ Ed25519 attestation            │ Ed25519 attestation
       └───────────────┬────────────────┘
                       ▼
                 FAAR Runtime  (verify-only trust)
       ┌───────────────┼──────────────────────────┐
       │               │                          │
 grant registry    deterministic gates   transactional store
 fingerprint       capability + risk     intent / usage / risk claim
 epoch, halt,             │              evidence chain + signed head
 authority anchor         │                          │
       └───────────────┬──┴──────────────────────────┘
                       ▼
             Constrained permit authority   (independent re-check, Ed25519 signer)
                       │ SignedExecutionPermit
                       ▼
             submission fence + deadline
                       │ ExecutionRequest + permit
                       ▼
               reviewed adapter ──► venue / gateway verifies & consumes the permit
                       │                              (epoch, halt, anchor, single use)
                       ▼
          independent settlement verifier   (distinct component; quorum optional)
                       │ authoritative record bound to the request hash
                       ▼
              economic settlement  (permit-bounded ambiguity window)
                       │
                       ▼
             signed task contract
                       │
                       ▼
          deterministic outcome check   (bound to this intent's settlement)
             MET / NOT_MET / UNKNOWN
```

## Why split the trust domains

A single LLM-generated object such as:

```json
{"authorized": true, "risk_ok": true, "amount": 1000}
```

is not a security boundary. If the coordinator or model can fabricate both authorization and risk evidence, deterministic downstream checks provide little protection.

FAAR therefore binds two upstream decisions to the exact canonical intent:

- **authority attestation**: posture and work primitive;
- **risk attestation**: portfolio/market state and risk-state version.

Reference attestations and execution permits are Ed25519 (the `cryptography` package is a required dependency). Signers hold private keys; the runtime and the execution gateway hold public keys only and refuse any object that exposes a signing API; the permit authority holds exactly one private key (the permit signer) plus verify-only upstream trust. Symmetric HMAC classes survive solely as test fixtures and are refused by the permit authority and the gateway. Keys carry optional lifecycle windows and revocation (`KeyValidity`), and verifiers bound every artifact's own lifetime.

## Intent lifecycle

The durable state machine distinguishes authorization, reservation, submission, ambiguity, reconciliation, and settlement:

```text
PROPOSED ─► AUTHORIZED ─► RESERVED ─► SUBMITTED ─► UNKNOWN ─► RECONCILING ─► CONFIRMED ─► FINALIZED
   │            │            │            │            ▲            │  │
   └─► DENIED / DEFERRED / STOPPED        └─► FAILED_SAFE          │  ├─► STOPPED
                                                       │            │  └─► FAILED_SAFE (authoritative absence, retry blocked)
                                                       └────────────┘  (retry: RECONCILING ─► SUBMITTED, new permit)
```

Important properties:

- `SUBMITTED`, the durable attempt counter, the permit and the `submission_started` event are persisted before the external adapter call;
- every terminal decision leaves an event in the evidence chain, and every chain starts atomically with registration;
- a process restart resumes the same intent unless the crashed worker still owns the durable lease (`INTENT_BUSY`, operator recovery in `OPERATIONS.md`);
- ambiguous execution never creates a new logical intent;
- every recorded permit sets the intent's `ambiguity_until` to its expiry in the same transaction, whatever the adapter reports afterwards; absence is not trusted and no retry is issued until that window has closed, and the store refuses a second live permit for one intent;
- a decision is never recorded without evidence: if the chain refuses an append (`EVIDENCE_INTEGRITY_FAILURE`) no state advances;
- resubmission requires authoritative proof of absence after the window, fresh authorization/risk, unexpired authority, ACTIVE grant status, remaining retry budget, and no durable resubmission block;
- settlement verification and retries run outside the per-grant revocation fence; only the adapter call is fenced, and it can be bounded by `adapter_deadline_seconds`.

## Grant lifecycle

The complete parsed grant document is fingerprinted:

```text
(grant_id, version) -> SHA256(canonical grant)
```

The parser rejects unknown keys, so a misspelled limit is an error rather than an unenforced limit with a valid fingerprint. Runtime status is separate:

```text
ACTIVE <-> PAUSED
ACTIVE/PAUSED -> REVOKED
REVOKED -X-> ACTIVE
```

Every lifecycle change advances the grant's `runtime_epoch`, which every permit carries and which permit consumption re-checks. Two more effective statuses are folded in by the store: `HALTED` (a global or per-principal emergency stop, which also advances epochs) and `REGRESSED` (the datastore's authority state is older than its external anchor; see `OPERATIONS.md` §5).

Money-moving grants are bounded by construction: explicit asset scope, positive per-action and daily-turnover caps, and an action-velocity limit are mandatory; PAY/SWAP also require target allowlists.

## Risk-state concurrency

Per-order checks are not enough. Two different intents can each look safe against the same portfolio snapshot and jointly exceed a limit.

Every trusted risk snapshot therefore carries `scope`, `state_version` and `observed_at`. FAAR atomically claims one state version for one new intent, and a retry that presents a fresher version claims that version too. A version older than any claimed version is refused in both ledgers. The risk engine is responsible for advancing versions only after incorporating prior reservations/effects; see `RISK_ENGINE_CONTRACT.md`.

Aggregate usage (turnover, velocity) is reserved atomically in the store over trailing windows, independently of the risk signer's own accounting.

## Execution permits

See [`EXECUTION_PERMITS.md`](EXECUTION_PERMITS.md). The permit authority independently re-verifies everything the runtime checked, claims the risk state, allocates a fence token and signs a short-lived permit. The venue (or a gateway) verifies the signature and every binding and consumes the permit once in the shared store; consumption checks the grant epoch, halt state and authority anchor in the same transaction, which is the cross-process revocation fence.

## Adapter boundary

The adapter is not a generic tool pass-through. FAAR converts the authorized `Intent` into a minimized `ExecutionRequest` and a permit; the adapter never receives model metadata, the capability grant, or the authority/risk decision objects. Agent-supplied calldata, raw transactions, signing payloads, key material, delegatecall, unlimited approvals, unknown execution fields, dual amount fields and non-canonical amount strings are rejected before this boundary.

Whatever the adapter returns is untrusted telemetry. Positive and negative settlement come only from the configured settlement verifier, which must be a distinct component with a trusted profile. The paper gateway (`faar/paper_gateway.py`) exercises distinct submit/query clients, credentials and routes, but both reach one in-memory venue process and book; it does not establish operational or ground-truth independence. Positive reconciliation must be authoritative and bound to the exact request hash; for money-moving effects FAAR also checks that a settled amount exists and does not exceed the authorized notional (`PAY` requires exact equality). A funded deployment still needs an independently authenticated source or a quorum with separate failure domains (R-12).

## Evidence

Each intent owns a hash-linked evidence chain. With an evidence key configured, every event carries a MAC and a signed head commitment binds the chain's length and tail; the store refuses to append to a chain whose head no longer matches, and verification reads chain and head in one transaction. Evidence records what the runtime observed and decided; it does not by itself prove what an external venue did.

## Emergency controls and restore safety

`halt(scope)`/`resume(scope)` stop a principal or everything without waiting on in-flight adapter calls. An `AuthorityAnchor` kept outside the database backup set records the highest epoch and fence token per grant version so a restored backup cannot resurrect revoked grants, consumed permits or spent risk states. Both are operator procedures in [`OPERATIONS.md`](OPERATIONS.md).

## Settlement vs outcome

Settlement answers:

> Did the economic effect occur?

Outcome verification answers:

> Did that effect satisfy the objective fixed before execution?

Those are intentionally separate. A finalized payment can still fail to purchase the desired service; a filled trade can still fail a strategy-level objective. The attested outcome check additionally binds the settlement record to this intent's execution request, so the settlement of another intent cannot satisfy the contract.
