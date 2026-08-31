# FAAR v0.4 Isolated Authority Plane

**v0.4 reference runtime. Not approved for live funds or production credentials.**

This note describes the isolated authority-plane work on top of frozen FAAR v0.3.0
(`3bb828fe6b599c31e6adf87b2643215d318d9403`). It is not a production-safety claim.

## Scope

v0.4 keeps the v0.3 mock/paper execution model and adds a stricter authority plane:

```text
LLM / Strategy
      │ proposed intent
      ▼
Authenticated Ingress     (principal-bound, server clock, admin ≠ execute)
      ▼
Deterministic Policy / Risk
      ▼
Permit Authority          (policy; cannot expand the request)
      ▼
Isolated Signer           (signs canonical ExecutionPermit only while key ACTIVE)
      ▼
Verify-only Execution Plane
      ▼
Deterministic Adapter     (ExecutionRequest + signed permit only)
      ▼
Independent Reconciliation
      ▼
Evidence / Settlement
```

Out of scope: live-money adapters, KMS/HSM, distributed production datastores,
formal verification, independent audit.

## What SQLite proves and does not prove

The reference store uses SQLite with `BEGIN IMMEDIATE`, unique constraints, and
per-grant execution guards. Tests include cross-process workers on one file.

This demonstrates linearizability **inside one reference database file**. It does
not prove a multi-region, multi-writer production datastore. Distributed fencing
remains a live-money release gate (`V0_2_RELEASE_GATES.md`).

## Key lifecycle

`faar.keys.KeyLifecycle` is verify-side state with no `sign` API:

| Status | Mint | Verify previously issued artifacts |
|---|---|---|
| ACTIVE | yes | yes |
| RETIRED | no | yes, if `issued_at <= retired_at` |
| REVOKED | no | no |

Revoked keys cannot be resurrected. Rotation registers a new `key_id`.

Residual risk: a stolen private key of a **retired** (not revoked) signer can
still backdate `issued_at`. Destroy retired private material operationally, or
revoke instead of retire. `key_id` is bound to a public-material hash so a
different key cannot occupy the same identifier.

## Authenticated ingress

`faar.ingress.AuthenticatedIngress` is a reference control plane:

- `PRINCIPAL` tokens cannot substitute `principal_id`
- `intent_id` is namespaced or server-minted (`__mint__`)
- `ADMIN` is required for provision/pause/revoke
- timestamps used after bind come from the server clock

Bypassing ingress by talking to `SQLiteIntentStore` / `FAARRuntime` directly is
still a trusted-operator path.

## Failure injection

`make faults` runs an in-process mock-venue catalog covering timeout before/after
venue acceptance, process-crash restart of consumed permits, network ambiguity,
stale verifier after key revocation, grant already revoked, partial fill /
repeat submit, partial-fill vs cancel lookup race, inconsistent settlement
providers, datastore interruption, and duplicate-worker permit consume. It is
not an OS crash or live-network test.

## Claim boundary

Deterministic regression, adversarial, fuzz, bounded-model, and fault-catalog
results only. Not formally verified, not independently audited, not
production-safe, not approved for live funds.
