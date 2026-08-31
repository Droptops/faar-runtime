# Changelog

## 0.5.0 — unreleased

Out-of-process authority issuance and serialized verifier descriptors. Still **pre-alpha and not approved for live funds or production credentials**. Not a tag.

- execution plane is constructed from `VerifierDescriptor` public material, not arbitrary verifier objects
- `faar-authority` mints signed execution permits; the executor does not import signing providers
- `SigningKeyProvider` with in-memory Ed25519, file-backed Ed25519, and an unimplemented KMS/HSM interface
- `ExecutionGateway` is the choke point for fake-money treasury `PAY`
- `AuthorityLedger` contract (SQLite reference) for permits, receipts, lineage, and account bindings
- mock treasury adapter: exactly-once transfer to an allowlisted beneficiary within a daily budget
- distributed-boundary eval for descriptor forgery, executor isolation, replay, expiry, and crash-after-effect

The v0.4 in-process `FAARRuntime` path is unchanged. These are deterministic/subprocess results, not a production KMS or live-payments claim.

## 0.4.0 — 2026-08-31

Isolated authority-plane reference release over frozen v0.3.0. Still **pre-alpha and not approved for live funds or production credentials**.

- explicit `PermitSigner` / `PermitVerifier` and `AttestationSigner` / `AttestationVerifier` splits; Ed25519 signers are sign-only and Ed25519 verifiers are verify-only
- `Ed25519TrustStore` is a compatibility alias for `Ed25519AttestationSigner` (no `verify()`)
- hardened runtime/permit-authority construction accepts only FAAR-provided `Ed25519AttestationVerifier`
- `has_signing_api()` is documented as defense-in-depth, not proof that an object holds no private key
- Python API break documented separately from unchanged wire formats: `Ed25519PermitSignature` no longer accepts `public_key=` or `verify()`
- residual `can_sign` flags removed; structural capability detection supersedes them
- durable key lifecycle (`ACTIVE` / `RETIRED` / `REVOKED`) for permit, attestation, and ingress keys
- `key_id` is bound to a public-material hash; substitution/collision is rejected
- revoked keys cannot be resurrected; retirement still verifies in-flight artifacts
- principal-bound authenticated ingress with distinct ADMIN vs PRINCIPAL roles
- stronger grant/permit fencing across threads and processes; at most one outstanding permit per intent; consumed permits and revoked grants survive store restart
- deterministic failure-injection eval (`make faults`) added to `make check`
- bounded permit model expanded with key lifecycle states

These are deterministic regression, adversarial, fuzz, bounded-model, and in-process fault results. They are not formal verification, an independent security audit, or a production-safety claim.

## 0.3.0 — 2026-08-31

v0.3.0 reference runtime. Still **pre-alpha and not approved for live funds or production credentials**.

- package version `0.3.0`
- expanded deterministic unit/invariant suite to 105 tests
- expanded targeted red-team matrix to 59 attack classes
- bounded permit protocol model checker included in `make check`
- adversarial headline results unchanged in count: 160 denial cases with 0 unauthorized economic effects; 100 same-intent replay attempts with 1 valid economic effect
- seeded fuzz: 96 scenarios with 0 duplicate-effect and 0 aggregate-budget violations
- bounded permit model: max depth 10, 12 unique states, 15 transitions, 0 invariant violations; stale permit consumable after revoke = false

These are deterministic regression, adversarial, fuzz, and bounded-model results. They are not formal verification, an independent security audit, or a production-safety claim. Live-money adapters remain blocked on [`docs/V0_2_RELEASE_GATES.md`](docs/V0_2_RELEASE_GATES.md).

## 0.2.1 — 2026-08-30

Outcome-control red-team patch over v0.2.0:

- definition-of-done requires authoritative FINALIZED settlement;
- normalized settlement fields (`effect_id`, `amount_usd`, `status`) override same-named adapter evidence;
- signed task-contract issue/expiry windows are enforced;
- explicit regression coverage for future/stale task contracts and exact PAY settlement amounts;
- expanded reviewer-facing matrix to 41 named attack classes and 75 unit/invariant tests.

No live-money adapter or production-safety claim is introduced.

## 0.2.0 — 2026-08-30

Hardening release for the FAAR reference runtime. This release is still **pre-alpha and not approved for live funds**.

- signed, intent-bound authority and risk attestations with signer-role scoping;
- deep-immutable canonical intent inputs and strict JSON/parser boundaries;
- monotonic risk-state version consumption to prevent stale shared-risk races;
- atomic cross-intent turnover/velocity reservations and orphan-reservation recovery;
- submission-time freshness revalidation and local revocation fencing;
- authoritative reconciliation requirements, effect-ID uniqueness, and contradictory-settlement STOP semantics;
- settlement amount envelope checks and non-authoritative positive/negative reconciliation rejection;
- signed task contracts separating economic settlement from definition-of-done;
- explicit trust model, risk-engine contract, unplug test, adapter contract, and live-money release gates;
- 73 deterministic unit tests, 39 named red-team attack classes, 160 denial mutations with 0 unauthorized effects, 100 same-intent retries with 1 effect, and 96 seeded state-machine fuzz scenarios with 0 duplicate-effect or aggregate-budget violations.

These results are regression evidence only; they are not formal verification, an external security audit, or a live-venue security claim.

## 0.1.0 — 2026-08-30

Initial executable FAAR reference runtime:

- typed authority/capability/risk/intent models;
- canonical fingerprints;
- immutable grant registry;
- deterministic gates and reason codes;
- atomic grant usage reservations;
- SQLite intent state machine;
- reconciliation-first retry semantics;
- mock and paper-trading adapters;
- hash-chained evidence integrity log;
- CLI, CI, schemas, adversarial harness, and invariant tests.
