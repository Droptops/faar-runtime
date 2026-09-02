# FAAR v0.2 Red-Team Report

## Scope

Baseline target: the v0.1 reference runtime. This report records failures found while hardening it into v0.2 under a deliberately hostile assumption: the model and ordinary coordination layer may be malicious, buggy, replaying stale state, racing workers, or experiencing ambiguous external I/O.

Method: source review, state-machine analysis, concurrency fault reasoning, deterministic adversarial adapters, mutation cases, and seeded replay/concurrency fuzzing.

**This is self-red-team regression evidence, not an independent audit or formal proof.**

## Findings fixed in v0.2

| ID | Finding | Severity in reference model | v0.2 response |
|---|---|---:|---|
| RT-01 | Caller could fabricate authority/risk decision objects | High | Signed intent-bound attestations |
| RT-02 | FINALIZED/CONFIRMED could lack effect identity | High | Non-empty stable effect ID required |
| RT-03 | Effect ID could change/disappear across reconciliation | High | Effect continuity checks -> STOP |
| RT-04 | Weak `NONE` could be mistaken for proof of no effect | High | Authoritative absence required before retry |
| RT-05 | Retry could occur after original intent authority expired | High | TTL/grant/attestation/risk recheck before resubmit |
| RT-06 | Revocation race between status check and adapter call | High | Shared local execution/revocation fence |
| RT-07 | Concurrent different intents could oversubscribe turnover | High | Transactional usage reservation |
| RT-08 | Different intents could reuse one apparently-safe portfolio snapshot | High | Single-consumption monotonic risk-state claims |
| RT-09 | Retry limit could reset across invocations | Medium | Persisted submission count |
| RT-10 | One external effect ID could be attributed to multiple intents | High | Global effect-ID uniqueness + STOP |
| RT-11 | NaN/infinity/time anomalies could crash or bypass comparisons | Medium | Strict finite/time validation |
| RT-12 | Model could smuggle low-level execution authority | High | Forbidden raw/signing fields |
| RT-13 | Database hash chain alone did not authenticate rewritten events | Medium | Optional event HMAC |
| RT-14 | Economic finality could be conflated with task success | Medium / control failure | Signed definition-of-done contract + outcome verifier |
| RT-15 | Shallow-frozen intent allowed nested mutation after authorization | High | Deep immutable copy of canonical inputs |
| RT-16 | Canonicalizer could collapse ordered tuples by sorting | High for future ordered fields | Preserve list/tuple order; sort only sets |
| RT-17 | Parser type coercion could turn stringified values into permissive state | High on risk completeness | Strict JSON scalar typing + duplicate/non-finite rejection |
| RT-18 | Authority/risk could expire while waiting for submission fence | High | Reauthorization under trusted clock immediately before adapter call |
| RT-19 | Crash after usage reservation could strand HELD budget when pre-submit intent later denies | Medium / availability | Safe orphan release when PROPOSED terminalizes |
| RT-20 | Lower-privilege signer key could be reused across attestation roles | High | Exact per-key `AttestationKind` scopes |
| RT-21 | Caller could move the security clock backwards | High | Caller time ignored outside explicit test mode |
| RT-22 | Unknown execution fields could become future confused-deputy authority | High | Per-primitive payload allowlists |
| RT-23 | Target allowlist could be bypassed by omitting a target field | High | Target required whenever grant scopes targets; PAY/SWAP grants require target scope |
| RT-24 | Structurally incompatible adapter could enter retry path | High | Required exactly-once-compatible `AdapterSecurityProfile` |
| RT-25 | Adapter received full intent/model metadata | High | Sanitized `ExecutionRequest` boundary |
| RT-26 | Frozen grant `status` conflicted with mutable PAUSE/RESUME lifecycle | Medium / correctness | Provisioning-time status separated from runtime lifecycle state |
| RT-27 | Monetary grant could omit limits/assets and become effectively unbounded | Critical design flaw | Bounded-by-construction grant rules |
| RT-28 | Extreme Decimal exponents could cause pathological canonical serialization | Medium / availability | Precision/exponent bounds before formatting |
| RT-29 | Non-authoritative positive reconciliation could finalize an effect | High | Positive reconciliation must be authoritative |
| RT-30 | Effect identity could be correct while settled amount exceeded authorization | High | Settled-amount integrity checks; PAY exact, trading <= authorized notional |
| RT-31 | Outcome verifier could accept non-authoritative FINALIZED settlement | High / control failure | Definition-of-done requires authoritative final settlement |
| RT-32 | Signed task contract could be reused after its own expiry | Medium / stale control | Task-contract issued/expiry window enforced |
| RT-33 | Adapter evidence could shadow normalized settlement fields used by success criteria | High / confused evidence | Runtime-owned `effect_id`, `amount_usd`, and `status` overwrite same-named adapter evidence |
| RT-34 | Future-dated signed task contract could be evaluated early | Medium / stale/future control | Task-contract issuance window enforced |
| RT-35 | PAY effect could settle for a different amount while remaining under general trade cap | High | PAY requires exact settled amount equality |

## Findings fixed in v0.3.1

A second adversarial review pass (source review plus a fan-out of independent per-dimension reviewers, each finding adversarially re-verified) surfaced the following code-level gaps over v0.3.0. Each was reproduced against the real modules before fixing and now has regression coverage.

| ID | Finding | Severity in reference model | v0.3.1 response |
|---|---|---:|---|
| RT-36 | `QuorumSettlementVerifier` resolved a genuine source disagreement by iteration order: when two distinct authoritative facts each reached quorum (e.g. a 2-2 split at quorum=2) it returned the first, not a contradiction | High | Multiple facts reaching quorum now return `CONTRADICTORY` (fail closed) |
| RT-37 | `allowed_assets` allowlist was skipped for a falsy-but-present asset value (integer `0`, `false`) because asset extraction used truthiness, not presence | Low | Asset extraction uses presence (`not in (None, "")`), so falsy values are validated |
| RT-38 | `denied_targets` / `TARGET_REQUIRED` were skipped for a falsy-but-present target because target resolution used `a or b or c` | Low | Target resolution coalesces on presence (`is None`), not truthiness |
| RT-39 | Action-velocity reservation used a fixed tumbling bucket (`timestamp // window`), allowing up to 2x the limit to fire across a bucket boundary | Low / Medium | Sliding window over the trailing `action_window_seconds` |
| RT-40 | The evidence hash chain could not detect tail-truncation or whole-chain deletion (a deleted suffix leaves an internally consistent prefix), despite the store claiming to detect database-only rewriting | Medium | Signed per-intent head commitment (seq + head hash under the evidence MAC) detects truncation/deletion in keyed mode |
| RT-41 | CI actions pinned to mutable `@v4`/`@v5` tags; `cryptography` pinned to an over-tight `>=46,<47` that blocked installs and security updates | Low | Actions pinned to commit SHAs; dependency range loosened |

Residual, by design: RT-40's head commitment is only meaningful when an evidence key is configured — without a key a database-level attacker can rewrite the head row too, so the chain-only guarantees remain the ceiling (see R-07). RT-36 still accepts a quorum-reaching fact when the dissent is below quorum; that is the intended tolerance of a quorum configuration, not unanimity.

## Executable regression matrix

The findings table above records the v0.2 hardening work. The matrix below is the current `make check` result for v0.3.0:

```text
105 unit/invariant tests -> PASS
59 targeted red-team attack classes -> PASS
160 deterministic denial mutations -> 0 unauthorized economic effects
100 retries of one logical intent -> 1 successful effect
ambiguous timeout-after-effect recovery -> 1 successful effect
96 seeded replay/concurrency state-machine scenarios -> 0 duplicate-effect violations
96 seeded replay/concurrency state-machine scenarios -> 0 aggregate-budget violations
CLI end-to-end mock execution -> FINALIZED once
evidence chain verification -> valid
bounded permit protocol model -> 0 invariant violations; stale permit consumable after revoke = false
```

The deterministic denial count covers attacks stopped **before the trusted adapter is permitted to create an effect**. A malicious adapter remains part of the TCB; post-effect amount checks can detect a bad effect report but cannot magically undo a venue action the adapter already performed.

## Residual risks / non-claims

### R-01 — Risk signer semantic correctness

FAAR enforces authenticated, fresh, single-consumption risk versions. It cannot prove that the trusted risk service computed position, P&L, liquidity, or market state correctly.

### R-02 — Distributed revocation fence

The reference lock is process-local. Multi-node production requires a datastore/lease fencing token or lower-level credential/capability revocation with equivalent ordering.

### R-03 — HMAC is reference trust

The reference verifier holds symmetric key material and can therefore sign within permitted roles. Production should use asymmetric/KMS/HSM-backed verification with signer/verifier separation.

### R-04 — Adapter is still in the trusted computing base

The minimized `ExecutionRequest` reduces confused-deputy surface and amount/effect checks detect several classes of misreporting. But code that actually controls a broad venue credential can still perform a broader action before FAAR observes the result. A live deployment needs key isolation and, where possible, lower-level account/contract limits that make policy escape physically impossible.

### R-05 — Adapter security profile is a declaration

`AdapterSecurityProfile` prevents accidental integration of an adapter that admits incompatible semantics. It does not prove idempotency or authoritative lookup. Those properties require venue-specific tests and review.

### R-06 — Credential authority

If a trading key can withdraw, transfer, bridge, or administer the account outside the constrained executor, credential compromise bypasses FAAR.

### R-07 — Evidence host/key compromise

An attacker with runtime and event-MAC key access can rewrite a consistent local evidence history. Production may require remote append-only logs, signed checkpoints, or transparency anchoring.

### R-08 — Venue semantics

Universal exactly-once effects are impossible to claim for external systems without stable logical identity and authoritative reconciliation. FAAR must refuse unattended execution where those semantics cannot be established.

### R-09 — Hung adapter calls can delay local revocation

The reference implementation holds the grant fence across submission. A stuck venue call can delay revocation completion. Production needs bounded network deadlines plus an external revocation/fencing mechanism that does not depend on a Python call returning.

### R-10 — Intent namespace denial of service

If public unauthenticated ingress can choose `intent_id`, it can squat predictable IDs. Production ingress must authenticate the principal and server-mint or cryptographically namespace durable economic intent IDs.

### R-11 — Trusted clock / host compromise

Caller-provided time cannot roll the security clock backwards, but a compromised host clock/runtime can. Production time-sensitive deployments should use hardened time sources and operational monitoring appropriate to the threat model.

### R-12 — No independent settlement verifier yet

v0.2 uses the adapter's authoritative reconciliation interface. A stronger live architecture should separate **execution** from **independent effect verification** so the component holding execution credentials is not the sole source of truth about what it did.

## Claim boundary

The strongest supportable claim is narrow:

> Under the current deterministic mock/paper adapter model and the encoded fault classes, FAAR v0.3.0 preserves the tested authorization, bounded-capability, replay/recovery, aggregate-usage, and settlement-integrity invariants.

It is **not** a production-security claim, live-venue claim, custody claim, or proof that a compromised trusted adapter cannot move funds incorrectly.
