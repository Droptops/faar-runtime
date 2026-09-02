# FAAR Red-Team Report

## Scope

This report records failures found while hardening the reference runtime under a deliberately hostile assumption: the model and ordinary coordination layer may be malicious, buggy, replaying stale state, racing workers, or experiencing ambiguous external I/O. It accumulates across releases; the v0.2 and v0.3.1 sections are kept as history.

Method: source review, state-machine analysis, concurrency fault reasoning, deterministic adversarial adapters, mutation cases, seeded replay/concurrency fuzzing and, since v0.4.0, a mutation sweep of security-relevant checks against the unit suite with end-to-end confirmation of every surviving mutant.

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
| RT-10 | One external effect ID could be attributed to multiple intents | High | Effect-ID uniqueness + STOP |
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

| ID | Finding | Severity in reference model | v0.3.1 response |
|---|---|---:|---|
| RT-36 | `QuorumSettlementVerifier` resolved a genuine source disagreement by iteration order | High | Multiple facts reaching quorum now return `CONTRADICTORY` |
| RT-37 | `allowed_assets` allowlist was skipped for a falsy-but-present asset value | Low | Asset extraction uses presence, not truthiness |
| RT-38 | `denied_targets` / `TARGET_REQUIRED` were skipped for a falsy-but-present target | Low | Target resolution coalesces on presence |
| RT-39 | Action-velocity reservation used a fixed tumbling bucket allowing 2x the limit across a boundary | Low / Medium | Sliding window over the trailing `action_window_seconds` |
| RT-40 | Evidence hash chain could not detect tail-truncation or whole-chain deletion | Medium | Signed per-intent head commitment |
| RT-41 | CI actions pinned to mutable tags; `cryptography` pinned to an over-tight range | Low | Actions pinned to commit SHAs; dependency range loosened |

## Findings fixed in v0.4.0

A third adversarial pass ran eight independent reviewers over the store, runtime, cryptographic boundary, gates/parsing, settlement/outcomes, documentation, test coverage and the go-live gates, then reproduced every code-level finding against the real modules before fixing it. A 51-mutant sweep of security-relevant checks found 17 mutants that passed the whole suite while permitting an unauthorized or duplicate effect end to end; each now has a killing test (`test/test_mutation_gaps.py`).

| ID | Finding | Severity in reference model | v0.4.0 response |
|---|---|---:|---|
| RT-42 | An authoritative `NONE` while the previous attempt was still in flight (timeout, exception) authorized a retry; the venue could later execute both permits | High | Permit-bounded ambiguity window: absence is not trusted and no retry is issued until the last permit has expired plus clock skew (`SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW`); bounded model demonstrates the duplicate without the rule |
| RT-43 | A non-authoritative observation after a CONFIRMED effect terminally STOPPED the intent (`SETTLEMENT_LOST_PREVIOUS_EFFECT`), stranding a real effect and its budget | Medium | Continuity and amount checks apply to authoritative records only; weak observations stay UNKNOWN |
| RT-44 | The deterministic-failure resubmission block was call-local; a later worker resubmitted | Low | Block derived from persisted reason codes, carried through every non-terminal transition |
| RT-45 | Settlement verification and retries ran inside the per-grant revocation fence on exception paths; a revoke queued behind a verifier and a retry executed first | Low | Only the adapter call is fenced; `adapter_deadline_seconds` bounds it |
| RT-46 | `attestation.expires_at + skew` extended signed authority; permits were not bounded by attestation expiry | Medium | Expiry exact; permit expiry is the minimum of intent, grant and both attestation expiries |
| RT-47 | Ed25519 signature strings had many accepted encodings (padding, junk suffix, alternate alphabet, trailing bits) | Low | One canonical encoding accepted |
| RT-48 | Permit signature did not cover `signer_id`/`algorithm` | Info | Envelope signed; multi-signer gateway with key lifecycle |
| RT-49 | `parse_grant` ignored unknown/misspelled keys: a typo'd optional limit became "not enforced" inside a valid fingerprint | Medium | Strict key allowlists for every document |
| RT-50 | Amount grammar: `1e-999999999` passed the gate and made the store allocate gigabytes; whitespace/Unicode/exponent strings were forwarded to adapters | High (availability) | One bounded ASCII decimal parser shared by every amount consumer |
| RT-51 | BUY/SELL/PLACE_ORDER accepted both `amount_usd` and `notional_usd` with different values; the ceiling applied to one, the adapter saw both | Medium | `AMOUNT_FIELDS_AMBIGUOUS` deny |
| RT-52 | Non-Mapping payload, `Attestation.kind` as a plain string, bytes effect ids, oversized ints, naive datetimes, 5 MB identifiers escaped `process()` as raw exceptions or were accepted | Medium | Construction-time validation; identifier bounds; `SETTLED_EFFECT_ID_INVALID` |
| RT-53 | Outcome verifier never bound the settlement record to the contract's intent; another intent's FINALIZED record yielded MET | Medium | `TASK_SETTLEMENT_INTENT_MISMATCH` |
| RT-54 | Quorum split honest sources on Decimal scale (`50` vs `50.00`) and one raising source wedged the quorum forever | Medium (availability) | Numeric vote; raising source counts as non-authoritative UNKNOWN |
| RT-55 | A v0.3.0 database could not be opened by v0.3.1 (index created before migration); concurrent workers raced the migration | High (availability) | Indexes after migration; transactional migration; busy retry |
| RT-56 | Daily turnover was a UTC calendar bucket: 2x the cap across midnight | Medium | Trailing 24 h window |
| RT-57 | The next legitimate append re-committed the evidence head over a truncated chain, laundering RT-40 tampering; verification of unknown intents returned true; reads raced appends | Medium | Append refuses on head mismatch; fail closed for unknown/deleted chains; single-transaction verification; chains start at registration |
| RT-58 | Global effect-id uniqueness across venues recorded a genuine second-venue effect as STOPPED | Medium | Uniqueness per (venue, effect_id) |
| RT-59 | Terminalize + release ran as two statements; a crash between them stranded HELD budget forever; `reserve_usage` coerced malformed amounts to a zero-cost reservation; the two risk ledgers disagreed on "stale" | Low | Atomic `transition(release_usage=True)`; orphan release on replay; fail-closed amounts; shared monotonic ceiling |
| RT-60 | `intent_guard` ignored `wait_seconds` in-process; fences were per store instance; lock registry grew unbounded | Low | Timed acquire; fences shared per database path; reference counting |
| RT-61 | Terminal STOPs for grant substitution, paused grants and recovered authorizations left no evidence; recovered authorizations lacked the `authorized` event | Low | Every terminal decision recorded |
| RT-62 | Backup restore resurrected revoked grants, consumed permits and spent risk states (gate 2) | High | External `AuthorityAnchor`; `REGRESSED` status; `revoke_after_restore` |
| RT-63 | No kill switch: an incident required revoking N grant versions one by one while workers kept minting permits (gate 9) | High | `halt(scope)` / `resume(scope)` with epoch fencing |
| RT-64 | No key rotation or revocation; the gateway trusted exactly one signer id (gate 1) | Medium | `KeyValidity`; multi-signer gateway |
| RT-65 | 17 security checks had no killing test: capability scope (venue/primitive/actor), every risk limit, authority primitive, pause/resume epoch fence, Ed25519 role scope, grant auto-provisioning, future attestations, permit expiry, risk monotonicity, PAY runtime path, settlement profile gate, outcome prerequisites | High (assurance) | `test_mutation_gaps.py`; red-team matrix now maps classes to tests and fails on unmapped ones |

Residual, by design: RT-42's window is only as accurate as the venue's permit expiry check; a venue that ignores permits is outside the model. RT-62's anchor detects nothing if restored together with the database. RT-45's deadline cannot cancel a Python call; the orphaned call is bounded by RT-42.

## Findings fixed in the v0.4.0 review pass

Before release, five independent reviewers (fail-closed regressions, new-code correctness, documentation versus code, test quality, upgrade compatibility) read the v0.4.0 change set; a skeptic re-ran every reproduction it could before a finding was accepted. Each code finding below has a regression test named in `evals/run_redteam.py`.

| ID | Finding | Severity in reference model | Response |
|---|---|---:|---|
| RT-66 | The per-venue effect index (RT-58) left every pre-0.4 row in venue namespace `''`; on an upgraded database a new intent at the same venue could be FINALIZED with a legacy effect id and commit its budget against an effect that already settled another intent | High | Migration backfills `venue` from the canonical payload inside the migration transaction and fails closed if any row cannot be namespaced |
| RT-67 | The ambiguity window (RT-42) was recorded only on the timeout/exception paths. A receipt for a merely accepted request let an authoritative NONE authorize a retry while permit #1 was live; a deterministic rejection released the budget while the venue could still execute the queued request, orphaning the effect | High | The store writes `ambiguity_until` in the same transaction as the permit record, so every adapter outcome is covered; it refuses a second live permit per intent (`PERMIT_PREVIOUS_ATTEMPT_LIVE`, budget held); a later permit supersedes the earlier one at consumption (`PERMIT_SUPERSEDED`) |
| RT-68 | `FileAuthorityAnchor` held only a per-instance thread lock and a fixed temp name: concurrent workers or the CLI lost high-water marks (a later restore then went undetected) and could corrupt the file; read failures escaped as raw exceptions into permit issuance and `process()` | High | Inter-process `flock` across every read-modify-write, unique temp names, typed `AnchorUnavailable` mapped to `ANCHOR_UNAVAILABLE` / `PERMIT_ANCHOR_UNAVAILABLE` |
| RT-69 | The anchor recorded issuance but not consumption: a snapshot taken between the two restored as ACTIVE and the consumed permit consumed again; the shipped test snapshotted before issuance and passed for an unrelated reason | Medium | The grant fence counter advances at consumption and is anchored; the test now snapshots between issuance and consumption and asserts `PERMIT_AUTHORITY_REGRESSED` |
| RT-70 | Any instance opened without an anchor (a worker missing the option, `halt` without `--anchor`) advanced authority unrecorded, so a later restore silently resurrected the permits a halt had killed | Medium | The first anchored open binds the database durably; unanchored instances report `ANCHOR_REQUIRED`, refuse issuance and consumption (`PERMIT_ANCHOR_REQUIRED`) and raise `AuthorityAnchorRequired` on lifecycle changes; the CLI exits 2 with the typed error |
| RT-71 | `QuorumSettlementVerifier` turned one uncontested vote short of quorum into an authoritative CONTRADICTORY, so a single transient source error terminally STOPPED an intent whose effect exists and held its budget forever | Medium | Short-of-quorum without a contest is a non-authoritative UNKNOWN (`quorum-not-reached`) the runtime retries; a contest or a binding mismatch stays CONTRADICTORY |
| RT-72 | On a 0.3.0 database (no signed heads) the keyed runtime committed `UNKNOWN -> RECONCILING`, then raised `EvidenceIntegrityError` out of `process()` on every call; keyed `verify-evidence` reported every legacy chain as tampered; zero-event chains had no remedy | Medium | Appendability is checked before any transition; refusal is the machine-readable `EVIDENCE_INTEGRITY_FAILURE`; `evidence_status` distinguishes `head_missing` from tampering; `rebuild-evidence-head --all [--adopt-empty]` is the documented upgrade step and still refuses chains that do not verify |
| RT-73 | An adapter returning a non-`ExecutionReceipt` value crashed `_submit` outside its exception handlers, leaving the intent SUBMITTED with a transported permit | Medium | Treated as `AmbiguousExecution` inside the window |
| RT-74 | A halt (or any non-ACTIVE status) while an intent carried the durable deterministic-failure block overwrote the block; after `resume` the adapter was called again | Low | The durable block outranks the status block through every non-terminal transition |
| RT-75 | Replaying a never-submitted intent that reconciliation had STOPPED on settlement evidence (`SETTLED_AMOUNT_EXCEEDS_AUTHORIZED` from a RESERVED intent) released the hold that reconciliation deliberately kept | Low | Settlement-derived stops are never treated as orphaned holds |
| RT-76 | `KeyValidity.not_after` was judged on the signer-controlled `issued_at` with no bound on artifact lifetime: a retired (not revoked) key could mint a back-dated ten-year attestation that verified forever | Low | Verifiers bound artifact lifetime (`ATTESTATION_TTL_EXCEEDED` above 24 h, `PERMIT_TTL_EXCEEDED` above 60 s); revocation documented as the hard control |
| RT-77 | After upgrade, legacy reservations (`velocity_ts` NULL) vanished from the sliding velocity window and legacy in-flight attempts (`ambiguity_until` NULL) were resubmitted immediately | Low | Migration backfills `velocity_ts` from `created_at` and a 60 s window for in-flight legacy rows; unreadable timestamps fail the open |
| RT-78 | The gateway never emitted `PERMIT_HALTED` / `PERMIT_AUTHORITY_REGRESSED` (documented codes); `ConstrainedPermitAuthority` accepted the symmetric `HMACPermitSignature` although the trust model said otherwise | Info | Status-specific codes at `verify`; symmetric signers refused without the test override |
| RT-79 | Test-quality defects: the restore test snapshotted before issuance; the canonical-encoding test exercised its check in ~25 % of runs; the signer-relabel test could not distinguish a payload binding from a different key; a deadline test synchronised on `sleep`; the suite leaked 157 temp files per run; a CLI test destroyed a caller's environment variable | Assurance | All rewritten (deterministic aliases, same key under two ids, events, per-test temp directories, `patch.dict`) |

| RT-80 | `FINALIZED` and the usage commit were two autocommit statements; a worker killed between them left budget HELD on a FINALIZED intent forever (found by the new crash-injection eval, which kills a worker before every store call) | Low | `transition(..., commit_usage=True)` finalizes and commits in one transaction; a replay repairs rows written by older versions; `make crash` runs 191 crash points in `make check` |

| RT-81 | The permit gateway had no identity: a compromised adapter for venue A could present A's permit and request to venue B's gateway (same signer, shared control store) and move the money at a venue the grant never allowed; the runtime then saw NONE and could retry on A | High | Gateways are bound to a venue (`ExecutionPermitVerifier(venue=...)` / `consume(venue=...)`); `PERMIT_VENUE_MISMATCH` before anything is consumed; reference venues pass their name |
| RT-82 | Authoritative NONE after the window was trusted even when the ledger showed the permit consumed (venue admitted the request, settlement lagged): budget released, intent terminal, effect landed later; a venue clock lagging beyond the grant skew could still consume a permit after the runtime had released | Medium | Before acting on absence the runtime voids unconsumed permits (`PERMIT_VOIDED`, clock-independent) and stops on a consumed one (`SETTLEMENT_NONE_AFTER_PERMIT_CONSUMED`); `TIMEOUT_BEFORE_EFFECT` no longer consumes; new `TIMEOUT_AFTER_ADMISSION` mode; the paper venue records admitted-then-rejected orders as `CANCELLED` |
| RT-83 | Settlement records and receipts bypassed the bounded parser: a 12-byte amount allocated half a gigabyte and wrote a 100 MB evidence row; evidence with out-of-bounds Decimals, lone surrogates or `bytes` hashes raised out of `process()` after RECONCILING was committed; a DAG-shaped payload expanded exponentially in `_deep_freeze` | Medium | `SettlementRecord`/`ExecutionReceipt` bound amounts to canonical form, require string ids/hashes and canonical evidence of at most 64 KiB; `_deep_freeze` has a total node budget; a record the chain cannot carry is `SETTLEMENT_RECORD_MALFORMED` |
| RT-84 | Quorum treated `CONFIRMED` versus `FINALIZED` for the same effect and amount (finality lag between sources) as a contest and terminally STOPPED the intent | Medium | Reached finality is not vetoed by a lagging member; otherwise the combined votes carry `CONFIRMED` and the runtime reconciles again |
| RT-85 | A quorum member returning garbage instead of raising (`None`, a dict, an unbounded amount) wedged an honest 2-of-3 quorum indefinitely | Medium | Everything derived from a member's answer runs inside the per-member guard |
| RT-86 | Adapter-controlled content crashed `_submit` after the permit was transported: a receipt whose `__repr__`/`__format__` raised, a `__class__` spoof, an exception whose `__str__` raised, a `BaseException` subclass | Medium | Exact receipt type check, transition before evidence, bounded exception-free rendering, `BaseException` recorded before interpreter signals propagate |
| RT-87 | The definition-of-done verifier could declare MET on the very record the runtime had STOPPED (effect id owned by another intent, amount above the envelope) | Low | `verify_attested_task_outcome(runtime_state=..., runtime_effect_id=...)` returns `TASK_INTENT_NOT_FINALIZED` / `TASK_EFFECT_ID_MISMATCH` |

Documentation corrections from the same pass: halt semantics for in-flight intents, the persisted deterministic-failure code, the residual-risk table (partial fills OPEN, orphan threads under R-09), adapter-contract references, HMAC statements, the lifecycle diagram (`RECONCILING -> FAILED_SAFE`, retry edge), and the invariants header.

## Executable regression matrix

Current `make check` result for v0.4.0:

```text
289 unit/invariant tests -> PASS
117 targeted red-team attack classes, each mapped to named tests (157 tests) -> PASS, 0 unmapped
160 deterministic denial mutations -> 0 unauthorized economic effects, 0 adapter calls
100 retries of one logical intent -> 1 successful effect, 1 adapter call, 1 permit issued and consumed
ambiguous timeout-after-effect recovery -> 1 successful effect, 1 adapter call
96 seeded replay/concurrency state-machine scenarios (clock advancing) -> 0 duplicate-effect violations
96 seeded replay/concurrency state-machine scenarios -> 0 aggregate-budget violations
CLI end-to-end mock execution -> FINALIZED once; keyed evidence chain + head -> valid
bounded permit protocol model (2 permits, in-flight, expiry, halt) -> 1766 states, 4304 transitions, 0 invariant violations
same model without the permit-window rule -> 187 violations (first: issue, issue, submit0, consume0, submit1, consume1)
```

The deterministic denial count covers attacks stopped **before the trusted adapter is permitted to create an effect**. A malicious adapter remains part of the TCB until the venue verifies permits; post-effect amount checks can detect a bad effect report but cannot undo a venue action the adapter already performed.

## Residual risks / non-claims

### R-01 — Risk signer semantic correctness

FAAR enforces authenticated, fresh, single-consumption, monotonic risk versions. It cannot prove that the trusted risk service computed position, P&L, liquidity, or market state correctly.

### R-02 — Distributed revocation fence

The durable fence is the grant epoch re-checked at permit consumption in the shared store, plus the kill switch. Its strength equals the store's transactional guarantee and the venue's willingness to verify permits. Multi-node production needs a store with equivalent semantics and a permit-verifying venue or gateway.

### R-03 — Key custody

Signer and verifier roles are separated and keys can be rotated and revoked, but private keys are held by Python objects. Production needs KMS/HSM custody and process isolation for the authority, risk, task and permit signers.

### R-04 — Adapter is still in the trusted computing base

The minimized `ExecutionRequest` plus permit reduces confused-deputy surface and amount/effect checks detect several classes of misreporting. But code that controls a broad venue credential can still perform a broader action before FAAR observes the result. A live deployment needs venue-side permit verification or lower-level account/contract limits.

### R-05 — Adapter security profile is a declaration

`AdapterSecurityProfile` prevents accidental integration of an adapter that admits incompatible semantics. It does not prove idempotency or authoritative lookup.

### R-06 — Credential authority

If a trading key can withdraw, transfer, bridge, or administer the account outside the constrained executor, credential compromise bypasses FAAR.

### R-07 — Evidence host/key compromise

An attacker with runtime and evidence-key access can rewrite a consistent local evidence history. Whole-database rollback to an older valid snapshot is invisible to the chain. Production may require remote append-only logs, signed checkpoints, or transparency anchoring.

### R-08 — Venue semantics

Universal exactly-once effects are impossible to claim for external systems without stable logical identity and authoritative reconciliation. FAAR must refuse unattended execution where those semantics cannot be established.

### R-09 — Hung adapter calls

Bounded by `adapter_deadline_seconds` and the kill switch in-repo; the abandoned Python call cannot be cancelled and is bounded only by the permit window and the venue honouring expiry.

### R-10 — Intent namespace denial of service

Ids are principal-namespaced and length-bounded, but first-writer-wins: unauthenticated ingress that can choose ids can still squat predictable ids inside a principal. Production ingress must authenticate the principal and server-mint or cryptographically namespace ids.

### R-11 — Trusted clock / host compromise

Caller-provided time cannot roll the security clock backwards, but a compromised host clock/runtime can. The permit window assumes runtime and venue clocks agree within the grant's skew allowance.

### R-12 — Reference settlement verifier shares ground truth with the mock venue

The runtime enforces a distinct, trusted verifier per adapter, but `MockSettlementVerifier` reads the same in-memory ledger as `MockVenue`; independence in the reference is structural, not evidential. Live venues need an independently authenticated read path or a quorum.

### R-13 — Anchor placement

The authority anchor is only meaningful on storage that is not restored with the database. This is an operational property the library cannot enforce.

### R-14 — Partial fills and cancellation

The reference commits the authorized notional on any authoritative FINALIZED at or below it and has no cancel/late-fill linkage. Order venues need this modelled before live use.

## Claim boundary

The strongest supportable claim is narrow:

> Under the current deterministic mock/paper adapter model and the encoded fault classes, FAAR v0.4.0 preserves the tested authorization, bounded-capability, replay/recovery, permit-fencing, aggregate-usage, settlement-integrity, restore-safety and key-lifecycle invariants.

It is **not** a production-security claim, live-venue claim, custody claim, or proof that a compromised trusted adapter cannot move funds incorrectly.
