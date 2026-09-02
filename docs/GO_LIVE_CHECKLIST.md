# Go-Live Checklist

Status of every live-money release gate in [`V0_2_RELEASE_GATES.md`](V0_2_RELEASE_GATES.md)
and every residual risk in [`RED_TEAM_REPORT.md`](RED_TEAM_REPORT.md), with the
evidence in this repository. A row is **DONE-IN-REPO** only when a named test or
eval enforces it; **DEPLOYMENT** rows cannot be closed by library code and are the
operator's responsibility; **OPEN** rows block live funds.

The repository's own claim stands: a green `make check` is necessary and not
sufficient. Live-money credentials and adapters remain prohibited until every
DEPLOYMENT and OPEN row is closed and the result has been independently reviewed
(gate 8).

## Release gates

| Gate | Requirement | Status | Evidence |
|---|---|---|---|
| 1.1 | asymmetric or KMS/HSM-backed signing | DONE-IN-REPO (Ed25519) / DEPLOYMENT (custody) | `faar/attestation.py`, `faar/permits.py`; `test_attestation`, `test_permits` |
| 1.2 | verifier cannot mint | DONE-IN-REPO | `has_signing_api` checks in `FAARRuntime`, `ConstrainedPermitAuthority`, `ExecutionPermitVerifier`; `test_runtime.test_runtime_rejects_signing_capable_attestation_store`, `test_permits.test_verifier_has_no_minting_api_and_cannot_issue` |
| 1.3 | key rotation / revocation | DONE-IN-REPO | `KeyValidity`; `test_key_lifecycle` |
| 1.4 | signer roles separated | DONE-IN-REPO | per-key `AttestationKind` scopes; `test_mutation_gaps.AttestationScopeTests` |
| 2.1 | serializable semantics across processes | DONE-IN-REPO (SQLite) / DEPLOYMENT (production DB) | `test_multiprocess`, `test_store_hardening.SchemaMigrationTests` |
| 2.2 | distributed grant revocation / submission fence | DONE-IN-REPO (epoch at permit consumption) | `test_multiprocess.test_revocation_in_other_process_during_submission_prevents_effect`, `test_mutation_gaps.EpochFenceTests` |
| 2.3 | unique intent / effect / risk-state constraints | DONE-IN-REPO | `test_store_hardening.EffectIdentityScopeTests`, `test_mutation_gaps.RiskStateMonotonicityTests` |
| 2.4 | backup/restore does not resurrect consumed authority | DONE-IN-REPO (with anchor; issuance and consumption both anchored; unanchored instances refused) / DEPLOYMENT (anchor placement) | `faar/anchor.py`; `test_controls.AuthorityAnchorTests`; `OPERATIONS.md` §5 |
| 3.1 | monotonic risk-state versions | DONE-IN-REPO | `test_mutation_gaps.RiskStateMonotonicityTests`, `test_permits` |
| 3.2 | authoritative portfolio / market semantics | DEPLOYMENT | `RISK_ENGINE_CONTRACT.md` (external risk signer) |
| 3.3 | no aggregate oversubscription under concurrency | DONE-IN-REPO | `test_runtime`, `test_multiprocess`, `evals/run_state_fuzz.py`, `test_store_hardening.TurnoverWindowTests` |
| 4.1 | bounded adapter deadlines | DONE-IN-REPO | `adapter_deadline_seconds`; `test_runtime_hardening` deadline tests |
| 4.2 | stable external intent identity | DEPLOYMENT (per venue; the contract is documented, no in-repo test can prove it for a real venue) | `ADAPTER_CONTRACT.md` A2; `test_runtime.test_adapter_without_exactly_once_contract_is_rejected` checks the declared profile only |
| 4.3 | authoritative reconciliation by identity | DONE-IN-REPO (contract) / DEPLOYMENT | `test_runtime` settlement tests, `test_settlement` |
| 4.4 | partial-fill / cancel semantics | DONE-IN-REPO (modelled: `PARTIALLY_FILLED`, `CANCELLED`) / DEPLOYMENT (venue guarantees cancel terminality) | `ADAPTER_CONTRACT.md` Part C; `test_partial_fills`; `evals/run_crash_injection.py` `partial_fill_then_cancel` |
| 4.5 | effect ID definition | DONE-IN-REPO (contract, per venue) | `INVARIANTS.md` I-10/I-11 |
| 4.6 | authoritative positive and negative reconciliation | DONE-IN-REPO | `test_runtime_hardening` weak-observation tests |
| 4.7 | independent settled amount / asset / target verification | DONE-IN-REPO (amount) / DEPLOYMENT (venue evidence) | I-24 tests, `test_mutation_gaps.PayPrimitiveTests` |
| 4.8 | retry behaviour and maximum ambiguity window | DONE-IN-REPO | permit-bounded ambiguity window recorded at permit issuance for every adapter outcome; one live permit per intent; `test_runtime_hardening`, `test_permits`, model check |
| 4.9 | finality definition | DEPLOYMENT (per venue) | `ADAPTER_CONTRACT.md` |
| 5.1 | model cannot access signing secrets | DONE-IN-REPO (structure) / DEPLOYMENT (process isolation) | `UNPLUG_TEST.md` |
| 5.2 | credential scope narrower than root authority | DEPLOYMENT | venue configuration |
| 5.3 | withdrawal authority disabled for trading credentials | DEPLOYMENT | venue configuration |
| 5.4 | adapter receives only sanitized requests | DONE-IN-REPO | `test_runtime.test_adapter_receives_sanitized_execution_request_not_model_metadata` |
| 5.5 | no alternate direct execution path | DEPLOYMENT | `UNPLUG_TEST.md` |
| 6.1 | timeout before/after venue acceptance | DONE-IN-REPO | `MockMode` tests, deadline tests |
| 6.2 | process / network partition | DONE-IN-REPO (deadline + window; worker killed before every store call) / DEPLOYMENT | `test_runtime_hardening`; `evals/run_crash_injection.py` |
| 6.3 | duplicate workers | DONE-IN-REPO | `test_runtime.test_concurrent_workers_create_at_most_one_effect`, `test_multiprocess` |
| 6.4 | datastore failover | OPEN (not testable against SQLite; `STORE_CONTRACT.md` lists every guarantee a replacement must reproduce and the tests that check it) | `STORE_CONTRACT.md`; `evals/run_crash_injection.py`; `test_multiprocess` |
| 6.5 | stale / malicious RPC or provider | DONE-IN-REPO (fail closed; a transient single-source error is retriable, a contest stops) | non-authoritative settlement tests, quorum tests |
| 6.6 | revocation during submission | DONE-IN-REPO | fence and cross-process tests |
| 6.7 | partial fill + cancellation race | DONE-IN-REPO (a cancel reporting no fill after a recorded fill STOPs; a fill after CANCELLED is a venue contract violation) / DEPLOYMENT | `test_partial_fills.test_cancel_reporting_no_fill_after_a_recorded_fill_stops`; `ADAPTER_CONTRACT.md` Part C |
| 6.8 | venue returns changing identifiers / states | DONE-IN-REPO | effect continuity tests |
| 7.1 | authenticated intent creation | DEPLOYMENT (ingress) | `THREAT_MODEL.md` intent-namespace section |
| 7.2 | separately authorized provisioning / pause / resume / revoke | DEPLOYMENT (ingress); in-repo the runtime cannot provision or change lifecycle | `test_mutation_gaps.GrantProvisioningTests` |
| 7.3 | production time not trusting caller timestamps | DONE-IN-REPO | `test_runtime.test_caller_cannot_move_security_clock_backwards` |
| 7.4 | principal-bound or server-minted ids | DONE-IN-REPO (principal namespace, first-writer) / DEPLOYMENT (server minting) | `test_mutation_gaps.ConstructionGateTests` |
| 7.5 | unauthenticated caller cannot squat another principal's id | DEPLOYMENT (ingress authentication) | R-10 |
| 7.6 | collision never creates a replacement intent | DONE-IN-REPO | `IntentConflict` tests |
| 8 | independent security review | OPEN | none |
| 9 | capped first exposure and kill switch | DONE-IN-REPO (halt; scope exposure caps enforced at reservation) / DEPLOYMENT (funded balance at the venue) | `test_controls.KillSwitchTests`; `test_exposure_cap`; `OPERATIONS.md` §1 |

## Residual risks

| Risk | Status | Note |
|---|---|---|
| R-01 risk signer semantics | DEPLOYMENT | external |
| R-02 distributed revocation fence | DONE-IN-REPO for a shared control store; DEPLOYMENT for venue-side verification | epoch at consumption |
| R-03 key custody | DEPLOYMENT | signer/verifier separation done; KMS/HSM custody is operational |
| R-04 adapter in TCB | DEPLOYMENT | permits narrow it and the gateway is bound to its venue (`PERMIT_VENUE_MISMATCH`); venue must verify them |
| R-05 profile is a declaration | DEPLOYMENT | per-venue failure injection |
| R-06 credential authority | DEPLOYMENT | |
| R-07 evidence host / key compromise | DEPLOYMENT | append refusal + head commitment in repo; remote anchoring operational |
| R-08 venue semantics | DEPLOYMENT | |
| R-09 hung adapter delays revocation; orphaned adapter threads | DONE-IN-REPO | deadline + kill switch + `max_orphaned_adapter_calls`; a cancelled Python call cannot be killed, the venue refuses its expired or superseded permit |
| R-10 intent namespace squatting | DEPLOYMENT | ingress authentication |
| R-11 trusted clock | DEPLOYMENT | |
| R-12 mock verifier shares ground truth with mock venue | DEPLOYMENT | independent read path or quorum per venue |
| R-13 anchor placement | DEPLOYMENT | anchor restored with the DB detects nothing |
| R-14 partial fills and cancellation | DONE-IN-REPO / DEPLOYMENT (venue cancel terminality) | gates 4.4 and 6.7; `ADAPTER_CONTRACT.md` Part C |

## Before the first funded deployment

1. Close every OPEN row (6.4 datastore failover, 8 independent review) or record why it does not apply to the chosen venue.
2. Close every DEPLOYMENT row with written evidence in the deployment repository.
3. Obtain the independent review (gate 8) covering core plus the specific adapter.
4. Cap the funded balance at the venue and with `set-exposure-cap`, configure the
   authority anchor outside the backup set, bind every gateway to its venue,
   rehearse `halt`/`resume`, a restore and a worker crash (`make crash`), and keep
   `make check` green in CI.
