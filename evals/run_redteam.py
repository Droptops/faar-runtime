#!/usr/bin/env python3
"""Targeted red-team regression matrix for FAAR v0.4.

The unit suite contains the detailed assertions. This script produces a compact,
reviewer-facing readout of the attack classes the implementation currently blocks.

Every attack class is mapped to the exact unit tests that exercise it. The suite is
loaded in-process; a class whose tests are missing is reported as UNMAPPED and
fails the gate, so the headline count can never drift away from real coverage.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_DIR = ROOT / "test"

ATTACK_CLASSES: dict[str, tuple[str, ...]] = {
    "forged authority attestation": ("test_runtime.FAARRuntimeTests.test_forged_authority_attestation_stops",),
    "risk attestation replay across intents": ("test_runtime.FAARRuntimeTests.test_risk_attestation_bound_to_intent",),
    "expired attestation": (
        "test_runtime.FAARRuntimeTests.test_expired_attestation_stops",
        "test_boundary_hardening.AttestationLifetimeTests.test_attestation_expiry_is_exact_not_extended_by_skew",
    ),
    "raw transaction/calldata injection": ("test_runtime.FAARRuntimeTests.test_raw_calldata_from_agent_is_denied",),
    "NaN/non-finite numeric payload": ("test_runtime.FAARRuntimeTests.test_nonfinite_amount_is_denied_not_crash",),
    "stale and contradictory risk evidence": (
        "test_runtime.FAARRuntimeTests.test_stale_market_data_defers",
        "test_gates.GateTests.test_risk_source_disagreement_fails_closed",
    ),
    "duplicate intent with changed payload": ("test_runtime.FAARRuntimeTests.test_same_intent_id_different_payload_is_rejected",),
    "same risk-state version consumed by two intents": ("test_runtime.FAARRuntimeTests.test_same_risk_state_version_cannot_authorize_two_distinct_intents",),
    "concurrent turnover oversubscription": (
        "test_runtime.FAARRuntimeTests.test_concurrent_distinct_intents_cannot_oversubscribe_daily_turnover",
        "test_multiprocess.MultiProcessStoreTests.test_distinct_processes_cannot_oversubscribe_daily_budget",
    ),
    "timeout after economic effect": ("test_runtime.FAARRuntimeTests.test_timeout_after_effect_reconciles_without_second_effect",),
    "non-authoritative NONE reconciliation": ("test_runtime.FAARRuntimeTests.test_non_authoritative_none_never_resubmits",),
    "retry after intent expiry": ("test_runtime.FAARRuntimeTests.test_expired_intent_never_resubmits_after_authoritative_none",),
    "risk change before resubmission": ("test_runtime.FAARRuntimeTests.test_changed_risk_is_rechecked_before_resubmit",),
    "settled result without effect identity": ("test_runtime.FAARRuntimeTests.test_finalized_without_effect_id_stops",),
    "effect identity changes during reconciliation": ("test_runtime.FAARRuntimeTests.test_effect_id_change_after_confirmation_stops",),
    "same effect identity claimed by two intents": ("test_runtime.FAARRuntimeTests.test_duplicate_effect_id_across_intents_stops_second",),
    "revocation race at submission boundary": (
        "test_runtime.FAARRuntimeTests.test_revocation_completion_is_execution_fence",
        "test_multiprocess.MultiProcessStoreTests.test_revocation_in_other_process_during_submission_prevents_effect",
    ),
    "grant-envelope substitution": ("test_runtime.FAARRuntimeTests.test_substituted_grant_envelope_is_stopped",),
    "database evidence-MAC tampering": (
        "test_runtime.FAARRuntimeTests.test_evidence_chain_and_mac_verify",
        "test_store.EvidenceHeadCommitmentTests.test_keyed_head_commitment_detects_tail_truncation",
    ),
    "agent rewrite of signed definition-of-done criteria": ("test_outcomes.OutcomeTests.test_agent_cannot_rewrite_attested_done_criteria",),
    "mutable nested intent payload TOCTOU": ("test_canonical.CanonicalizationTests.test_intent_payload_is_deep_frozen_against_source_mutation",),
    "ordered-tuple canonical hash collision": ("test_canonical.CanonicalizationTests.test_tuple_order_is_preserved_in_hash",),
    "parser type-coercion / stringified boolean bypass": (
        "test_parsing.ParsingTests.test_string_false_cannot_bypass_data_complete",
        "test_parsing.ParsingTests.test_string_integer_is_rejected_at_typed_boundary",
    ),
    "authorization/risk expires while waiting on submission fence": ("test_runtime.FAARRuntimeTests.test_authorization_is_rechecked_at_submission_time",),
    "crash after budget reservation before state transition": ("test_runtime.FAARRuntimeTests.test_orphan_held_usage_is_released_when_proposed_intent_later_denies",),
    "attestation signing-key role confusion": (
        "test_attestation.AttestationScopeTests.test_valid_mac_from_wrong_role_key_is_rejected",
        "test_mutation_gaps.AttestationScopeTests.test_ed25519_valid_signature_from_wrong_role_key_is_rejected",
    ),
    "caller-controlled security-clock rollback": ("test_runtime.FAARRuntimeTests.test_caller_cannot_move_security_clock_backwards",),
    "unknown execution-field confused-deputy smuggling": ("test_runtime.FAARRuntimeTests.test_unknown_execution_field_is_denied",),
    "target allowlist bypass by omission": ("test_runtime.FAARRuntimeTests.test_target_allowlist_cannot_be_bypassed_by_omission",),
    "adapter missing exactly-once semantic contract": ("test_runtime.FAARRuntimeTests.test_adapter_without_exactly_once_contract_is_rejected",),
    "model metadata leakage into execution adapter": ("test_runtime.FAARRuntimeTests.test_adapter_receives_sanitized_execution_request_not_model_metadata",),
    "provision-time PAUSED vs mutable runtime lifecycle mismatch": ("test_runtime.FAARRuntimeTests.test_provisioned_paused_grant_can_resume_without_mutating_envelope",),
    "unbounded monetary grant construction": (
        "test_gates.GateTests.test_money_moving_grant_cannot_be_unbounded",
        "test_gates.GateTests.test_grant_requires_explicit_scope_and_velocity",
    ),
    "extreme-decimal canonicalization resource exhaustion": (
        "test_canonical.CanonicalizationTests.test_extreme_decimal_exponent_is_rejected_before_serialization",
        "test_boundary_hardening.AmountGrammarTests.test_extreme_exponent_amount_is_denied_at_the_gate_not_reserved",
    ),
    "non-authoritative positive settlement claim": ("test_runtime.FAARRuntimeTests.test_non_authoritative_positive_reconciliation_cannot_finalize",),
    "settled amount exceeds authorized economic envelope": ("test_runtime.FAARRuntimeTests.test_settled_amount_cannot_exceed_authorized_intent",),
    "non-authoritative settlement used to declare task done": ("test_outcomes.OutcomeTests.test_outcome_requires_authoritative_final_settlement",),
    "expired signed task-contract reuse": ("test_outcomes.OutcomeTests.test_expired_task_contract_cannot_be_reused",),
    "adapter evidence shadowing normalized settlement fields": ("test_outcomes.OutcomeTests.test_standard_settlement_fields_are_definition_of_done_inputs",),
    "future-dated signed task-contract use": ("test_outcomes.OutcomeTests.test_future_dated_task_contract_cannot_be_used",),
    "PAY settlement amount under/over-match": (
        "test_runtime.FAARRuntimeTests.test_payment_settlement_amount_must_match_exactly",
        "test_mutation_gaps.PayPrimitiveTests.test_pay_settlement_amount_mismatch_stops_reconciliation",
    ),
    "execution permit request-hash broadening": ("test_permits.PermitBoundaryTests.test_transport_cannot_broaden_signed_request",),
    "stale permit after pause/revoke epoch change": (
        "test_permits.PermitBoundaryTests.test_revocation_invalidates_already_issued_permit",
        "test_permits.PermitBoundaryTests.test_pause_invalidates_already_issued_permit",
        "test_mutation_gaps.EpochFenceTests.test_permit_issued_before_pause_is_stale_after_resume",
    ),
    "single-use permit replay at capability gateway": ("test_permits.PermitBoundaryTests.test_permit_is_single_use_at_capability_gateway",),
    "symmetric/private permit key leakage into execution gateway": (
        "test_permits.PermitBoundaryTests.test_execution_gateway_rejects_symmetric_signing_material",
        "test_permits.PermitBoundaryTests.test_permit_verifier_rejects_private_key_material",
        "test_permits.PermitBoundaryTests.test_permit_authority_rejects_symmetric_signer",
    ),
    "fresh retry risk-state reuse by another intent": ("test_permits.PermitBoundaryTests.test_fresh_retry_risk_state_cannot_be_reused_by_different_intent",),
    "submitter receipt self-finalization": ("test_runtime.FAARRuntimeTests.test_submitter_receipt_cannot_override_independent_settlement",),
    "settlement request-binding mismatch": ("test_runtime.FAARRuntimeTests.test_settlement_for_different_request_hash_stops",),
    "unexpected permit signer failure before adapter": ("test_runtime.FAARRuntimeTests.test_unexpected_permit_issuance_exception_fails_before_adapter",),
    "submitter deterministic failure hiding observed effect": ("test_runtime.FAARRuntimeTests.test_submitter_failure_cannot_hide_independently_observed_effect",),
    "duplicate settlement verifier identity in quorum": ("test_settlement.SettlementQuorumTests.test_duplicate_source_identity_is_rejected",),
    "same verifier object counted twice in quorum": ("test_settlement.SettlementQuorumTests.test_same_verifier_object_cannot_count_twice",),
    "observed effect rebound to different execution request": ("test_settlement.SettlementQuorumTests.test_observed_effect_must_bind_exact_execution_request",),
    "durable cross-process same-intent lease contention": ("test_multiprocess.MultiProcessStoreTests.test_durable_intent_lease_blocks_second_process",),
    "untrusted evidence depth/width resource exhaustion": (
        "test_canonical.CanonicalizationTests.test_deeply_nested_untrusted_data_is_bounded",
        "test_canonical.CanonicalizationTests.test_oversized_untrusted_container_is_bounded",
    ),
    "signing-capable attestation trust entering runtime": ("test_runtime.FAARRuntimeTests.test_runtime_rejects_signing_capable_attestation_store",),
    "signing-capable attestation trust entering permit authority": ("test_permits.PermitBoundaryTests.test_permit_authority_rejects_signing_capable_upstream_trust",),
    "verify-only Ed25519 trust store cannot mint attestations": ("test_attestation.AttestationScopeTests.test_ed25519_public_verifier_validates_but_cannot_sign",),
    "settlement verifier and submitter object identity collapse": ("test_runtime.FAARRuntimeTests.test_settlement_verifier_cannot_be_submitter_object",),
    # --- added in 0.4.0 ---------------------------------------------------------
    "weak settlement observation terminally losing a confirmed effect": ("test_runtime_hardening.RuntimeHardeningTests.test_weak_none_after_confirmed_does_not_lose_the_effect",),
    "deterministic-failure resubmission block forgotten across workers": ("test_runtime_hardening.RuntimeHardeningTests.test_deterministic_failure_block_survives_across_calls",),
    "premature authoritative NONE while a permit is in flight": (
        "test_runtime_hardening.RuntimeHardeningTests.test_absence_is_not_authoritative_while_an_in_flight_permit_is_live",
        "test_runtime_hardening.RuntimeHardeningTests.test_late_effect_after_permit_expiry_is_refused_by_the_venue",
    ),
    "hung adapter or verifier holding the revocation fence": (
        "test_runtime_hardening.RuntimeHardeningTests.test_adapter_deadline_releases_the_fence_and_never_duplicates_a_late_effect",
        "test_runtime_hardening.RuntimeHardeningTests.test_revocation_completes_while_verifier_runs_after_ambiguous_submission",
    ),
    "evidence tail truncation laundered by the next append": ("test_store_hardening.EvidenceIntegrityTests.test_append_after_tail_truncation_fails_closed_instead_of_healing",),
    "calendar-day turnover double spend across midnight": ("test_store_hardening.TurnoverWindowTests.test_turnover_limit_is_trailing_window_not_calendar_day",),
    "zero-cost reservation via malformed amount": ("test_store_hardening.ReservationIntegrityTests.test_invalid_monetary_amount_cannot_reserve_zero",),
    "cross-venue effect identity collision stranding a real effect": ("test_store_hardening.EffectIdentityScopeTests.test_effect_identity_is_unique_per_venue",),
    "dual amount fields authorized on one and executed on the other": ("test_boundary_hardening.AmountGrammarTests.test_dual_amount_fields_are_ambiguous_and_denied",),
    "misspelled grant limit silently unenforced": ("test_boundary_hardening.ParsingBoundaryTests.test_misspelled_limit_or_top_level_key_is_rejected",),
    "non-canonical signature encodings": ("test_boundary_hardening.AttestationLifetimeTests.test_non_canonical_signature_encodings_are_rejected",),
    "permit relabelled to another trusted signer": ("test_boundary_hardening.PermitVerifierBoundaryTests.test_relabelled_signer_or_algorithm_breaks_the_signature",),
    "malformed permit crashing the gateway": ("test_boundary_hardening.PermitVerifierBoundaryTests.test_malformed_permit_is_a_deterministic_rejection_not_an_exception",),
    "settlement of another intent satisfying the task contract": ("test_boundary_hardening.OutcomeBindingTests.test_settlement_of_another_intent_cannot_satisfy_the_contract",),
    "restored backup resurrecting a revoked grant": ("test_controls.AuthorityAnchorTests.test_restored_snapshot_cannot_resurrect_a_revoked_grant",),
    "restored backup replaying a consumed permit": (
        "test_controls.AuthorityAnchorTests.test_restored_snapshot_cannot_replay_a_consumed_permit",
        "test_controls.AuthorityAnchorTests.test_restored_snapshot_from_before_issuance_is_regressed_too",
    ),
    "outstanding permits surviving an emergency halt": ("test_controls.KillSwitchTests.test_global_halt_stops_new_intents_and_kills_outstanding_permits",),
    "revoked attestation key still trusted": ("test_key_lifecycle.AttestationKeyLifecycleTests.test_revoked_key_is_rejected_even_with_a_valid_signature",),
    "retired permit signer still trusted at the gateway": ("test_key_lifecycle.PermitSignerRotationTests.test_gateway_trusts_both_signers_during_overlap_then_revokes_the_old_one",),
    "venue, primitive, or actor outside the grant scope": (
        "test_mutation_gaps.CapabilityScopeTests.test_venue_outside_grant_is_denied",
        "test_mutation_gaps.CapabilityScopeTests.test_primitive_outside_grant_is_denied",
        "test_mutation_gaps.CapabilityScopeTests.test_actor_grant_and_principal_binding_are_enforced",
    ),
    "risk limit breach reaching the adapter": ("test_mutation_gaps.RiskLimitTests.test_each_risk_limit_and_data_gap_never_reaches_the_adapter",),
    "EXECUTE posture with a non-execution primitive": ("test_mutation_gaps.AuthorityGateTests.test_execute_posture_with_non_execution_primitive_is_denied",),
    "runtime auto-provisioning an unknown grant": ("test_mutation_gaps.GrantProvisioningTests.test_unprovisioned_grant_is_stopped_and_never_auto_provisioned",),
    "future-dated attestation accepted": ("test_mutation_gaps.AttestationScopeTests.test_future_dated_attestation_stops",),
    "expired or future permit consumed at the gateway": ("test_mutation_gaps.EpochFenceTests.test_expired_and_future_permits_are_rejected_at_the_gateway",),
    "older risk state re-authorizing after a newer one": ("test_mutation_gaps.RiskStateMonotonicityTests.test_older_risk_state_version_cannot_authorize_after_newer_one",),
    "PAY to an unapproved recipient": ("test_mutation_gaps.PayPrimitiveTests.test_pay_to_unapproved_recipient_is_denied",),
    # --- added in the 0.4.0 review pass ------------------------------------------
    "receipt or deterministic rejection closing the permit window early": (
        "test_runtime_hardening.RuntimeHardeningTests.test_receipt_without_effect_does_not_close_the_permit_window",
        "test_runtime_hardening.RuntimeHardeningTests.test_deterministic_failure_keeps_budget_until_the_permit_window_closes",
        "test_paper.PaperVenueTests.test_insufficient_balance_fails_safe_and_releases_usage",
    ),
    "second live permit minted for one intent": (
        "test_permits.PermitBoundaryTests.test_one_live_permit_per_intent_is_enforced_by_the_store",
        "test_runtime_hardening.RuntimeHardeningTests.test_store_refuses_a_second_live_permit_and_the_runtime_keeps_the_budget",
    ),
    "adapter returning a non-receipt value crashing the state machine": ("test_runtime_hardening.RuntimeHardeningTests.test_non_receipt_adapter_return_is_ambiguous_not_a_crash",),
    "deterministic-failure block overwritten by a halt": ("test_runtime_hardening.RuntimeHardeningTests.test_deterministic_failure_block_survives_a_halt_and_resume",),
    "settlement-derived stop released as an orphaned hold on replay": ("test_runtime_hardening.RuntimeHardeningTests.test_replay_keeps_the_hold_of_a_never_submitted_intent_stopped_on_settlement_evidence",),
    "single transient settlement source error terminally stopping an intent": (
        "test_settlement.SettlementQuorumTests.test_single_transient_source_error_is_insufficient_evidence_not_contradiction",
        "test_settlement.SettlementQuorumTests.test_non_authoritative_source_cannot_form_quorum",
        "test_boundary_hardening.SettlementHardeningTests.test_one_raising_minority_source_does_not_wedge_the_quorum",
    ),
    "retired-but-not-revoked key with a back-dated long-lived artifact": (
        "test_key_lifecycle.AttestationKeyLifecycleTests.test_artifact_lifetime_bound_caps_a_retired_keys_exposure",
        "test_key_lifecycle.PermitSignerRotationTests.test_gateway_bounds_permit_lifetime",
    ),
    "concurrent anchor writers losing a high-water mark": ("test_controls.AuthorityAnchorTests.test_file_anchor_is_safe_across_processes",),
    "authority consumed through an unanchored or unreadable anchor": (
        "test_controls.AuthorityAnchorTests.test_store_bound_to_an_anchor_refuses_unanchored_authority_changes",
        "test_controls.AuthorityAnchorTests.test_unreadable_anchor_fails_closed",
        "test_cli.OperatorCliTests.test_unanchored_command_on_an_anchored_database_exits_with_a_typed_error",
    ),
    "legacy effect id claimable by a new intent after upgrade": ("test_store_hardening.SchemaMigrationTests.test_legacy_effect_ids_stay_bound_to_their_venue_after_upgrade",),
    "legacy reservations dropped from the velocity window after upgrade": ("test_store_hardening.SchemaMigrationTests.test_legacy_reservations_count_toward_velocity_after_upgrade",),
    "legacy in-flight attempt trusted as absent immediately after upgrade": ("test_store_hardening.SchemaMigrationTests.test_legacy_in_flight_intent_gets_a_conservative_ambiguity_window",),
    "unreadable legacy row silently exempted from the invariants": ("test_store_hardening.SchemaMigrationTests.test_unreadable_legacy_timestamp_fails_closed",),
    "keyed runtime advancing state on a chain it cannot extend": (
        "test_store_hardening.LegacyChainTests.test_runtime_does_not_advance_state_on_a_chain_it_cannot_extend",
        "test_store_hardening.LegacyChainTests.test_empty_legacy_chain_is_adopted_only_on_request_and_records_the_adoption",
        "test_store_hardening.LegacyChainTests.test_tampered_chain_is_not_adopted_by_the_bulk_rebuild",
        "test_cli.OperatorCliTests.test_rebuild_evidence_heads_for_a_legacy_database",
    ),
    # --- live-money pass: order semantics, exposure, crash safety ----------------------
    "partial fill remainder resubmitted as a second order": (
        "test_partial_fills.PartialFillTests.test_partial_fill_confirms_with_its_effect_and_never_resubmits",
        "test_partial_fills.PartialFillTests.test_mock_venue_partial_fill_completes_or_cancels_without_a_second_order",
    ),
    "cancellation contradicting or releasing a recorded fill": (
        "test_partial_fills.PartialFillTests.test_cancel_after_partial_fill_finalizes_the_filled_effect",
        "test_partial_fills.PartialFillTests.test_cancel_reporting_no_fill_after_a_recorded_fill_stops",
        "test_partial_fills.PartialFillTests.test_recorded_partial_fill_then_authoritative_none_stops",
    ),
    "unfilled cancellation resubmitted under the same intent": ("test_partial_fills.PartialFillTests.test_cancel_without_fill_fails_safe_releases_and_never_resubmits",),
    "partial fill beyond the authorized notional or on PAY": (
        "test_partial_fills.PartialFillTests.test_partial_fill_integrity_checks",
        "test_partial_fills.PartialFillTests.test_pay_cannot_partially_fill",
    ),
    "weak partial-fill or cancel observation acted on": ("test_partial_fills.PartialFillTests.test_weak_partial_or_cancel_observations_carry_no_weight",),
    "quorum split on the filled amount": ("test_partial_fills.PartialFillTests.test_quorum_agrees_on_partial_fills_and_contests_differing_fills",),
    "fleet exposure beyond the funded cap": (
        "test_exposure_cap.ExposureCapTests.test_global_cap_bounds_the_whole_fleet_across_grants_and_principals",
        "test_exposure_cap.ExposureCapTests.test_principal_cap_isolates_principals_and_can_be_cleared",
        "test_exposure_cap.ExposureCapTests.test_runtime_defers_an_intent_over_the_cap_before_any_permit",
    ),
    "exposure cap changed without the anchor": ("test_exposure_cap.ExposureCapTests.test_caps_are_authority_changes_on_an_anchored_database",),
    "unbounded abandoned adapter calls": ("test_orphan_cap.OrphanedAdapterCallCapTests.test_process_stops_submitting_while_too_many_abandoned_calls_are_running",),
    "crash between finalize and commit stranding budget": ("test_runtime_hardening.RuntimeHardeningTests.test_finalize_and_commit_are_one_transaction_and_replay_repairs_older_rows",),
}


def _collect_ids(suite: unittest.TestSuite) -> set[str]:
    ids: set[str] = set()
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            ids |= _collect_ids(item)
        else:
            ids.add(item.id())
    return ids


def main() -> None:
    sys.path.insert(0, str(TEST_DIR))
    loader = unittest.TestLoader()
    suite = loader.discover(str(TEST_DIR), pattern="test_*.py", top_level_dir=str(TEST_DIR))
    available = _collect_ids(suite)
    if loader.errors:
        print(json.dumps({"suite": "FAAR v0.4 targeted red-team matrix", "pass": False, "load_errors": loader.errors}, indent=2))
        raise SystemExit(1)

    referenced = {test_id for tests in ATTACK_CLASSES.values() for test_id in tests}
    unmapped = sorted(test_id for test_id in referenced if test_id not in available)

    stream = io.StringIO()
    result = unittest.TextTestRunner(stream=stream, verbosity=0).run(suite)
    failed = {test.id() for test, _ in result.failures} | {test.id() for test, _ in result.errors}
    failed_classes = sorted(name for name, tests in ATTACK_CLASSES.items() if any(t in failed for t in tests))

    report = {
        "suite": "FAAR v0.4 targeted red-team matrix",
        "attack_classes": len(ATTACK_CLASSES),
        "mapped_tests": len(referenced),
        "unit_tests_run": result.testsRun,
        "unit_failures": len(failed),
        "unmapped_tests": unmapped,
        "failed_attack_classes": failed_classes,
        "classes": list(ATTACK_CLASSES),
        "pass": result.wasSuccessful() and not unmapped,
        "claim_boundary": "Regression evidence only; not a formal proof, production audit, or live-venue security claim.",
    }
    print(json.dumps(report, indent=2))
    if not report["pass"]:
        sys.stderr.write(stream.getvalue()[-4000:])
        raise SystemExit(1)


if __name__ == "__main__":
    main()
