"""Regression coverage for checks that a mutation sweep showed to be unguarded.

Every test here corresponds to a single-line mutation of a security-relevant check
that previously passed the whole suite while allowing an unauthorized or duplicate
economic effect end to end. Each test asserts the machine-readable reason and that
the adapter was never invoked (or invoked exactly once).
"""
from __future__ import annotations

import inspect
import unittest
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import faar.runtime as runtime_module
from faar.adapters import AmbiguousExecution, DeterministicFailure, MockVenue, REFERENCE_SAFE_PROFILE
from faar.attestation import Ed25519TrustStore
from faar.canonical import canonical_hash
from faar.models import (
    AttestationKind,
    AuthorityDecision,
    AuthorityPosture,
    AuthorityPrimitive,
    EconomicPrimitive,
    ExecutionReceipt,
    ExecutionRequest,
    IntentState,
    OutcomeCriterion,
    OutcomeVerdict,
    SettlementRecord,
    SettlementStatus,
    TaskContract,
    Verdict,
)
from faar.outcomes import verify_attested_task_outcome, verify_task_outcome
from faar.permits import PermitIssuanceError
from faar.runtime import FAARRuntime
from faar.settlement import MockSettlementVerifier, QuorumSettlementVerifier, REFERENCE_SETTLEMENT_PROFILE, SettlementSecurityProfile
from faar.store import IntentConflict, InvalidTransition, SQLiteIntentStore, UnknownGrant
from support import AUTH, NOW, PRINCIPAL, TRUST_KEY_KINDS, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, temp_path, trust, verification_trust


class _Base(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self), evidence_key=b"evidence-test-key-32-bytes-long!!!!")
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))
        self.runtime, self.venue, self.settlement, self.permit_authority, self.permit_verifier = build_mock_runtime(self.store, self.trust)

    def tearDown(self):
        self.store.close()

    def run_case(self, i, auth=AUTH, g=None, rs=None, *, runtime=None, now=NOW, attestations=None):
        g = g or grant()
        rs = rs or risk()
        aa, ra = attestations or attest_pair(self.trust, i, auth, rs, now)
        return (runtime or self.runtime).process(i, auth, g, rs, authority_attestation=aa, risk_attestation=ra, now=now)

    def usage_status(self, iid, grant_id="grant:test"):
        rows = [r for r in self.store.usage(grant_id, 1) if r["intent_id"] == iid]
        return rows[0]["status"] if rows else None


class CapabilityScopeTests(_Base):
    def test_venue_outside_grant_is_denied(self):
        runtime, venue, *_ = build_mock_runtime(self.store, self.trust, name="other-dex")
        i = intent(intent_id="intent_gap_000000000001", venue="other-dex")
        result = self.run_case(i, runtime=runtime)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("VENUE_NOT_ALLOWED", result.reason_codes)
        self.assertEqual(0, venue.execute_call_count(i.intent_id))

    def test_primitive_outside_grant_is_denied(self):
        i = intent(intent_id="intent_gap_000000000002", primitive=EconomicPrimitive.PAY,
                   payload={"asset": "USDC", "amount_usd": "50", "target": "router:approved"})
        result = self.run_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("PRIMITIVE_NOT_ALLOWED", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_actor_grant_and_principal_binding_are_enforced(self):
        cases = (
            (intent(intent_id="intent_gap_000000000003", actor_id="agent:someone-else"), "ACTOR_MISMATCH"),
            (intent(intent_id="intent_gap_000000000004", grant_id="grant:other"), "GRANT_ID_MISMATCH"),
        )
        for i, code in cases:
            result = self.run_case(i)
            self.assertEqual(IntentState.DENIED, result.state, code)
            self.assertIn(code, result.reason_codes)
            self.assertEqual(0, self.venue.execute_call_count(i.intent_id))
        other = intent(intent_id="intent_gap_000000000005", principal_id="principal:other")
        result = self.run_case(other)
        self.assertNotEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(0, self.venue.execute_call_count(other.intent_id, principal_id="principal:other"))


class RiskLimitTests(_Base):
    def test_each_risk_limit_and_data_gap_never_reaches_the_adapter(self):
        cases = [
            (dict(position_after_usd=Decimal("1000")), "MAX_POSITION_USD_EXCEEDED", IntentState.DENIED),
            (dict(requested_slippage_bps=500), "MAX_SLIPPAGE_BPS_EXCEEDED", IntentState.DENIED),
            (dict(price_impact_bps=500), "MAX_PRICE_IMPACT_BPS_EXCEEDED", IntentState.DENIED),
            (dict(daily_turnover_after_usd=Decimal("5000")), "MAX_DAILY_TURNOVER_USD_EXCEEDED", IntentState.DENIED),
            (dict(daily_loss_usd=Decimal("1000")), "MAX_DAILY_LOSS_USD_EXCEEDED", IntentState.DENIED),
            (dict(actions_in_window=10), "ACTION_VELOCITY_EXCEEDED", IntentState.DENIED),
            (dict(data_complete=False), "RISK_DATA_INCOMPLETE", IntentState.DEFERRED),
            (dict(source_count=0), "RISK_SOURCES_CONTRADICTORY", IntentState.DEFERRED),
            (dict(market_data_age_seconds=-1), "MARKET_DATA_AGE_NEGATIVE", IntentState.DEFERRED),
            (dict(position_after_usd=None), "POSITION_DATA_REQUIRED", IntentState.DEFERRED),
            (dict(requested_slippage_bps=None), "SLIPPAGE_DATA_REQUIRED", IntentState.DEFERRED),
            (dict(price_impact_bps=None), "PRICE_IMPACT_DATA_REQUIRED", IntentState.DEFERRED),
            (dict(daily_turnover_after_usd=None), "TURNOVER_DATA_REQUIRED", IntentState.DEFERRED),
            (dict(daily_loss_usd=None), "LOSS_DATA_REQUIRED", IntentState.DEFERRED),
            (dict(market_data_age_seconds=None), "MARKET_DATA_AGE_REQUIRED", IntentState.DEFERRED),
        ]
        for n, (changes, code, state) in enumerate(cases):
            i = intent(intent_id=f"intent_gap_0000000001{n:02d}")
            result = self.run_case(i, rs=risk(state_version=n + 2, **changes))
            self.assertEqual(state, result.state, code)
            self.assertIn(code, result.reason_codes)
            self.assertEqual(0, self.venue.execute_call_count(i.intent_id), code)

    def test_velocity_limit_defers_at_runtime(self):
        tight = grant(grant_id="grant:velocity", limits=replace(grant().limits, max_actions_per_window=1))
        self.store.provision_grant(tight, canonical_hash(tight))
        first = intent(intent_id="intent_gap_000000000120", grant_id="grant:velocity")
        second = intent(intent_id="intent_gap_000000000121", grant_id="grant:velocity")
        self.assertEqual(IntentState.FINALIZED, self.run_case(first, g=tight, rs=risk(state_version=1, actions_in_window=0)).state)
        result = self.run_case(second, g=tight, rs=risk(state_version=2, actions_in_window=0))
        self.assertEqual(IntentState.DEFERRED, result.state)
        self.assertIn("ATOMIC_ACTION_VELOCITY_EXCEEDED", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(second.intent_id))


class AuthorityGateTests(_Base):
    def test_execute_posture_with_non_execution_primitive_is_denied(self):
        auth = AuthorityDecision(AuthorityPosture.EXECUTE, AuthorityPrimitive.GIVE_RECOMMENDATION)
        i = intent(intent_id="intent_gap_000000000130")
        result = self.run_case(i, auth=auth)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("AUTHORITY_PRIMITIVE_NOT_EXECUTION", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_stop_and_defer_postures_are_terminal_before_execution(self):
        for n, (posture, state, code) in enumerate((
            (AuthorityPosture.STOP, IntentState.STOPPED, "AUTHORITY_STOP"),
            (AuthorityPosture.DEFER, IntentState.DEFERRED, "AUTHORITY_DEFER"),
        )):
            i = intent(intent_id=f"intent_gap_00000000013{n + 1}")
            result = self.run_case(i, auth=AuthorityDecision(posture, AuthorityPrimitive.EXECUTE_ACTION), rs=risk(state_version=n + 2))
            self.assertEqual(state, result.state)
            self.assertIn(code, result.reason_codes)
            self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_stop_dominates_defer_and_deny_across_layers(self):
        i = intent(intent_id="intent_gap_000000000140")
        result = self.run_case(i, auth=AuthorityDecision(AuthorityPosture.DEFER, AuthorityPrimitive.EXECUTE_ACTION), rs=risk(circuit_breaker_active=True))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("AUTHORITY_DEFER", result.reason_codes)
        self.assertIn("CIRCUIT_BREAKER_ACTIVE", result.reason_codes)
        j = intent(intent_id="intent_gap_000000000141", payload={**intent().payload, "amount_usd": "76"})
        result = self.run_case(j, rs=risk(state_version=2, market_data_age_seconds=11))
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("MAX_ORDER_USD_EXCEEDED", result.reason_codes)
        self.assertIn("MARKET_DATA_STALE", result.reason_codes)
        from faar.models import Decision
        rank = {Verdict.ALLOW: 0, Verdict.DEFER: 1, Verdict.DENY: 2, Verdict.STOP: 3}
        for a in Verdict:
            for b in Verdict:
                for c in Verdict:
                    decisions = (Decision(a, (), "authority"), Decision(b, (), "capability"), Decision(c, (), "risk"))
                    self.assertEqual(max((a, b, c), key=lambda v: rank[v]), FAARRuntime._dominant(decisions).verdict)


class GrantProvisioningTests(_Base):
    def test_unprovisioned_grant_is_stopped_and_never_auto_provisioned(self):
        store = SQLiteIntentStore(":memory:")
        runtime, venue, *_ = build_mock_runtime(store, self.trust)
        i = intent(intent_id="intent_gap_000000000150")
        aa, ra = attest_pair(self.trust, i, AUTH, risk(), NOW)
        result = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_NOT_PROVISIONED", result.reason_codes)
        self.assertEqual(0, venue.execute_call_count(i.intent_id))
        with self.assertRaises(UnknownGrant):
            store.verify_grant(grant(), canonical_hash(grant()))
        source = inspect.getsource(runtime_module)
        self.assertNotIn(".provision_grant(", source, "the runtime must never mint grants")
        self.assertNotIn(".set_grant_status(", source, "the runtime must never change grant lifecycle")

    def test_paused_grant_releases_an_orphaned_hold(self):
        i = intent(intent_id="intent_gap_000000000151")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "PAUSED")
        result = self.run_case(i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_RUNTIME_PAUSED", result.reason_codes)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))


class EpochFenceTests(_Base):
    def _issue(self, iid, state_version=50):
        i = intent(intent_id=iid)
        rs = risk(state_version=state_version)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        return i, request, self.permit_authority.issue(
            request, intent=i, authority=AUTH, grant=grant(), risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW,
        )

    def test_permit_issued_before_pause_is_stale_after_resume(self):
        i, request, permit = self._issue("intent_gap_000000000160")
        self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "PAUSED")
        self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "ACTIVE")
        self.assertEqual("ACTIVE", self.store.get_grant_status(PRINCIPAL, "grant:test", 1))
        self.assertEqual(3, self.store.get_grant_control(PRINCIPAL, "grant:test", 1)[1], "every lifecycle change bumps the epoch")
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_GRANT_EPOCH_STALE"):
            self.venue.execute(request, permit)
        self.assertEqual(0, self.venue.successful_effect_count(i.intent_id))

    def test_expired_and_future_permits_are_rejected_at_the_gateway(self):
        i, request, permit = self._issue("intent_gap_000000000161")
        self.assertLessEqual(permit.permit.expires_at - permit.permit.issued_at, timedelta(seconds=5))
        self.assertLessEqual(permit.permit.expires_at, i.expires_at)
        late = MockVenue(permit_verifier=self.permit_verifier, name="mock-dex", clock=lambda: NOW + timedelta(seconds=30))
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_EXPIRED"):
            late.execute(request, permit)
        early = MockVenue(permit_verifier=self.permit_verifier, name="mock-dex", clock=lambda: NOW - timedelta(seconds=30))
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_FROM_FUTURE"):
            early.execute(request, permit)
        self.assertEqual(0, late.successful_effect_count(i.intent_id) + early.successful_effect_count(i.intent_id))

    def test_permit_claim_rejects_older_risk_state_on_retry(self):
        i, request, _ = self._issue("intent_gap_000000000162", state_version=20)
        older = risk(state_version=19)
        aa, ra = attest_pair(self.trust, i, AUTH, older, NOW)
        with self.assertRaises(PermitIssuanceError) as ctx:
            self.permit_authority.issue(request, intent=i, authority=AUTH, grant=grant(), risk=older, authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertIn("PERMIT_RISK_STATE_VERSION_NOT_MONOTONIC", ctx.exception.reasons)


class RiskStateMonotonicityTests(_Base):
    def test_older_risk_state_version_cannot_authorize_after_newer_one(self):
        first = self.run_case(intent(intent_id="intent_gap_000000000170"), rs=risk(state_version=7))
        self.assertEqual(IntentState.FINALIZED, first.state)
        i2 = intent(intent_id="intent_gap_000000000171")
        second = self.run_case(i2, rs=risk(state_version=6))
        self.assertEqual(IntentState.DEFERRED, second.state)
        self.assertIn("RISK_STATE_VERSION_NOT_MONOTONIC", second.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i2.intent_id))


class AttestationScopeTests(_Base):
    def test_ed25519_valid_signature_from_wrong_role_key_is_rejected(self):
        i = intent()
        risk_private = self.trust._keys["risk-test"]
        rogue = Ed25519TrustStore({"risk-test": risk_private}, key_kinds={"risk-test": {AttestationKind.AUTHORITY, AttestationKind.RISK}})
        forged = rogue.sign("risk-test", AttestationKind.AUTHORITY, AUTH, i, issued_at=NOW, ttl_seconds=20)
        ok, reasons = verification_trust(self.trust).verify(forged, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=i, now=NOW)
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_KEY_KIND_NOT_ALLOWED", reasons)
        _, ra = attest_pair(self.trust, i, AUTH, risk(), NOW)
        result = self.run_case(i, attestations=(forged, ra))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_ed25519_kind_mismatch_is_rejected(self):
        i = intent()
        aa, ra = attest_pair(self.trust, i, AUTH, risk(), NOW)
        ok, reasons = verification_trust(self.trust).verify(ra, kind=AttestationKind.AUTHORITY, subject=risk(), intent=i, now=NOW)
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_KIND_MISMATCH", reasons)

    def test_future_dated_attestation_stops(self):
        i = intent(intent_id="intent_gap_000000000180")
        attestations = attest_pair(self.trust, i, AUTH, risk(), NOW + timedelta(minutes=10))
        result = self.run_case(i, attestations=attestations)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertTrue(any("ATTESTATION_FROM_FUTURE" in r for r in result.reason_codes))
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))


class _PayAdapter:
    name = "mock-dex"
    security_profile = REFERENCE_SAFE_PROFILE

    def __init__(self, settled_amount):
        self.settled_amount = settled_amount
        self.calls = 0

    def execute(self, request, permit):
        self.calls += 1
        return ExecutionReceipt("pay-effect", SettlementStatus.FINALIZED, {}, Decimal(self.settled_amount))

    def reconcile(self, request):
        return SettlementRecord(
            SettlementStatus.FINALIZED, effect_id="pay-effect", amount_usd=Decimal(self.settled_amount),
            evidence={"source": "independent"}, authoritative=True, verified_request_hash=canonical_hash(request),
        )


class _Verifier:
    name = "test-verifier"
    security_profile = REFERENCE_SETTLEMENT_PROFILE

    def __init__(self, adapter):
        self.adapter = adapter

    def verify(self, request):
        return self.adapter.reconcile(request)


class PayPrimitiveTests(_Base):
    PAY_GRANT = grant(
        grant_id="grant:pay", allowed_primitives=frozenset({EconomicPrimitive.PAY}), allowed_assets=frozenset({"USDC"}),
        allowed_targets=frozenset({"merchant:approved"}),
    )

    def setUp(self):
        super().setUp()
        self.store.provision_grant(self.PAY_GRANT, canonical_hash(self.PAY_GRANT))

    def pay(self, iid, target="merchant:approved", amount="50"):
        return intent(intent_id=iid, grant_id="grant:pay", primitive=EconomicPrimitive.PAY,
                      payload={"asset": "USDC", "amount_usd": amount, "target": target})

    def runtime_for(self, adapter):
        permit_authority, _ = permit_stack(self.store, self.trust)
        return FAARRuntime(self.store, {"mock-dex": adapter}, verification_trust(self.trust), permit_authority,
                           {"mock-dex": _Verifier(adapter)}, clock=lambda: NOW, allow_test_time_override=True)

    def test_pay_to_unapproved_recipient_is_denied(self):
        i = self.pay("intent_gap_000000000190", target="wallet:attacker")
        result = self.run_case(i, g=self.PAY_GRANT)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("TARGET_NOT_ALLOWED", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_pay_to_approved_recipient_finalizes_once(self):
        i = self.pay("intent_gap_000000000191")
        adapter = _PayAdapter("50")
        runtime = self.runtime_for(adapter)
        result = self.run_case(i, g=self.PAY_GRANT, runtime=runtime)
        self.assertEqual(IntentState.FINALIZED, result.state)
        again = self.run_case(i, g=self.PAY_GRANT, runtime=runtime)
        self.assertTrue(again.replayed)
        self.assertEqual(1, adapter.calls)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id, "grant:pay"))

    def test_pay_settlement_amount_mismatch_stops_reconciliation(self):
        for n, settled in enumerate(("49.99", "50.01")):
            i = self.pay(f"intent_gap_00000000019{n + 2}")
            runtime = self.runtime_for(_PayAdapter(settled))
            result = self.run_case(i, g=self.PAY_GRANT, rs=risk(state_version=n + 2), runtime=runtime)
            self.assertEqual(IntentState.STOPPED, result.state, settled)
            self.assertIn("PAYMENT_AMOUNT_MISMATCH", result.reason_codes)
            self.assertIsNone(self.store.get(i.intent_id).effect_id)
            self.assertEqual("HELD", self.usage_status(i.intent_id, "grant:pay"))


class RecoveryPathTests(_Base):
    def _authorized(self, iid):
        i = intent(intent_id=iid)
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        return i

    def test_interrupted_authorization_is_reevaluated_and_releases_usage_on_stop(self):
        i = self._authorized("intent_gap_000000000200")
        result = self.run_case(i, rs=risk(circuit_breaker_active=True))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("CIRCUIT_BREAKER_ACTIVE", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    def test_interrupted_authorization_resumes_to_single_effect(self):
        i = self._authorized("intent_gap_000000000201")
        result = self.run_case(i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(1, self.venue.execute_call_count(i.intent_id))
        self.assertEqual(1, self.store.get(i.intent_id).submission_count)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))

    def test_submit_time_reauthorization_failure_releases_usage(self):
        i = intent(intent_id="intent_gap_000000000202")
        # Attestations that expire before the (fence-time) clock: valid at the
        # decision instant, expired by the time of submission.
        aa, ra = attest_pair(self.trust, i, AUTH, risk(), NOW - timedelta(seconds=19))
        runtime, venue, *_ = build_mock_runtime(self.store, self.trust, runtime_clock=lambda: NOW + timedelta(seconds=5), allow_test_time_override=False)
        result = runtime.process(i, AUTH, grant(), risk(observed_at=NOW + timedelta(seconds=4)), authority_attestation=aa, risk_attestation=ra)
        self.assertNotEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(0, venue.execute_call_count(i.intent_id))
        self.assertIn(self.usage_status(i.intent_id), (None, "RELEASED"))

    def test_grant_validity_expiry_blocks_resubmit(self):
        expiring = grant(grant_id="grant:expiring", valid_until=NOW + timedelta(seconds=5))
        self.store.provision_grant(expiring, canonical_hash(expiring))
        i = intent(intent_id="intent_gap_000000000203", grant_id="grant:expiring", expires_at=NOW + timedelta(seconds=14))
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, expiring, risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        self.store.begin_submission(i.intent_id, [IntentState.RESERVED], max_attempts=2)
        later = NOW + timedelta(seconds=10)
        result = self.run_case(i, g=expiring, rs=risk(observed_at=later), now=later)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_EXPIRED_BEFORE_RESUBMIT", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))
        self.assertEqual("RELEASED", self.usage_status(i.intent_id, "grant:expiring"))

    def test_reconcile_without_fresh_attestations_cannot_resubmit(self):
        i = intent(intent_id="intent_gap_000000000204")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        self.store.begin_submission(i.intent_id, [IntentState.RESERVED], max_attempts=2)
        result = self.runtime.reconcile(i, grant=grant(), now=NOW)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("FRESH_AUTHORIZATION_REQUIRED_FOR_RESUBMIT", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    def test_retry_with_changed_metadata_is_a_conflict_not_a_second_intent(self):
        i = intent(intent_id="intent_gap_000000000205", metadata={"trace": "a"})
        self.assertEqual(IntentState.FINALIZED, self.run_case(i).state)
        with self.assertRaises(IntentConflict):
            self.run_case(replace(i, metadata={"trace": "b"}))
        self.assertEqual(1, self.venue.execute_call_count(i.intent_id))


class SettlementPathTests(_Base):
    def test_contradictory_quorum_stops_and_keeps_usage_held(self):
        permit_authority, permit_verifier = permit_stack(self.store, self.trust)
        venue = MockVenue(permit_verifier=permit_verifier, name="mock-dex", clock=lambda: NOW)

        class Disagreeing:
            name = "dissenter"
            security_profile = REFERENCE_SETTLEMENT_PROFILE

            def verify(self, request):
                return SettlementRecord(SettlementStatus.FINALIZED, "other-effect", Decimal("50"), authoritative=True, verified_request_hash=canonical_hash(request))

        quorum = QuorumSettlementVerifier([MockSettlementVerifier(venue, name="a"), Disagreeing()], quorum=2)
        runtime = FAARRuntime(self.store, {"mock-dex": venue}, verification_trust(self.trust), permit_authority, {"mock-dex": quorum}, clock=lambda: NOW, allow_test_time_override=True)
        i = intent(intent_id="intent_gap_000000000210")
        result = self.run_case(i, runtime=runtime)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("SETTLEMENT_CONTRADICTORY", result.reason_codes)
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        self.assertEqual(1, venue.execute_call_count(i.intent_id))

    def test_reconciliation_exception_leaves_intent_unknown_and_usage_held(self):
        class Boom:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE

            def execute(self, request, permit):
                return ExecutionReceipt("fx", SettlementStatus.FINALIZED, {}, Decimal("50"))

            def reconcile(self, request):
                raise TimeoutError("verifier down")

        permit_authority, _ = permit_stack(self.store, self.trust)
        runtime = FAARRuntime(self.store, {"mock-dex": Boom()}, verification_trust(self.trust), permit_authority, {"mock-dex": _Verifier(Boom())}, clock=lambda: NOW, allow_test_time_override=True)
        i = intent(intent_id="intent_gap_000000000211")
        result = self.run_case(i, runtime=runtime)
        self.assertEqual(IntentState.UNKNOWN, result.state)
        self.assertIn("RECONCILIATION_EXCEPTION", result.reason_codes)
        self.assertEqual("HELD", self.usage_status(i.intent_id))

    def test_partial_fill_below_authorized_finalizes_and_commits_authorized_amount(self):
        adapter = _PayAdapter("30")
        adapter.name = "mock-dex"
        permit_authority, _ = permit_stack(self.store, self.trust)
        runtime = FAARRuntime(self.store, {"mock-dex": adapter}, verification_trust(self.trust), permit_authority, {"mock-dex": _Verifier(adapter)}, clock=lambda: NOW, allow_test_time_override=True)
        i = intent(intent_id="intent_gap_000000000212")
        result = self.run_case(i, runtime=runtime)
        self.assertEqual(IntentState.FINALIZED, result.state)
        row = next(r for r in self.store.usage("grant:test", 1) if r["intent_id"] == i.intent_id)
        self.assertEqual(("COMMITTED", "50"), (row["status"], row["amount_usd"]), "the ledger commits the authorized notional, never less")

    def test_happy_path_commits_usage(self):
        i = intent(intent_id="intent_gap_000000000213")
        self.assertEqual(IntentState.FINALIZED, self.run_case(i).state)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))


class ConstructionGateTests(_Base):
    def test_untrusted_settlement_verifier_profile_is_rejected(self):
        class Weak:
            name = "weak"
            security_profile = SettlementSecurityProfile(True, False, True, True)

            def verify(self, request):
                raise AssertionError("never called")

        class NoProfile:
            name = "none"

            def verify(self, request):
                raise AssertionError("never called")

        with self.assertRaisesRegex(ValueError, "trusted verification profile"):
            FAARRuntime(self.store, {"mock-dex": self.venue}, verification_trust(self.trust), self.permit_authority, {"mock-dex": Weak()})
        with self.assertRaisesRegex(ValueError, "trusted verification profile"):
            FAARRuntime(self.store, {"mock-dex": self.venue}, verification_trust(self.trust), self.permit_authority, {"mock-dex": NoProfile()})
        with self.assertRaisesRegex(ValueError, "exactly one configured settlement verifier"):
            FAARRuntime(self.store, {"mock-dex": self.venue}, verification_trust(self.trust), self.permit_authority, {"other": self.settlement})

    def test_store_enforces_transition_table_and_principal_namespace(self):
        i = intent(intent_id="intent_gap_000000000220")
        self.store.register(i, canonical_hash(i))
        with self.assertRaises(InvalidTransition):
            self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.FINALIZED, effect_id="x")
        other = replace(i, principal_id="principal:other")
        with self.assertRaisesRegex(IntentConflict, "principal namespace"):
            self.store.register(other, canonical_hash(other))


class OutcomePrerequisiteTests(unittest.TestCase):
    def _contract(self, iid="intent_test_000000000001"):
        return TaskContract("task-gap", iid, "settled", (OutcomeCriterion("amount_usd", "lte", "50"),), NOW, NOW + timedelta(hours=1))

    def test_finalized_settlement_without_effect_id_cannot_be_done(self):
        settlement = SettlementRecord(SettlementStatus.FINALIZED, effect_id=None, amount_usd=Decimal("50"), authoritative=True, verified_request_hash="x")
        result = verify_task_outcome(self._contract(), settlement)
        self.assertEqual(OutcomeVerdict.UNKNOWN, result.verdict)
        self.assertIn("FINALIZED_EFFECT_ID_REQUIRED", result.reason_codes)

    def test_non_finalized_settlement_is_not_done(self):
        settlement = SettlementRecord(SettlementStatus.CONFIRMED, effect_id="fx", amount_usd=Decimal("50"), authoritative=True, verified_request_hash="x")
        result = verify_task_outcome(self._contract(), settlement)
        self.assertEqual(OutcomeVerdict.UNKNOWN, result.verdict)
        self.assertIn("ECONOMIC_EFFECT_NOT_FINALIZED", result.reason_codes)

    def test_task_contract_for_other_intent_is_rejected(self):
        t = trust()
        i = intent()
        contract = self._contract("intent_other_000000000001")
        att = t.sign("task-test", AttestationKind.TASK, contract, i, issued_at=NOW, ttl_seconds=60)
        settlement = SettlementRecord(SettlementStatus.FINALIZED, "fx", Decimal("50"), authoritative=True, verified_request_hash=canonical_hash(ExecutionRequest.from_intent(i)))
        result = verify_attested_task_outcome(contract, settlement, attestation=att, intent=i, trust=verification_trust(t), now=NOW)
        self.assertEqual(OutcomeVerdict.UNKNOWN, result.verdict)
        self.assertIn("TASK_INTENT_ID_MISMATCH", result.reason_codes)


if __name__ == "__main__":
    unittest.main()
