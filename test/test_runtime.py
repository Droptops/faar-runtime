from __future__ import annotations

import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

from faar.adapters import AmbiguousExecution, MockMode, MockVenue, REFERENCE_SAFE_PROFILE, AdapterSecurityProfile
from faar.canonical import canonical_hash
from faar.models import (
    AttestationKind,
    AuthorityDecision,
    AuthorityPosture,
    AuthorityPrimitive,
    EconomicPrimitive,
    ExecutionReceipt,
    GrantStatus,
    IntentState,
    SettlementStatus,
)
from faar.runtime import FAARRuntime
from faar.settlement import MockSettlementVerifier, SettlementRecord, SettlementSecurityProfile, REFERENCE_SETTLEMENT_PROFILE
from faar.models import ExecutionRequest
from faar.store import GrantConflict, IntentConflict, SQLiteIntentStore

from support import AUTH, NOW, PRINCIPAL, attest_pair, grant, intent, risk, trust, verification_trust, build_mock_runtime


class AdapterBackedVerifier:
    """Test-only verifier shim for adversarial adapter fixtures.

    Production FAAR requires an independent verifier. These fixtures intentionally
    isolate runtime handling of malformed/contradictory settlement records.
    """
    name = "test-adapter-backed-verifier"
    security_profile = REFERENCE_SETTLEMENT_PROFILE

    def __init__(self, adapter):
        self.adapter = adapter

    def verify(self, request):
        return self.adapter.reconcile(request)



class FAARRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self.store = SQLiteIntentStore(self.tmp.name, evidence_key=b"evidence-test-key-32-bytes-long!!!!")
        self.trust = trust()
        self.runtime, self.venue, self.settlement, self.permit_authority, self.permit_verifier = build_mock_runtime(
            self.store, self.trust
        )
        self.store.provision_grant(grant(), canonical_hash(grant()))

    def tearDown(self):
        self.store.close()

    def runtime_for(self, adapter, *, verifier=None, clock=lambda: NOW, allow_test_time_override=True):
        verifier = verifier or AdapterBackedVerifier(adapter)
        return FAARRuntime(
            self.store, {"mock-dex": adapter}, verification_trust(self.trust), self.permit_authority,
            {"mock-dex": verifier}, clock=clock, allow_test_time_override=allow_test_time_override,
        )

    def force_external_effect(self, i, *, g=None, rs=None):
        g = g or grant()
        rs = rs or risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        request = ExecutionRequest.from_intent(i)
        permit = self.permit_authority.issue(
            request, intent=i, authority=AUTH, grant=g, risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )
        return self.venue.execute(request, permit)

    def execute_case(self, i, auth=AUTH, g=None, rs=None, *, runtime=None, now=NOW, attestations=None):
        g = g or grant()
        rs = rs or risk()
        runtime = runtime or self.runtime
        aa, ra = attestations or attest_pair(self.trust, i, auth, rs, now)
        return runtime.process(
            i, auth, g, rs,
            authority_attestation=aa,
            risk_attestation=ra,
            now=now,
        )

    def test_runtime_rejects_signing_capable_attestation_store(self):
        with self.assertRaisesRegex(ValueError, "verify-only attestation"):
            FAARRuntime(
                self.store, {"mock-dex": self.venue}, self.trust, self.permit_authority,
                {"mock-dex": self.settlement},
            )

    def test_happy_path_finalizes_once(self):
        i = intent()
        result = self.execute_case(i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(1, result.submission_count)
        replay = self.execute_case(i)
        self.assertEqual(IntentState.FINALIZED, replay.state)
        self.assertTrue(replay.replayed)
        self.assertEqual(1, self.venue.successful_effect_count(i.intent_id))
        self.assertEqual(1, self.venue.execute_call_count(i.intent_id))

    def test_same_intent_id_different_payload_is_rejected(self):
        i = intent()
        self.execute_case(i)
        changed = replace(i, payload={**i.payload, "amount_usd": "51"})
        with self.assertRaises(IntentConflict):
            self.execute_case(changed)

    def test_authority_advise_cannot_execute(self):
        i = intent(intent_id="intent_test_000000000002")
        auth = AuthorityDecision(AuthorityPosture.ADVISE, AuthorityPrimitive.GIVE_RECOMMENDATION)
        result = self.execute_case(i, auth=auth)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertEqual(0, self.venue.successful_effect_count(i.intent_id))

    def test_forged_authority_attestation_stops(self):
        i = intent(intent_id="intent_test_000000000023")
        aa, ra = attest_pair(self.trust, i, AUTH, risk())
        aa = replace(aa, signature="invalid-signature")
        result = self.execute_case(i, attestations=(aa, ra))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertTrue(any("ATTESTATION_SIGNATURE_INVALID" in r for r in result.reason_codes))
        self.assertEqual(0, self.venue.successful_effect_count(i.intent_id))

    def test_risk_attestation_bound_to_intent(self):
        i1 = intent(intent_id="intent_test_000000000024")
        i2 = intent(intent_id="intent_test_000000000025")
        aa2, _ = attest_pair(self.trust, i2, AUTH, risk())
        _, ra1 = attest_pair(self.trust, i1, AUTH, risk())
        result = self.execute_case(i2, attestations=(aa2, ra1))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("RISK_ATTESTATION_INTENT_MISMATCH", result.reason_codes)

    def test_expired_attestation_stops(self):
        i = intent(intent_id="intent_test_000000000026")
        aa = self.trust.sign("authority-test", AttestationKind.AUTHORITY, AUTH, i, issued_at=NOW - timedelta(minutes=2), ttl_seconds=5)
        ra = self.trust.sign("risk-test", AttestationKind.RISK, risk(), i, issued_at=NOW - timedelta(minutes=2), ttl_seconds=5)
        result = self.execute_case(i, attestations=(aa, ra))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertTrue(any("ATTESTATION_EXPIRED" in r for r in result.reason_codes))

    def test_over_order_cap_is_denied(self):
        i = intent(intent_id="intent_test_000000000003", payload={**intent().payload, "amount_usd": "76"})
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("MAX_ORDER_USD_EXCEEDED", result.reason_codes)

    def test_unapproved_target_is_denied(self):
        i = intent(intent_id="intent_test_000000000004", payload={**intent().payload, "target": "wallet:attacker"})
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("TARGET_NOT_ALLOWED", result.reason_codes)

    def test_raw_calldata_from_agent_is_denied(self):
        i = intent(intent_id="intent_test_000000000017", payload={**intent().payload, "raw_calldata": "0xdeadbeef"})
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("UNSAFE_RAW_EXECUTION_FIELD", result.reason_codes)

    def test_nonfinite_amount_is_denied_not_crash(self):
        i = intent(intent_id="intent_test_000000000027", payload={**intent().payload, "amount_usd": "NaN"})
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("AMOUNT_INVALID_OR_NONFINITE", result.reason_codes)

    def test_swap_requires_assets_and_target(self):
        i = intent(intent_id="intent_test_000000000018", payload={"amount_usd": "50"})
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertTrue(any(code.startswith("PAYLOAD_FIELD_REQUIRED") for code in result.reason_codes))

    def test_unknown_asset_is_denied(self):
        i = intent(intent_id="intent_test_000000000005", payload={**intent().payload, "to_asset": "SCAM"})
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertTrue(any(code.startswith("ASSET_NOT_ALLOWED") for code in result.reason_codes))

    def test_stale_market_data_defers(self):
        i = intent(intent_id="intent_test_000000000006")
        result = self.execute_case(i, rs=risk(market_data_age_seconds=11))
        self.assertEqual(IntentState.DEFERRED, result.state)
        self.assertIn("MARKET_DATA_STALE", result.reason_codes)

    def test_stale_risk_snapshot_defers_even_if_market_age_claim_is_fresh(self):
        i = intent(intent_id="intent_test_000000000028")
        rs = risk(observed_at=NOW - timedelta(seconds=6), market_data_age_seconds=1)
        result = self.execute_case(i, rs=rs)
        self.assertEqual(IntentState.DEFERRED, result.state)
        self.assertIn("RISK_SNAPSHOT_STALE", result.reason_codes)

    def test_circuit_breaker_dominates_allow(self):
        i = intent(intent_id="intent_test_000000000007")
        result = self.execute_case(i, rs=risk(circuit_breaker_active=True))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("CIRCUIT_BREAKER_ACTIVE", result.reason_codes)

    def test_orphan_held_usage_is_released_when_proposed_intent_later_denies(self):
        i = intent(intent_id="intent_test_000000000041")
        rs = risk()
        # Simulate crash cut: register + reserve completed, but the state update
        # from PROPOSED to AUTHORIZED never happened.
        self.store.register(i, canonical_hash(i))
        ok, reasons = self.store.reserve_usage(i, grant(), rs, NOW)
        self.assertTrue(ok, reasons)
        self.assertEqual("HELD", self.store.usage("grant:test", 1)[-1]["status"])

        expired = NOW + timedelta(seconds=30)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        result = self.runtime.process(
            i, AUTH, grant(), rs, authority_attestation=aa, risk_attestation=ra, now=expired
        )
        self.assertIn(result.state, {IntentState.DENIED, IntentState.DEFERRED, IntentState.STOPPED})
        row = next(r for r in self.store.usage("grant:test", 1) if r["intent_id"] == i.intent_id)
        self.assertEqual("RELEASED", row["status"])

    def test_authorization_is_rechecked_at_submission_time(self):
        i = intent(intent_id="intent_test_000000000040")
        rs = risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        times = iter((NOW, NOW + timedelta(seconds=30)))
        runtime = FAARRuntime(
            self.store, {"mock-dex": self.venue}, verification_trust(self.trust), self.permit_authority,
            {"mock-dex": self.settlement}, clock=lambda: next(times)
        )
        result = runtime.process(
            i, AUTH, grant(), rs, authority_attestation=aa, risk_attestation=ra
        )
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("SUBMIT_REAUTHORIZATION_FAILED", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_timeout_after_effect_reconciles_without_second_effect(self):
        i = intent(intent_id="intent_test_000000000008")
        self.venue.set_mode(MockMode.TIMEOUT_AFTER_EFFECT)
        result = self.execute_case(i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(1, self.venue.successful_effect_count(i.intent_id))
        self.assertEqual(1, self.venue.execute_call_count(i.intent_id))

    def test_timeout_before_effect_stops_after_durable_retry_budget(self):
        i = intent(intent_id="intent_test_000000000009")
        self.venue.set_mode(MockMode.TIMEOUT_BEFORE_EFFECT)
        result = self.execute_case(i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("MAX_SUBMISSION_ATTEMPTS_REACHED", result.reason_codes)
        self.assertEqual(0, self.venue.successful_effect_count(i.intent_id))
        self.assertEqual(2, self.venue.execute_call_count(i.intent_id))
        self.assertEqual(2, self.store.get(i.intent_id).submission_count)
        # Retry budget is durable across later process invocations.
        again = self.execute_case(i)
        self.assertEqual(IntentState.STOPPED, again.state)
        self.assertEqual(2, self.venue.execute_call_count(i.intent_id))

    def test_crash_after_external_effect_before_local_persist_reconciles(self):
        i = intent(intent_id="intent_test_000000000010")
        self.store.register(i, canonical_hash(i))
        self.store.reserve_usage(i, grant(), risk(), NOW)
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        self.store.begin_submission(i.intent_id, [IntentState.RESERVED], max_attempts=2)
        self.force_external_effect(i)
        recovered = self.execute_case(i)
        self.assertEqual(IntentState.FINALIZED, recovered.state)
        self.assertEqual(1, self.venue.successful_effect_count(i.intent_id))
        self.assertEqual(1, self.venue.execute_call_count(i.intent_id))

    def test_concurrent_workers_create_at_most_one_effect(self):
        i = intent(intent_id="intent_test_000000000011")
        results, errors = [], []
        barrier = threading.Barrier(2)

        def worker():
            try:
                barrier.wait()
                results.append(self.execute_case(i))
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        t1 = threading.Thread(target=worker); t2 = threading.Thread(target=worker)
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertFalse(errors, errors)
        self.assertEqual(1, self.venue.successful_effect_count(i.intent_id))
        self.assertEqual(IntentState.FINALIZED, self.store.get(i.intent_id).state)

    def test_concurrent_distinct_intents_cannot_oversubscribe_daily_turnover(self):
        tight = grant(grant_id="grant:tight", limits=replace(grant().limits, max_daily_turnover_usd=Decimal("75")))
        self.store.provision_grant(tight, canonical_hash(tight))
        i1 = intent(intent_id="intent_budget_000000000001", grant_id="grant:tight")
        i2 = intent(intent_id="intent_budget_000000000002", grant_id="grant:tight")
        results = []
        barrier = threading.Barrier(2)

        def worker(i):
            barrier.wait()
            results.append(self.execute_case(i, g=tight, rs=risk(daily_turnover_after_usd=Decimal("50"))))

        t1 = threading.Thread(target=worker, args=(i1,)); t2 = threading.Thread(target=worker, args=(i2,))
        t1.start(); t2.start(); t1.join(); t2.join()
        self.assertEqual(1, sum(self.venue.successful_effect_count(i.intent_id) for i in (i1, i2)))
        self.assertEqual(1, sum(r.state == IntentState.FINALIZED for r in results))
        self.assertEqual(1, sum(r.state == IntentState.DEFERRED for r in results))

    def test_same_risk_state_version_cannot_authorize_two_distinct_intents(self):
        g = grant(grant_id="grant:risk-version", limits=replace(grant().limits, max_daily_turnover_usd=Decimal("1000")))
        self.store.provision_grant(g, canonical_hash(g))
        i1 = intent(intent_id="intent_riskver_0000000001", grant_id=g.grant_id)
        i2 = intent(intent_id="intent_riskver_0000000002", grant_id=g.grant_id)
        first = self.execute_case(i1, g=g, rs=risk(state_version=7))
        second = self.execute_case(i2, g=g, rs=risk(state_version=7))
        self.assertEqual(IntentState.FINALIZED, first.state)
        self.assertEqual(IntentState.DEFERRED, second.state)
        self.assertIn("RISK_STATE_VERSION_ALREADY_CLAIMED", second.reason_codes)
        self.assertEqual(1, len(self.store.risk_claims(g.grant_id, g.version)))

    def test_paused_grant_stops(self):
        paused = grant(grant_id="grant:paused", status=GrantStatus.PAUSED)
        self.store.provision_grant(paused, canonical_hash(paused))
        i = intent(intent_id="intent_test_000000000012", grant_id="grant:paused")
        result = self.execute_case(i, g=paused)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_RUNTIME_PAUSED", result.reason_codes)

    def test_grant_version_binding(self):
        i = intent(intent_id="intent_test_000000000013", grant_version=2)
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("GRANT_VERSION_MISMATCH", result.reason_codes)

    def test_expired_intent_denied(self):
        i = intent(
            intent_id="intent_test_000000000014",
            created_at=NOW - timedelta(seconds=30),
            expires_at=NOW - timedelta(seconds=1),
        )
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("INTENT_EXPIRED", result.reason_codes)

    def test_overlong_intent_ttl_denied(self):
        i = intent(intent_id="intent_test_000000000029", expires_at=NOW + timedelta(seconds=60))
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("INTENT_TTL_EXCEEDED", result.reason_codes)

    def test_future_created_intent_denied(self):
        i = intent(
            intent_id="intent_test_000000000030",
            created_at=NOW + timedelta(seconds=3),
            expires_at=NOW + timedelta(seconds=10),
        )
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("INTENT_CREATED_IN_FUTURE", result.reason_codes)

    def test_revocation_is_irreversible_for_same_grant_version(self):
        self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
        with self.assertRaises(GrantConflict):
            self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "ACTIVE")

    def test_provisioned_paused_grant_can_resume_without_mutating_envelope(self):
        store = SQLiteIntentStore(":memory:", evidence_key=b"paused-grant-evidence-key-32-bytes!!")
        try:
            g = grant(status=GrantStatus.PAUSED)
            store.provision_grant(g, canonical_hash(g))
            store.set_grant_status(g.principal_id, g.grant_id, g.version, "ACTIVE")
            runtime, venue, _, _, _ = build_mock_runtime(store, self.trust)
            i = intent(intent_id="intent_test_000000000044")
            rs = risk()
            aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
            result = runtime.process(i, AUTH, g, rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
            self.assertEqual(IntentState.FINALIZED, result.state)
            self.assertEqual(1, venue.successful_effect_count(i.intent_id))
        finally:
            store.close()

    def test_confirmed_effect_followed_by_none_stops_without_resubmit(self):
        class LosingAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def __init__(self): self.calls = 0; self.lookups = 0
            def execute(self, i, permit):
                self.calls += 1
                return ExecutionReceipt("effect-known", SettlementStatus.CONFIRMED, {"phase": "submitter"}, Decimal("50"))
            def reconcile(self, i):
                self.lookups += 1
                if self.lookups == 1:
                    return SettlementRecord(
                        SettlementStatus.CONFIRMED, effect_id="effect-known", amount_usd=Decimal("50"),
                        evidence={"phase": "independent-confirmed"}, authoritative=True,
                        verified_request_hash=canonical_hash(i),
                    )
                return SettlementRecord(
                    SettlementStatus.NONE, evidence={"phase": "lost"}, authoritative=True,
                    verified_request_hash=canonical_hash(i),
                )

        adapter = LosingAdapter()
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_test_000000000022")
        first = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.CONFIRMED, first.state)
        second = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.STOPPED, second.state)
        self.assertIn("SETTLEMENT_LOST_PREVIOUS_EFFECT", second.reason_codes)
        self.assertEqual(1, adapter.calls)

    def test_finalized_without_effect_id_stops(self):
        class BadAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def execute(self, i, permit):
                return ExecutionReceipt("", SettlementStatus.FINALIZED, {"bad": True})
            def reconcile(self, i):
                return SettlementRecord(
                    SettlementStatus.FINALIZED, effect_id=None, amount_usd=Decimal("50"),
                    evidence={"bad": True}, authoritative=True, verified_request_hash=canonical_hash(i),
                )

        runtime = self.runtime_for(BadAdapter())
        i = intent(intent_id="intent_test_000000000031")
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("SETTLED_EFFECT_ID_REQUIRED", result.reason_codes)

    def test_effect_id_change_after_confirmation_stops(self):
        class SwappingAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def __init__(self): self.lookups = 0
            def execute(self, i, permit):
                return ExecutionReceipt("effect-A", SettlementStatus.CONFIRMED, {"phase": "submitter"}, Decimal("50"))
            def reconcile(self, i):
                self.lookups += 1
                effect = "effect-A" if self.lookups == 1 else "effect-B"
                status = SettlementStatus.CONFIRMED if self.lookups == 1 else SettlementStatus.FINALIZED
                return SettlementRecord(
                    status, effect_id=effect, amount_usd=Decimal("50"), evidence={"phase": str(self.lookups)},
                    authoritative=True, verified_request_hash=canonical_hash(i),
                )

        runtime = self.runtime_for(SwappingAdapter())
        i = intent(intent_id="intent_test_000000000032")
        self.assertEqual(IntentState.CONFIRMED, self.execute_case(i, runtime=runtime).state)
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("SETTLEMENT_EFFECT_ID_MISMATCH", result.reason_codes)

    def test_duplicate_effect_id_across_intents_stops_second(self):
        class DuplicateAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def execute(self, i, permit):
                return ExecutionReceipt("same-effect", SettlementStatus.FINALIZED, {"intent": i.intent_id}, Decimal("50"))
            def reconcile(self, i):
                return SettlementRecord(
                    SettlementStatus.FINALIZED, effect_id="same-effect", amount_usd=Decimal("50"),
                    evidence={"intent": i.intent_id}, authoritative=True, verified_request_hash=canonical_hash(i),
                )

        runtime = self.runtime_for(DuplicateAdapter())
        i1 = intent(intent_id="intent_test_000000000033")
        i2 = intent(intent_id="intent_test_000000000034")
        self.assertEqual(IntentState.FINALIZED, self.execute_case(i1, runtime=runtime).state)
        result = self.execute_case(i2, runtime=runtime, rs=risk(state_version=2))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("EFFECT_ID_ALREADY_CLAIMED", result.reason_codes)

    def test_non_authoritative_none_never_resubmits(self):
        class WeakLookupAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def __init__(self): self.calls = 0
            def execute(self, i, permit):
                self.calls += 1
                raise AmbiguousExecution("timeout")
            def reconcile(self, i):
                return SettlementRecord(SettlementStatus.NONE, evidence={"rpc": "not found"}, authoritative=False)

        adapter = WeakLookupAdapter()
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_test_000000000035")
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.UNKNOWN, result.state)
        self.assertIn("SETTLEMENT_NONE_NOT_AUTHORITATIVE", result.reason_codes)
        self.assertEqual(1, adapter.calls)
        usage = self.store.usage("grant:test", 1)
        row = [x for x in usage if x["intent_id"] == i.intent_id][0]
        self.assertEqual("HELD", row["status"])

    def test_expired_intent_never_resubmits_after_authoritative_none(self):
        i = intent(intent_id="intent_test_000000000036")
        self.store.register(i, canonical_hash(i))
        self.store.reserve_usage(i, grant(), risk(), NOW)
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        self.store.begin_submission(i.intent_id, [IntentState.RESERVED], max_attempts=2)
        later = NOW + timedelta(seconds=20)
        result = self.execute_case(i, now=later)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("INTENT_EXPIRED_BEFORE_RESUBMIT", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_changed_risk_is_rechecked_before_resubmit(self):
        i = intent(intent_id="intent_test_000000000037")
        self.store.register(i, canonical_hash(i))
        self.store.reserve_usage(i, grant(), risk(), NOW)
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        self.store.begin_submission(i.intent_id, [IntentState.RESERVED], max_attempts=2)
        result = self.execute_case(i, rs=risk(circuit_breaker_active=True))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("RESUBMIT_NOT_AUTHORIZED", result.reason_codes)
        self.assertIn("CIRCUIT_BREAKER_ACTIVE", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_runtime_revocation_stops_new_execution(self):
        i = intent(intent_id="intent_test_000000000019")
        self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
        result = self.execute_case(i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_RUNTIME_REVOKED", result.reason_codes)

    def test_revocation_during_ambiguous_recovery_never_resubmits(self):
        i = intent(intent_id="intent_test_000000000020")
        self.store.register(i, canonical_hash(i))
        self.store.reserve_usage(i, grant(), risk(), NOW)
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        self.store.begin_submission(i.intent_id, [IntentState.RESERVED], max_attempts=2)
        self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
        result = self.execute_case(i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_RUNTIME_REVOKED", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))
        row = [u for u in self.store.usage("grant:test", 1) if u["intent_id"] == i.intent_id][0]
        self.assertEqual("RELEASED", row["status"])

    def test_revocation_during_recovery_still_records_effect_that_already_happened(self):
        i = intent(intent_id="intent_test_000000000021")
        self.store.register(i, canonical_hash(i))
        self.store.reserve_usage(i, grant(), risk(), NOW)
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        self.store.begin_submission(i.intent_id, [IntentState.RESERVED], max_attempts=2)
        self.force_external_effect(i)
        self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
        result = self.execute_case(i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(1, self.venue.successful_effect_count(i.intent_id))

    def test_revocation_completion_is_execution_fence(self):
        entered = threading.Event()
        release = threading.Event()

        class BlockingAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def __init__(self): self.effects = 0
            def execute(self, i, permit):
                entered.set()
                release.wait(timeout=2)
                self.effects += 1
                return ExecutionReceipt("blocked-effect", SettlementStatus.FINALIZED, {"ok": True}, Decimal("50"))
            def reconcile(self, i):
                return SettlementRecord(
                    SettlementStatus.FINALIZED, effect_id="blocked-effect", amount_usd=Decimal("50"),
                    evidence={"ok": True}, authoritative=True, verified_request_hash=canonical_hash(i),
                )

        adapter = BlockingAdapter()
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_test_000000000038")
        result_box = []
        revoke_done = threading.Event()

        t_exec = threading.Thread(target=lambda: result_box.append(self.execute_case(i, runtime=runtime)))
        t_exec.start(); self.assertTrue(entered.wait(timeout=1))

        def revoke():
            self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
            revoke_done.set()

        t_rev = threading.Thread(target=revoke); t_rev.start()
        time.sleep(0.05)
        self.assertFalse(revoke_done.is_set(), "revocation returned while submission held the execution fence")
        release.set(); t_exec.join(); t_rev.join()
        self.assertTrue(revoke_done.is_set())
        self.assertEqual(IntentState.FINALIZED, result_box[0].state)

        later = intent(intent_id="intent_test_000000000039")
        stopped = self.execute_case(later)
        self.assertEqual(IntentState.STOPPED, stopped.state)
        self.assertEqual(1, adapter.effects)

    def test_substituted_grant_envelope_is_stopped(self):
        i = intent(intent_id="intent_test_000000000015")
        broader = grant(limits=replace(grant().limits, max_order_usd=Decimal("1000000")))
        # Attestations are irrelevant: the presented grant itself must match the
        # separately provisioned fingerprint.
        result = self.execute_case(i, g=broader)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_ENVELOPE_MISMATCH", result.reason_codes)

    def test_evidence_chain_and_mac_verify(self):
        i = intent(intent_id="intent_test_000000000016")
        self.assertEqual(IntentState.FINALIZED, self.execute_case(i).state)
        self.assertTrue(self.store.verify_evidence_chain(i.intent_id))
        self.store._conn.execute("UPDATE evidence SET event_mac=? WHERE intent_id=? AND id=(SELECT MIN(id) FROM evidence WHERE intent_id=?)", ("00" * 32, i.intent_id, i.intent_id))
        self.assertFalse(self.store.verify_evidence_chain(i.intent_id))

    def test_unknown_execution_field_is_denied(self):
        i = intent(
            intent_id="intent_test_000000000041",
            payload={**intent().payload, "recipient_override": "wallet:attacker"},
        )
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertTrue(any(r.startswith("UNKNOWN_EXECUTION_FIELDS:") for r in result.reason_codes))
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_target_allowlist_cannot_be_bypassed_by_omission(self):
        i = intent(
            intent_id="intent_test_000000000042",
            payload={k: v for k, v in intent().payload.items() if k != "target"},
        )
        result = self.execute_case(i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("TARGET_REQUIRED", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_caller_cannot_move_security_clock_backwards(self):
        i = intent(
            intent_id="intent_test_000000000043",
            created_at=NOW - timedelta(seconds=10),
            expires_at=NOW - timedelta(seconds=1),
        )
        rs = risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        runtime = FAARRuntime(
            self.store,
            {"mock-dex": self.venue},
            verification_trust(self.trust), self.permit_authority, {"mock-dex": self.settlement},
            clock=lambda: NOW,
        )
        # Passing an old `now` is ignored unless the runtime was explicitly created
        # in deterministic-test mode.
        result = runtime.process(
            i,
            AUTH,
            grant(),
            rs,
            authority_attestation=aa,
            risk_attestation=ra,
            now=NOW - timedelta(seconds=9),
        )
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("INTENT_EXPIRED", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_settlement_verifier_cannot_be_submitter_object(self):
        class DualProfile:
            exactly_once_compatible = True
            trusted = True
        class DualRole:
            name = "mock-dex"
            security_profile = DualProfile()
            def execute(self, request, permit):
                raise AssertionError("should not execute")
            def verify(self, request):
                return SettlementRecord(
                    SettlementStatus.NONE, authoritative=True,
                    verified_request_hash=canonical_hash(request),
                )
        dual = DualRole()
        with self.assertRaisesRegex(ValueError, "distinct component"):
            FAARRuntime(
                self.store, {"mock-dex": dual}, verification_trust(self.trust),
                self.permit_authority, {"mock-dex": dual},
            )

    def test_adapter_without_exactly_once_contract_is_rejected(self):
        class UnsafeAdapter:
            name = "mock-dex"
            def execute(self, i, permit):
                return ExecutionReceipt("x", SettlementStatus.FINALIZED, {})
            def reconcile(self, i):
                return SettlementRecord(SettlementStatus.NONE, authoritative=True, verified_request_hash=canonical_hash(request))

        with self.assertRaises(ValueError):
            FAARRuntime(self.store, {"mock-dex": UnsafeAdapter()}, verification_trust(self.trust), self.permit_authority, {"mock-dex": self.settlement})

    def test_adapter_receives_sanitized_execution_request_not_model_metadata(self):
        class InspectingAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            saw_metadata = None
            def execute(self, request, permit):
                self.saw_metadata = hasattr(request, "metadata")
                return ExecutionReceipt("sanitized-effect", SettlementStatus.FINALIZED, {"ok": True}, Decimal("50"))
            def reconcile(self, request):
                return SettlementRecord(SettlementStatus.FINALIZED, effect_id="sanitized-effect", amount_usd=Decimal("50"), evidence={"ok": True}, authoritative=True, verified_request_hash=canonical_hash(request))

        adapter = InspectingAdapter()
        runtime = self.runtime_for(adapter)
        i = intent(
            intent_id="intent_test_000000000045",
            metadata={"recipient_override": "wallet:attacker", "raw_calldata": "0xdeadbeef"},
        )
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertFalse(adapter.saw_metadata)

    def test_non_authoritative_positive_reconciliation_cannot_finalize(self):
        class WeakPositiveAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def execute(self, request, permit):
                raise AmbiguousExecution("transport ambiguity")
            def reconcile(self, request):
                return SettlementRecord(
                    SettlementStatus.FINALIZED, effect_id="weak-positive", amount_usd=Decimal("50"),
                    evidence={"source": "single-untrusted-rpc"}, authoritative=False,
                )

        runtime = self.runtime_for(WeakPositiveAdapter())
        i = intent(intent_id="intent_test_000000000046")
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.UNKNOWN, result.state)
        self.assertIn("SETTLEMENT_POSITIVE_NOT_AUTHORITATIVE", result.reason_codes)
        self.assertIsNone(self.store.get(i.intent_id).effect_id)
        row = next(r for r in self.store.usage("grant:test", 1) if r["intent_id"] == i.intent_id)
        self.assertEqual("HELD", row["status"])

    def test_settled_amount_cannot_exceed_authorized_intent(self):
        class OverfillAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def execute(self, request, permit):
                return ExecutionReceipt(
                    "overfill-effect", SettlementStatus.FINALIZED, {"reported": "overfill"}, Decimal("500")
                )
            def reconcile(self, request):
                return SettlementRecord(
                    SettlementStatus.FINALIZED, effect_id="overfill-effect", amount_usd=Decimal("500"),
                    evidence={"source": "independent"}, authoritative=True,
                    verified_request_hash=canonical_hash(request),
                )

        runtime = self.runtime_for(OverfillAdapter())
        i = intent(intent_id="intent_test_000000000047")
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("SETTLED_AMOUNT_EXCEEDS_AUTHORIZED", result.reason_codes)
        row = next(r for r in self.store.usage("grant:test", 1) if r["intent_id"] == i.intent_id)
        self.assertEqual("HELD", row["status"], "ambiguous overfill must keep budget held")

    def test_positive_settlement_requires_amount_for_money_moving_intent(self):
        class MissingAmountAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def execute(self, request, permit):
                return ExecutionReceipt("missing-amount-effect", SettlementStatus.FINALIZED, {"ok": False})
            def reconcile(self, request):
                return SettlementRecord(
                    SettlementStatus.FINALIZED, effect_id="missing-amount-effect", amount_usd=None,
                    evidence={"source": "independent"}, authoritative=True,
                    verified_request_hash=canonical_hash(request),
                )

        runtime = self.runtime_for(MissingAmountAdapter())
        i = intent(intent_id="intent_test_000000000048")
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("SETTLED_AMOUNT_REQUIRED", result.reason_codes)

    def test_submitter_receipt_cannot_override_independent_settlement(self):
        class LyingSubmitter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def execute(self, request, permit):
                return ExecutionReceipt(
                    "submitter-lie", SettlementStatus.FINALIZED, {"source": "submitter"}, Decimal("500")
                )
            def reconcile(self, request):
                return SettlementRecord(
                    SettlementStatus.FINALIZED, effect_id="independent-truth", amount_usd=Decimal("50"),
                    evidence={"source": "independent"}, authoritative=True,
                    verified_request_hash=canonical_hash(request),
                )

        runtime = self.runtime_for(LyingSubmitter())
        i = intent(intent_id="intent_test_000000000052")
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual("independent-truth", result.effect_id)
        self.assertEqual("independent-truth", self.store.get(i.intent_id).effect_id)

    def test_settlement_for_different_request_hash_stops(self):
        class Submitter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def execute(self, request, permit):
                return ExecutionReceipt("reported", SettlementStatus.FINALIZED, {}, Decimal("50"))

        class MismatchedVerifier:
            name = "mismatched-verifier"
            security_profile = REFERENCE_SETTLEMENT_PROFILE
            def verify(self, request):
                return SettlementRecord(
                    SettlementStatus.FINALIZED, effect_id="wrong-binding", amount_usd=Decimal("50"),
                    authoritative=True, verified_request_hash="deadbeef",
                )

        runtime = self.runtime_for(Submitter(), verifier=MismatchedVerifier())
        i = intent(intent_id="intent_test_000000000053")
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("SETTLEMENT_REQUEST_BINDING_MISMATCH", result.reason_codes)
        self.assertIsNone(self.store.get(i.intent_id).effect_id)

    def test_unexpected_permit_issuance_exception_fails_before_adapter(self):
        class BrokenPermitAuthority:
            def issue(self, *args, **kwargs):
                raise RuntimeError("signer datastore unavailable")

        runtime = FAARRuntime(
            self.store, {"mock-dex": self.venue}, verification_trust(self.trust), BrokenPermitAuthority(),
            {"mock-dex": self.settlement}, clock=lambda: NOW, allow_test_time_override=True,
        )
        i = intent(intent_id="intent_test_000000000054")
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.FAILED_SAFE, result.state)
        self.assertIn("EXECUTION_PERMIT_EXCEPTION", result.reason_codes)
        self.assertEqual(0, self.venue.execute_call_count(i.intent_id))

    def test_submitter_failure_cannot_hide_independently_observed_effect(self):
        class RejectingSubmitter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            def execute(self, request, permit):
                raise DeterministicFailure("claimed pre-execution rejection")

        class PositiveVerifier:
            name = "positive-independent-verifier"
            security_profile = REFERENCE_SETTLEMENT_PROFILE
            def verify(self, request):
                return SettlementRecord(
                    SettlementStatus.FINALIZED, effect_id="effect-despite-rejection", amount_usd=Decimal("50"),
                    authoritative=True, verified_request_hash=canonical_hash(request),
                )

        runtime = self.runtime_for(RejectingSubmitter(), verifier=PositiveVerifier())
        i = intent(intent_id="intent_test_000000000055")
        result = self.execute_case(i, runtime=runtime)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual("effect-despite-rejection", result.effect_id)

    def test_payment_settlement_amount_must_match_exactly(self):
        pay = intent(
            intent_id="intent_test_000000000050",
            primitive=EconomicPrimitive.PAY,
            payload={"asset": "USDC", "amount_usd": "50", "target": "merchant:approved"},
        )
        reason = FAARRuntime._effect_amount_integrity_reason(
            pay, SettlementStatus.FINALIZED, Decimal("49.99")
        )
        self.assertEqual("PAYMENT_AMOUNT_MISMATCH", reason)
        self.assertIsNone(
            FAARRuntime._effect_amount_integrity_reason(pay, SettlementStatus.FINALIZED, Decimal("50"))
        )


if __name__ == "__main__":
    unittest.main()
