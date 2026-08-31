from __future__ import annotations

import tempfile
import unittest

from faar.adapters import MockMode
from faar.canonical import canonical_hash
from faar.faults import FAULT_TO_MOCK_MODE, InjectedFault
from faar.models import IntentState
from faar.store import SQLiteIntentStore
from support import AUTH, NOW, attest_pair, build_mock_runtime, grant, intent, risk, trust


class FailureInjectionTests(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        self.store = SQLiteIntentStore(f.name)
        self.path = f.name
        self.g = grant()
        self.store.provision_grant(self.g, canonical_hash(self.g))
        self.t = trust()
        self.runtime, self.venue, self.settlement, self.permit_authority, self.permit_verifier = build_mock_runtime(
            self.store, self.t
        )

    def tearDown(self):
        self.store.close()

    def _run(self, intent_id, version, mode=MockMode.SUCCESS):
        self.venue.set_mode(mode)
        i = intent(intent_id=intent_id)
        rs = risk(state_version=version)
        aa, ra = attest_pair(self.t, i, AUTH, rs, NOW)
        return i, self.runtime.process(
            i, AUTH, self.g, rs, authority_attestation=aa, risk_attestation=ra, now=NOW
        )

    def test_timeout_before_accept_creates_no_effect(self):
        i, result = self._run("fault_timeout_before_00000001", 201, MockMode.TIMEOUT_BEFORE_EFFECT)
        self.assertNotEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(0, self.venue.successful_effect_count(i.intent_id))

    def test_timeout_after_accept_reconciles_to_one_effect(self):
        i, result = self._run("fault_timeout_after_000000001", 202, MockMode.TIMEOUT_AFTER_EFFECT)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(1, self.venue.successful_effect_count(i.intent_id))

    def test_network_ambiguity_does_not_create_a_second_effect(self):
        i, result = self._run("fault_ambiguous_0000000000001", 203, MockMode.AMBIGUOUS)
        self.assertNotEqual(IntentState.FINALIZED, result.state)
        self.assertLessEqual(self.venue.successful_effect_count(i.intent_id), 1)

    def test_stale_verifier_after_key_revocation_stops(self):
        i, result = self._run("fault_stale_key_0000000000001", 204)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.permit_verifier.lifecycle.revoke("permit-test", at=NOW)
        i2 = intent(intent_id="fault_stale_key_0000000000002")
        rs = risk(state_version=205)
        aa, ra = attest_pair(self.t, i2, AUTH, rs, NOW)
        result2 = self.runtime.process(i2, AUTH, self.g, rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertNotEqual(IntentState.FINALIZED, result2.state)

    def test_grant_revocation_survives_restart(self):
        self.store.set_grant_status("principal:test", self.g.grant_id, self.g.version, "REVOKED")
        self.store.close()
        restarted = SQLiteIntentStore(self.path)
        try:
            self.assertEqual("REVOKED", restarted.get_grant_status("principal:test", self.g.grant_id, self.g.version))
            with self.assertRaises(Exception):
                restarted.set_grant_status("principal:test", self.g.grant_id, self.g.version, "ACTIVE")
        finally:
            restarted.close()

    def test_consumed_permit_survives_restart(self):
        i, result = self._run("fault_consumed_restart_000001", 206)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.store.close()
        restarted = SQLiteIntentStore(self.path)
        try:
            row = restarted._conn.execute(
                "SELECT consumed_at FROM execution_permits WHERE intent_id=?", (i.intent_id,)
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertIsNotNone(row["consumed_at"])
        finally:
            restarted.close()

    def test_fault_catalog_maps_timeouts(self):
        self.assertEqual(MockMode.TIMEOUT_BEFORE_EFFECT, FAULT_TO_MOCK_MODE[InjectedFault.TIMEOUT_BEFORE_ACCEPT])
        self.assertEqual(MockMode.TIMEOUT_AFTER_EFFECT, FAULT_TO_MOCK_MODE[InjectedFault.TIMEOUT_AFTER_ACCEPT])

    def test_partial_fill_is_single_effect_and_survives_repeat_submit(self):
        i, result = self._run("fault_partial_fill_0000000001", 207, MockMode.PARTIAL_FILL)
        self.assertEqual(IntentState.CONFIRMED, result.state)
        self.assertEqual(1, self.venue.successful_effect_count(i.intent_id))
        again = self.runtime.process(
            i, AUTH, self.g, risk(state_version=207),
            authority_attestation=attest_pair(self.t, i, AUTH, risk(state_version=207), NOW)[0],
            risk_attestation=attest_pair(self.t, i, AUTH, risk(state_version=207), NOW)[1],
            now=NOW,
        )
        self.assertEqual(IntentState.CONFIRMED, again.state)
        self.assertEqual(1, self.venue.successful_effect_count(i.intent_id))
        self.assertEqual(self.store.get(i.intent_id).effect_id, again.effect_id)

    def test_datastore_interrupt_fails_closed_on_permit_consume(self):
        i = intent(intent_id="fault_datastore_interrupt_001")
        rs = risk(state_version=208)
        from faar.canonical import canonical_hash as ch
        from faar.models import ExecutionRequest
        self.store.register(i, ch(i))
        self.assertTrue(self.store.reserve_usage(i, self.g, rs, NOW)[0])
        aa, ra = attest_pair(self.t, i, AUTH, rs, NOW)
        req = ExecutionRequest.from_intent(i)
        permit = self.permit_authority.issue(
            req, intent=i, authority=AUTH, grant=self.g, risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )
        self.store.close()
        ok, reasons = self.permit_verifier.consume(permit, req, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_CONSUMPTION_UNAVAILABLE", reasons)

    def test_inconsistent_provider_responses_are_contradictory(self):
        from decimal import Decimal
        from faar.canonical import canonical_hash as ch
        from faar.models import ExecutionRequest, SettlementRecord, SettlementStatus
        from faar.settlement import QuorumSettlementVerifier, REFERENCE_SETTLEMENT_PROFILE

        class Source:
            security_profile = REFERENCE_SETTLEMENT_PROFILE
            def __init__(self, record, name):
                self.record = record
                self.name = name
            def verify(self, request):
                return self.record

        req = ExecutionRequest.from_intent(intent(intent_id="fault_inconsistent_00000001"))
        req_hash = ch(req)
        a = SettlementRecord(SettlementStatus.FINALIZED, "fx-a", Decimal("50"), authoritative=True, verified_request_hash=req_hash)
        b = SettlementRecord(SettlementStatus.NONE, authoritative=True, verified_request_hash=req_hash)
        q = QuorumSettlementVerifier([Source(a, "provider-a"), Source(b, "provider-b")], quorum=2)
        result = q.verify(req)
        self.assertEqual(SettlementStatus.CONTRADICTORY, result.status)
        self.assertTrue(result.authoritative)


if __name__ == "__main__":
    unittest.main()
