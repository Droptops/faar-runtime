from __future__ import annotations

import tempfile
import threading
import unittest
from dataclasses import replace
from decimal import Decimal

from faar.adapters import AmbiguousExecution, DeterministicFailure, REFERENCE_SAFE_PROFILE
from faar.canonical import canonical_hash
from faar.models import ExecutionReceipt, ExecutionRequest, IntentState, SettlementRecord, SettlementStatus
from faar.runtime import FAARRuntime
from faar.settlement import REFERENCE_SETTLEMENT_PROFILE
from faar.store import SQLiteIntentStore, UnknownIntent
from support import AUTH, NOW, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, trust, verification_trust


def _auth(status, effect_id=None, amount="50"):
    def make(request):
        return SettlementRecord(
            status, effect_id=effect_id, amount_usd=None if amount is None else Decimal(amount),
            evidence={"source": "independent"}, authoritative=True, verified_request_hash=canonical_hash(request),
        )
    return make


def _weak(status, effect_id=None, amount="50"):
    def make(request):
        return SettlementRecord(
            status, effect_id=effect_id, amount_usd=None if amount is None else Decimal(amount),
            evidence={"source": "single-rpc"}, authoritative=False,
        )
    return make


class ScriptedAdapter:
    """Test-only submitter whose behaviour and settlement observations are scripted.

    `behaviours` are consumed once each (exceptions are raised, receipts returned);
    `settlements` are consumed once each except the last, which repeats.
    """

    name = "mock-dex"
    security_profile = REFERENCE_SAFE_PROFILE

    def __init__(self, behaviours, settlements):
        self.behaviours = list(behaviours)
        self.settlements = list(settlements)
        self.calls = 0

    def execute(self, request, permit):
        self.calls += 1
        behaviour = self.behaviours.pop(0)
        if isinstance(behaviour, BaseException):
            raise behaviour
        return behaviour

    def reconcile(self, request):
        record = self.settlements.pop(0) if len(self.settlements) > 1 else self.settlements[0]
        return record(request) if callable(record) else record


class ScriptedVerifier:
    name = "test-scripted-verifier"
    security_profile = REFERENCE_SETTLEMENT_PROFILE

    def __init__(self, adapter):
        self.adapter = adapter

    def verify(self, request):
        return self.adapter.reconcile(request)


class RuntimeHardeningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self.store = SQLiteIntentStore(self.tmp.name, evidence_key=b"evidence-test-key-32-bytes-long!!!!")
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))

    def tearDown(self):
        self.store.close()

    def runtime_for(self, adapter):
        permit_authority, _ = permit_stack(self.store, self.trust)
        return FAARRuntime(
            self.store, {"mock-dex": adapter}, verification_trust(self.trust), permit_authority,
            {"mock-dex": ScriptedVerifier(adapter)}, clock=lambda: NOW, allow_test_time_override=True,
        )

    def run_case(self, runtime, i, g=None, rs=None):
        g = g or grant()
        rs = rs or risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        return runtime.process(i, AUTH, g, rs, authority_attestation=aa, risk_attestation=ra, now=NOW)

    def usage_status(self, iid):
        return next(r["status"] for r in self.store.usage("grant:test", 1) if r["intent_id"] == iid)

    def event_types(self, iid):
        return [e["event_type"] for e in self.store.evidence(iid)]

    # --- non-authoritative observations carry no weight in either direction -------

    def test_weak_none_after_confirmed_does_not_lose_the_effect(self):
        adapter = ScriptedAdapter(
            [ExecutionReceipt("effect-A", SettlementStatus.CONFIRMED, {}, Decimal("50"))],
            [_auth(SettlementStatus.CONFIRMED, "effect-A"), _weak(SettlementStatus.NONE), _auth(SettlementStatus.FINALIZED, "effect-A")],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000001")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        second = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, second.state)
        self.assertIn("SETTLEMENT_NONE_NOT_AUTHORITATIVE", second.reason_codes)
        third = self.run_case(runtime, i)
        self.assertEqual(IntentState.FINALIZED, third.state)
        self.assertEqual("effect-A", self.store.get(i.intent_id).effect_id)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))
        self.assertEqual(1, adapter.calls)

    def test_weak_positive_with_different_or_missing_effect_id_stays_unknown(self):
        for n, weak in enumerate((
            _weak(SettlementStatus.CONFIRMED, "effect-B"),
            _weak(SettlementStatus.FINALIZED, None),
        )):
            confirmed = f"effect-A{n}"  # distinct per intent: the same venue effect may back one intent only
            adapter = ScriptedAdapter(
                [ExecutionReceipt(confirmed, SettlementStatus.CONFIRMED, {}, Decimal("50"))],
                [_auth(SettlementStatus.CONFIRMED, confirmed), weak],
            )
            runtime = self.runtime_for(adapter)
            i = intent(intent_id=f"intent_hard_00000000001{n}")
            self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i, rs=risk(state_version=n + 2)).state)
            result = self.run_case(runtime, i, rs=risk(state_version=n + 2))
            self.assertEqual(IntentState.UNKNOWN, result.state)
            self.assertIn("SETTLEMENT_POSITIVE_NOT_AUTHORITATIVE", result.reason_codes)
            self.assertEqual(confirmed, self.store.get(i.intent_id).effect_id)
            self.assertEqual("HELD", self.usage_status(i.intent_id))

    # --- deterministic-failure block is durable ------------------------------------

    def test_deterministic_failure_block_survives_across_calls(self):
        adapter = ScriptedAdapter(
            [DeterministicFailure("permit rejected"), ExecutionReceipt("effect-Z", SettlementStatus.FINALIZED, {}, Decimal("50"))],
            [_auth(SettlementStatus.UNKNOWN), _auth(SettlementStatus.NONE)],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000020")
        first = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, first.state)
        self.assertIn("EXECUTION_DETERMINISTIC_FAILURE", self.store.get(i.intent_id).reason_codes)
        second = self.run_case(runtime, i)
        self.assertEqual(IntentState.FAILED_SAFE, second.state)
        self.assertEqual(("EXECUTION_DETERMINISTIC_FAILURE",), second.reason_codes)
        self.assertEqual(1, adapter.calls, "a persisted block must not be forgotten by the next worker")
        self.assertEqual(1, self.store.get(i.intent_id).submission_count)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    # --- revocation fence covers submission only ------------------------------------

    def test_revocation_completes_while_verifier_runs_after_ambiguous_submission(self):
        entered = threading.Event()
        release = threading.Event()

        def blocking_none(request):
            entered.set()
            release.wait(5)
            return _auth(SettlementStatus.NONE)(request)

        adapter = ScriptedAdapter([AmbiguousExecution("timeout")], [blocking_none, _auth(SettlementStatus.NONE)])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000030")
        results = []
        worker = threading.Thread(target=lambda: results.append(self.run_case(runtime, i)))
        worker.start()
        self.assertTrue(entered.wait(5))
        revoked = threading.Event()

        def revoke():
            self.store.set_grant_status(grant().principal_id, "grant:test", 1, "REVOKED")
            revoked.set()

        threading.Thread(target=revoke).start()
        self.assertTrue(revoked.wait(2), "settlement verification must not hold the revocation fence")
        release.set()
        worker.join(10)
        self.assertEqual(IntentState.STOPPED, results[0].state)
        self.assertIn("GRANT_NOT_ACTIVE_BEFORE_RESUBMIT", results[0].reason_codes)
        self.assertEqual(1, adapter.calls)

    # --- budget release only when no submission can have begun ---------------------

    def test_reconcile_releases_hold_for_reserved_intent_when_adapter_missing(self):
        i = intent(intent_id="intent_hard_000000000040")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        runtime, *_ = build_mock_runtime(self.store, self.trust, name="other-venue")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("ADAPTER_NOT_CONFIGURED", result.reason_codes)
        self.assertEqual(0, self.store.get(i.intent_id).submission_count)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    def test_replay_of_never_submitted_terminal_intent_releases_orphaned_hold(self):
        i = intent(intent_id="intent_hard_000000000041")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        # Simulated crash: terminal transition committed, release never ran.
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.STOPPED, reason_codes=("X",))
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        runtime, *_ = build_mock_runtime(self.store, self.trust)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertTrue(result.replayed)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    # --- every terminal decision leaves evidence ------------------------------------

    def test_grant_rejection_and_inactive_grant_are_recorded_in_evidence(self):
        runtime, *_ = build_mock_runtime(self.store, self.trust)
        broader = grant(limits=replace(grant().limits, max_order_usd=Decimal("1000000")))
        i = intent(intent_id="intent_hard_000000000050")
        result = self.run_case(runtime, i, g=broader)
        self.assertEqual(("GRANT_ENVELOPE_MISMATCH",), result.reason_codes)
        self.assertIn("grant_rejected", self.event_types(i.intent_id))
        self.assertTrue(self.store.verify_evidence_chain(i.intent_id))

        self.store.set_grant_status(grant().principal_id, "grant:test", 1, "PAUSED")
        j = intent(intent_id="intent_hard_000000000051")
        result = self.run_case(runtime, j)
        self.assertEqual(("GRANT_RUNTIME_PAUSED",), result.reason_codes)
        self.assertIn("grant_runtime_inactive", self.event_types(j.intent_id))

    def test_recovered_authorization_records_the_authorized_event(self):
        i = intent(intent_id="intent_hard_000000000052")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        runtime, venue, *_ = build_mock_runtime(self.store, self.trust)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        authorized = [e for e in self.store.evidence(i.intent_id) if e["event_type"] == "authorized"]
        self.assertEqual(1, len(authorized))
        self.assertTrue(authorized[0]["payload"]["recovered"])
        self.assertEqual(1, venue.successful_effect_count(i.intent_id))

    # --- malformed effect identity is machine-readable, never a crash ---------------

    def test_malformed_receipt_effect_id_is_recorded_not_raised(self):
        adapter = ScriptedAdapter(
            [ExecutionReceipt(b"binary-effect-id", SettlementStatus.FINALIZED, {}, Decimal("50"))],  # type: ignore[arg-type]
            [_auth(SettlementStatus.FINALIZED, "independent-effect")],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000060")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual("independent-effect", result.effect_id)
        receipt_events = [e for e in self.store.evidence(i.intent_id) if e["event_type"] == "adapter_receipt_untrusted"]
        self.assertFalse(receipt_events[0]["payload"]["reported_effect_id_well_formed"])

    def test_malformed_verifier_effect_id_stops_with_held_budget(self):
        adapter = ScriptedAdapter(
            [ExecutionReceipt("effect-A", SettlementStatus.FINALIZED, {}, Decimal("50"))],
            [_auth(SettlementStatus.FINALIZED, b"binary-effect-id")],  # type: ignore[arg-type]
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000061")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("SETTLED_EFFECT_ID_INVALID", result.reason_codes)
        self.assertIsNone(self.store.get(i.intent_id).effect_id)
        self.assertEqual("HELD", self.usage_status(i.intent_id))

    # --- public reconcile() is defensive --------------------------------------------

    def test_public_reconcile_rejects_unknown_intent_and_wrong_grant_without_mutation(self):
        runtime, *_ = build_mock_runtime(self.store, self.trust)
        with self.assertRaises(UnknownIntent):
            runtime.reconcile(intent(intent_id="intent_never_registered1"), grant=grant())

        i = intent(intent_id="intent_hard_000000000070")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        self.store.begin_submission(i.intent_id, [IntentState.RESERVED], max_attempts=2)
        result = runtime.reconcile(i, grant=grant(grant_id="grant:unprovisioned"))
        self.assertEqual(("GRANT_NOT_PROVISIONED",), result.reason_codes)
        self.assertEqual(IntentState.SUBMITTED, result.state)
        self.assertEqual(IntentState.SUBMITTED, self.store.get(i.intent_id).state)
        self.assertIsNone(self.store.intent_lease(i.intent_id))


if __name__ == "__main__":
    unittest.main()
