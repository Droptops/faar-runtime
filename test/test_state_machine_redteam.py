"""State-machine and resource personas (RT-108..RT-116).

The durable resubmission block binds every entry point and survives a worker
dying during the settlement lookup; every settlement-derived stop voids the
attempt's unconsumed permit; a cancel carrying another intent's order identity
stops instead of releasing; reconciling before submission is machine-readable;
gate reason codes and intent documents are bounded in bytes; per-intent lookups
are indexed; the orphaned-call cap is process-wide.
"""
from __future__ import annotations

import json
import threading
import time
import unittest
from datetime import timedelta
from decimal import Decimal

from faar.adapters import DeterministicFailure, MockVenue, REFERENCE_SAFE_PROFILE
from faar.canonical import canonical_hash, canonical_json
from faar.gates import evaluate_capability
from faar.models import MAX_CANONICAL_TOTAL_BYTES, ExecutionReceipt, IntentState, SettlementRecord, SettlementStatus, Verdict
from faar.runtime import FAARRuntime
from faar.settlement import MockSettlementVerifier
from faar.store import EvidenceRecordTooLarge, SQLiteIntentStore
from support import AUTH, NOW, attest_pair, grant, intent, permit_stack, risk, temp_path, trust, verification_trust
from test_runtime_hardening import ScriptedAdapter, ScriptedVerifier, _auth

AFTER_WINDOW = NOW + timedelta(seconds=10)
RECEIPT = ExecutionReceipt("order-1", SettlementStatus.PARTIALLY_FILLED, {"venue": "mock-dex"}, Decimal("20"))


class _Crash(Exception):
    pass


def _dies(request):
    # A worker dying during the settlement lookup: nothing the runtime catches.
    raise KeyboardInterrupt("worker killed during verify")


class CapturingAdapter(ScriptedAdapter):
    def execute(self, request, permit):
        self.last = (request, permit)
        return super().execute(request, permit)


class _RuntimeCase(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self), evidence_key=b"evidence-test-key-32-bytes-long!!!!")
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))
        self.permit_authority, self.permit_verifier = permit_stack(self.store, self.trust)
        self.n = 0

    def tearDown(self):
        self.store.close()

    def runtime_for(self, adapter):
        return FAARRuntime(
            self.store, {"mock-dex": adapter}, verification_trust(self.trust), self.permit_authority,
            {"mock-dex": ScriptedVerifier(adapter)}, clock=lambda: NOW, allow_test_time_override=True,
        )

    def auth(self, i, now=NOW):
        self.n += 1
        rs = risk(state_version=self.n, observed_at=now)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, now)
        return rs, aa, ra

    def run_case(self, runtime, i, now=NOW):
        rs, aa, ra = self.auth(i, now)
        return runtime.process(i, AUTH, grant(), rs, authority_attestation=aa, risk_attestation=ra, now=now)

    def usage_status(self, intent_id):
        rows = [r for r in self.store.usage("grant:test", 1) if r["intent_id"] == intent_id]
        return rows[0]["status"] if rows else None

    def events(self, intent_id):
        return [e["event_type"] for e in self.store.evidence(intent_id)]


class DurableBlockTests(_RuntimeCase):
    def _rejected(self, adapter, iid):
        runtime = self.runtime_for(adapter)
        i = intent(intent_id=iid)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, result.state)
        self.assertEqual(("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", "EXECUTION_DETERMINISTIC_FAILURE"), result.reason_codes)
        self.assertEqual(1, adapter.calls)
        return runtime, i

    def test_public_reconcile_with_fresh_authorization_honours_the_block(self):
        adapter = ScriptedAdapter([DeterministicFailure("rejected"), RECEIPT], [_auth(SettlementStatus.NONE)])
        runtime, i = self._rejected(adapter, "intent_block_0000000000001")
        rs, aa, ra = self.auth(i, AFTER_WINDOW)
        result = runtime.reconcile(
            i, grant=grant(), authority=AUTH, risk=rs, authority_attestation=aa, risk_attestation=ra, now=AFTER_WINDOW,
        )
        self.assertEqual(IntentState.FAILED_SAFE, result.state)
        self.assertEqual(("EXECUTION_DETERMINISTIC_FAILURE",), result.reason_codes)
        self.assertEqual(1, adapter.calls, "a blocked intent is never resubmitted through reconcile()")
        self.assertEqual(1, self.store.get(i.intent_id).submission_count)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))
        self.assertEqual(1, self.store.voided_permit_count(i.intent_id))

    def test_bare_reconcile_keeps_the_block_on_the_row(self):
        adapter = ScriptedAdapter([DeterministicFailure("rejected"), RECEIPT], [_auth(SettlementStatus.NONE)])
        runtime, i = self._rejected(adapter, "intent_block_0000000000002")
        bare = runtime.reconcile(i, grant=grant(), now=NOW)
        self.assertEqual(IntentState.UNKNOWN, bare.state)
        self.assertIn("EXECUTION_DETERMINISTIC_FAILURE", self.store.get(i.intent_id).reason_codes)
        after = self.run_case(runtime, i, AFTER_WINDOW)
        self.assertEqual(IntentState.FAILED_SAFE, after.state)
        self.assertEqual(("EXECUTION_DETERMINISTIC_FAILURE",), after.reason_codes)
        self.assertEqual(1, adapter.calls)

    def test_block_survives_a_worker_dying_during_the_settlement_lookup(self):
        adapter = ScriptedAdapter(
            [DeterministicFailure("rejected"), RECEIPT],
            [_auth(SettlementStatus.NONE), _dies, _auth(SettlementStatus.NONE)],
        )
        runtime, i = self._rejected(adapter, "intent_block_0000000000003")
        with self.assertRaises(KeyboardInterrupt):
            self.run_case(runtime, i, AFTER_WINDOW)
        stored = self.store.get(i.intent_id)
        self.assertEqual(IntentState.RECONCILING, stored.state)
        self.assertIn("EXECUTION_DETERMINISTIC_FAILURE", stored.reason_codes, "the block is durable through RECONCILING")
        self.assertEqual([], self.store.list_leases() if hasattr(self.store, "list_leases") else [])
        result = self.run_case(runtime, i, AFTER_WINDOW)
        self.assertEqual(IntentState.FAILED_SAFE, result.state)
        self.assertEqual(("EXECUTION_DETERMINISTIC_FAILURE",), result.reason_codes)
        self.assertEqual(1, adapter.calls)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    def test_reconcile_before_submission_is_machine_readable_and_mutates_nothing(self):
        runtime = self.runtime_for(ScriptedAdapter([RECEIPT], [_auth(SettlementStatus.NONE)]))
        i = intent(intent_id="intent_block_0000000000004")
        self.store.register(i, canonical_hash(i))
        result = runtime.reconcile(i, grant=grant(), now=NOW)
        self.assertEqual(IntentState.PROPOSED, result.state)
        self.assertEqual(("RECONCILE_NOT_APPLICABLE_BEFORE_SUBMISSION",), result.reason_codes)
        self.assertTrue(result.replayed)
        stored = self.store.get(i.intent_id)
        self.assertEqual((IntentState.PROPOSED, ()), (stored.state, stored.reason_codes))
        self.assertEqual(["intent_registered"], self.events(i.intent_id))


class StopVoidsPermitsTests(_RuntimeCase):
    def test_settlement_derived_stops_void_the_live_permit(self):
        cases = (
            (_auth(SettlementStatus.CONTRADICTORY, None, None), "SETTLEMENT_CONTRADICTORY"),
            (_auth(SettlementStatus.FINALIZED, "fx-over", "60"), "SETTLED_AMOUNT_EXCEEDS_AUTHORIZED"),
            (_auth(SettlementStatus.FINALIZED, None, "50"), "SETTLED_EFFECT_ID_REQUIRED"),
        )
        for n, (record, reason) in enumerate(cases):
            inner = MockVenue(permit_verifier=self.permit_verifier, name="mock-dex", clock=lambda: NOW)
            adapter = CapturingAdapter([RECEIPT], [record])
            runtime = self.runtime_for(adapter)
            i = intent(intent_id=f"intent_void_000000000000{n}")
            result = self.run_case(runtime, i)
            self.assertEqual(IntentState.STOPPED, result.state, reason)
            self.assertEqual((reason,), result.reason_codes)
            self.assertEqual("HELD", self.usage_status(i.intent_id))
            self.assertEqual((1, 0), self.store.permit_counts(i.intent_id))
            self.assertEqual(1, self.store.voided_permit_count(i.intent_id), reason)
            self.assertIn("permits_voided", self.events(i.intent_id))
            # The transported permit can no longer land late at the venue.
            request, permit = adapter.last
            with self.assertRaisesRegex(DeterministicFailure, "PERMIT_VOIDED"):
                inner.execute(request, permit)
            self.assertEqual(0, inner.successful_effect_count(i.intent_id))

    def test_cancel_carrying_another_intents_order_identity_stops(self):
        owner_adapter = ScriptedAdapter([RECEIPT], [_auth(SettlementStatus.FINALIZED, "fx-shared", "50")])
        owner = intent(intent_id="intent_claim_000000000001")
        self.assertEqual(IntentState.FINALIZED, self.run_case(self.runtime_for(owner_adapter), owner).state)

        thief_adapter = ScriptedAdapter([RECEIPT, RECEIPT], [_auth(SettlementStatus.CANCELLED, "fx-shared", None)])
        runtime = self.runtime_for(thief_adapter)
        thief = intent(intent_id="intent_claim_000000000002")
        result = self.run_case(runtime, thief)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertEqual(("EFFECT_ID_ALREADY_CLAIMED",), result.reason_codes)
        self.assertEqual("HELD", self.usage_status(thief.intent_id))
        self.assertIsNone(self.store.get(thief.intent_id).effect_id)
        self.assertEqual(1, thief_adapter.calls)
        self.assertEqual("intent_claim_000000000001", self.store.effect_owner("mock-dex", "fx-shared"))


class ReasonCodeBoundsTests(_RuntimeCase):
    def test_gate_reason_codes_never_carry_untrusted_content_verbatim(self):
        unknown = {("field%03d" % n) + "y" * 90: 1 for n in range(200)}
        junk = 'spaces "quotes" and ☃ ' * 100
        i = intent(payload={**intent().payload, "from_asset": junk, **unknown})
        decision = evaluate_capability(i, grant(), NOW)
        self.assertEqual(Verdict.DENY, decision.verdict)
        fields = next(r for r in decision.reason_codes if r.startswith("UNKNOWN_EXECUTION_FIELDS:"))
        assets = next(r for r in decision.reason_codes if r.startswith("ASSET_NOT_ALLOWED:"))
        self.assertLess(len(fields), 400)
        self.assertTrue(fields.endswith(",+192"), fields)
        self.assertLess(len(assets), 80)
        self.assertNotIn('"', assets)
        self.assertNotIn(" ", assets)
        self.assertNotIn("☃", assets)
        for code in decision.reason_codes:
            self.assertLessEqual(len(code), 400, code)

        runtime = self.runtime_for(ScriptedAdapter([RECEIPT], [_auth(SettlementStatus.NONE)]))
        j = intent(intent_id="intent_reason_00000000001", payload=i.payload)
        result = self.run_case(runtime, j)
        self.assertEqual(IntentState.DENIED, result.state)
        for event in self.store.evidence(j.intent_id):
            self.assertLess(len(json.dumps(event["payload"])), 8192, event["event_type"])
        self.assertLess(len(json.dumps(list(self.store.get(j.intent_id).reason_codes))), 4096)

    def test_store_refuses_oversized_reason_codes_and_evidence_rows(self):
        i = intent(intent_id="intent_reason_00000000002")
        self.store.register(i, canonical_hash(i))
        with self.assertRaises(EvidenceRecordTooLarge):
            self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.DENIED, reason_codes=("x" * 70_000,))
        self.assertEqual(IntentState.PROPOSED, self.store.get(i.intent_id).state)
        with self.assertRaises(EvidenceRecordTooLarge):
            self.store.add_evidence(i.intent_id, "blob", {"blob": ["y" * 8000] * 40})
        self.assertEqual(["intent_registered"], self.events(i.intent_id))
        self.assertTrue(self.store.evidence_status(i.intent_id)["valid"])


class IntentByteBudgetTests(unittest.TestCase):
    def test_intent_documents_are_bounded_in_bytes_not_only_nodes(self):
        self.assertEqual(65_536, MAX_CANONICAL_TOTAL_BYTES)
        big = ["a" * 8000] * 9  # 72 000 bytes over 9 nodes: far below the node budget
        with self.assertRaises(ValueError):
            intent(payload={**intent().payload, "notes": big})
        with self.assertRaises(ValueError):
            intent(metadata={"notes": big})
        with self.assertRaises(ValueError):
            intent(payload={**intent().payload, "☃" * 8000: 1, "b": ["☃" * 8000] * 2})  # 3-byte chars
        ok = intent(payload={**intent().payload, "notes": ["a" * 8000] * 7})
        self.assertLess(len(canonical_json(ok).encode("utf-8")), 2 * MAX_CANONICAL_TOTAL_BYTES)
        with self.assertRaises(ValueError):
            SettlementRecord(SettlementStatus.FINALIZED, effect_id="fx", amount_usd=Decimal("1"), evidence={"k": big}, authoritative=True)


class IndexCoverageTests(unittest.TestCase):
    def test_per_intent_and_window_lookups_use_indexes(self):
        store = SQLiteIntentStore(temp_path(self))
        try:
            def plan(sql, *params):
                return " ".join(str(row[3]) for row in store._conn.execute("EXPLAIN QUERY PLAN " + sql, params))
            self.assertIn("ix_evidence_intent_id", plan("SELECT COUNT(*), MAX(id) FROM evidence WHERE intent_id=?", "x"))
            self.assertIn("ix_permits_intent", plan("SELECT permit_id FROM execution_permits WHERE intent_id=? AND consumed_at IS NULL", "x"))
            self.assertIn(
                "ix_usage_velocity_status",
                plan("SELECT amount_usd FROM usage_reservations WHERE status IN ('HELD','COMMITTED') AND velocity_ts >= ?", 0),
            )
        finally:
            store.close()


class OrphanCapScopeTests(_RuntimeCase):
    def test_the_orphan_cap_is_process_wide(self):
        inner = MockVenue(permit_verifier=self.permit_verifier, name="mock-dex", clock=lambda: NOW)
        gate = threading.Event()

        class HangingVenue:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE

            def execute(self, request, permit):
                if not gate.wait(10):
                    raise AssertionError("test never released the hanging venue")
                return inner.execute(request, permit)

        def make_runtime():
            return FAARRuntime(
                self.store, {"mock-dex": HangingVenue()}, verification_trust(self.trust), self.permit_authority,
                {"mock-dex": MockSettlementVerifier(inner)}, clock=lambda: NOW, allow_test_time_override=True,
                adapter_deadline_seconds=0.05, max_orphaned_adapter_calls=2,
            )

        first, second = make_runtime(), make_runtime()
        try:
            for n in (1, 2):
                result = self.run_case(first, intent(intent_id=f"intent_scope_00000000000{n}"))
                self.assertEqual(IntentState.UNKNOWN, result.state)
            self.assertEqual(2, first.orphaned_adapter_calls)
            self.assertEqual(2, second.orphaned_adapter_calls, "the count is shared by every runtime in the process")
            third = self.run_case(second, intent(intent_id="intent_scope_000000000003"))
            self.assertEqual(IntentState.STOPPED, third.state)
            self.assertEqual(("ADAPTER_ORPHAN_LIMIT_REACHED",), third.reason_codes)
            self.assertEqual(2, sum(1 for t in threading.enumerate() if t.name.startswith("faar-adapter-")))
        finally:
            gate.set()
            deadline = time.monotonic() + 5
            while first.orphaned_adapter_calls and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertEqual(0, second.orphaned_adapter_calls)


if __name__ == "__main__":
    unittest.main()
