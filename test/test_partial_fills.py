"""Partial fills and cancellation (release gates 4.4, 6.7; residual risk R-14).

An order can rest on the book partially filled, fill completely later, or be
cancelled with or without a fill. None of those may ever cause a second attempt
for the remainder under the same intent (I-3), and the ledger must end in a
state that matches what settled.
"""
from __future__ import annotations

import unittest
from decimal import Decimal

from faar.adapters import DeterministicFailure, MockMode
from faar.canonical import canonical_hash
from faar.models import EconomicPrimitive, ExecutionReceipt, ExecutionRequest, IntentState, SettlementRecord, SettlementStatus
from faar.runtime import FAARRuntime
from faar.settlement import QuorumSettlementVerifier, REFERENCE_SETTLEMENT_PROFILE
from faar.store import SQLiteIntentStore
from support import AUTH, NOW, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, temp_path, trust, verification_trust
from test_runtime_hardening import ScriptedAdapter, ScriptedVerifier, _auth, _weak

RECEIPT = ExecutionReceipt("order-1", SettlementStatus.PARTIALLY_FILLED, {"venue": "mock-dex"}, Decimal("20"))


class PartialFillTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self), evidence_key=b"evidence-test-key-32-bytes-long!!!!")
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))
        self.n = 0

    def tearDown(self):
        self.store.close()

    def runtime_for(self, adapter):
        permit_authority, _ = permit_stack(self.store, self.trust)
        return FAARRuntime(
            self.store, {"mock-dex": adapter}, verification_trust(self.trust), permit_authority,
            {"mock-dex": ScriptedVerifier(adapter)}, clock=lambda: NOW, allow_test_time_override=True,
        )

    def run_case(self, runtime, i, now=NOW, primitive=None):
        self.n += 1
        rs = risk(state_version=self.n, observed_at=now)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, now)
        return runtime.process(i, AUTH, grant(), rs, authority_attestation=aa, risk_attestation=ra, now=now)

    def usage_status(self, intent_id):
        rows = [r for r in self.store.usage("grant:test", 1) if r["intent_id"] == intent_id]
        return rows[0]["status"] if rows else None

    def events(self, intent_id):
        return [e["event_type"] for e in self.store.evidence(intent_id)]

    # --- open partial fill, later completed ------------------------------------------

    def test_partial_fill_confirms_with_its_effect_and_never_resubmits(self):
        adapter = ScriptedAdapter(
            [RECEIPT, DeterministicFailure("must not be called again")],
            [_auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "20"), _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "30"),
             _auth(SettlementStatus.FINALIZED, "order-1", "50")],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_partial_00000000001")
        first = self.run_case(runtime, i)
        self.assertEqual(IntentState.CONFIRMED, first.state)
        self.assertEqual("order-1", first.effect_id)
        self.assertEqual(("SETTLEMENT_PARTIAL_FILL_OPEN",), first.reason_codes)
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        self.assertIn("partial_fill", self.events(i.intent_id))
        second = self.run_case(runtime, i)  # fills a bit more, still open
        self.assertEqual(IntentState.CONFIRMED, second.state)
        self.assertEqual("order-1", self.store.get(i.intent_id).effect_id)
        third = self.run_case(runtime, i)
        self.assertEqual(IntentState.FINALIZED, third.state)
        self.assertEqual("order-1", third.effect_id)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))
        self.assertEqual(1, adapter.calls, "the remainder is never a second attempt")
        self.assertEqual(1, self.store.get(i.intent_id).submission_count)

    def test_cancel_after_partial_fill_finalizes_the_filled_effect(self):
        adapter = ScriptedAdapter(
            [RECEIPT],
            [_auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "20"), _auth(SettlementStatus.CANCELLED, "order-1", "20")],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_partial_00000000002")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        done = self.run_case(runtime, i)
        self.assertEqual(IntentState.FINALIZED, done.state)
        self.assertEqual("order-1", done.effect_id)
        self.assertEqual(("SETTLEMENT_CANCELLED_AFTER_PARTIAL_FILL",), done.reason_codes)
        row = next(r for r in self.store.usage("grant:test", 1) if r["intent_id"] == i.intent_id)
        self.assertEqual(("COMMITTED", "50"), (row["status"], row["amount_usd"]), "the authorized notional stays committed (conservative)")
        self.assertIn("cancelled_after_partial_fill", self.events(i.intent_id))
        self.assertEqual(1, adapter.calls)
        # Replay is terminal and stable.
        self.assertEqual(IntentState.FINALIZED, self.run_case(runtime, i).state)

    def test_cancel_without_fill_fails_safe_releases_and_never_resubmits(self):
        adapter = ScriptedAdapter(
            [RECEIPT, DeterministicFailure("must not be called again")],
            [_auth(SettlementStatus.CANCELLED, "order-1", None)],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_partial_00000000003")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.FAILED_SAFE, result.state)
        self.assertEqual(("SETTLEMENT_CANCELLED_UNFILLED",), result.reason_codes)
        self.assertIsNone(self.store.get(i.intent_id).effect_id)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))
        replay = self.run_case(runtime, i)
        self.assertEqual(IntentState.FAILED_SAFE, replay.state)
        self.assertTrue(replay.replayed)
        self.assertEqual(1, adapter.calls, "a cancelled order is terminal for this intent; a new intent is required")
        # Zero filled amount reported explicitly is the same case.
        adapter2 = ScriptedAdapter([RECEIPT], [_auth(SettlementStatus.CANCELLED, "order-2", "0")])
        j = intent(intent_id="intent_partial_00000000004")
        self.assertEqual(IntentState.FAILED_SAFE, self.run_case(self.runtime_for(adapter2), j).state)

    def test_cancel_reporting_no_fill_after_a_recorded_fill_stops(self):
        adapter = ScriptedAdapter(
            [RECEIPT],
            [_auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "20"), _auth(SettlementStatus.CANCELLED, "order-1", "0")],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_partial_00000000005")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertEqual(("SETTLEMENT_CANCEL_CONTRADICTS_RECORDED_EFFECT",), result.reason_codes)
        self.assertEqual("order-1", self.store.get(i.intent_id).effect_id)
        self.assertEqual("HELD", self.usage_status(i.intent_id))

    def test_recorded_partial_fill_then_authoritative_none_stops(self):
        adapter = ScriptedAdapter(
            [RECEIPT],
            [_auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "20"), _auth(SettlementStatus.NONE)],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_partial_00000000006")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertEqual(("SETTLEMENT_LOST_PREVIOUS_EFFECT",), result.reason_codes)
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        self.assertEqual(1, adapter.calls)

    def test_weak_partial_or_cancel_observations_carry_no_weight(self):
        for n, (weak, reason) in enumerate((
            (_weak(SettlementStatus.PARTIALLY_FILLED, "order-1", "20"), "SETTLEMENT_POSITIVE_NOT_AUTHORITATIVE"),
            (_weak(SettlementStatus.CANCELLED, "order-1", "0"), "SETTLEMENT_CANCEL_NOT_AUTHORITATIVE"),
        )):
            adapter = ScriptedAdapter([RECEIPT, DeterministicFailure("no retry on weak evidence")], [weak])
            runtime = self.runtime_for(adapter)
            i = intent(intent_id=f"intent_partial_0000000001{n}")
            result = self.run_case(runtime, i)
            self.assertEqual(IntentState.UNKNOWN, result.state)
            self.assertIn(reason, result.reason_codes)
            self.assertEqual("HELD", self.usage_status(i.intent_id))
            self.assertIsNone(self.store.get(i.intent_id).effect_id)
            self.assertEqual(1, adapter.calls)

    def test_partial_fill_integrity_checks(self):
        cases = (
            (_auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "60"), "SETTLED_AMOUNT_EXCEEDS_AUTHORIZED"),
            (_auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "-1"), "SETTLED_AMOUNT_INVALID"),
            (_auth(SettlementStatus.PARTIALLY_FILLED, None, "20"), "SETTLED_EFFECT_ID_REQUIRED"),
            (_auth(SettlementStatus.CANCELLED, None, "0"), "SETTLED_EFFECT_ID_REQUIRED"),
            (_auth(SettlementStatus.CANCELLED, "order-1", "60"), "SETTLED_AMOUNT_EXCEEDS_AUTHORIZED"),
            (_auth(SettlementStatus.CANCELLED, "order-1", "-1"), "SETTLED_AMOUNT_INVALID"),
        )
        for n, (record, reason) in enumerate(cases):
            adapter = ScriptedAdapter([RECEIPT], [record])
            runtime = self.runtime_for(adapter)
            i = intent(intent_id=f"intent_partial_0000000002{n}")
            result = self.run_case(runtime, i)
            self.assertEqual(IntentState.STOPPED, result.state, reason)
            self.assertEqual((reason,), result.reason_codes)
            self.assertEqual("HELD", self.usage_status(i.intent_id), reason)

    def test_pay_cannot_partially_fill(self):
        pay_grant = grant(grant_id="grant:pay", allowed_primitives=frozenset({EconomicPrimitive.SWAP, EconomicPrimitive.PAY}))
        self.store.provision_grant(pay_grant, canonical_hash(pay_grant))
        for n, record in enumerate((
            _auth(SettlementStatus.PARTIALLY_FILLED, "pay-1", "20"),
            _auth(SettlementStatus.CANCELLED, "pay-1", "20"),
        )):
            adapter = ScriptedAdapter([ExecutionReceipt("pay-1", SettlementStatus.PARTIALLY_FILLED, {}, Decimal("20"))], [record])
            runtime = self.runtime_for(adapter)
            i = intent(
                intent_id=f"intent_partial_0000000003{n}", primitive=EconomicPrimitive.PAY, grant_id="grant:pay",
                payload={"amount_usd": "50", "asset": "USDC", "target": "router:approved"},
            )
            self.n += 1
            rs = risk(state_version=self.n)
            aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
            result = runtime.process(i, AUTH, pay_grant, rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
            self.assertEqual(IntentState.STOPPED, result.state)
            self.assertEqual(("PAYMENT_PARTIAL_NOT_ALLOWED",), result.reason_codes)

    # --- reference venue end to end --------------------------------------------------

    def test_mock_venue_partial_fill_completes_or_cancels_without_a_second_order(self):
        for n, terminal in enumerate(("complete", "cancel")):
            runtime, venue, _, _, _ = build_mock_runtime(self.store, self.trust, mode=MockMode.PARTIAL_FILL)
            i = intent(intent_id=f"intent_partial_0000000004{n}")
            request = ExecutionRequest.from_intent(i)
            first = self.run_case(runtime, i)
            self.assertEqual(IntentState.CONFIRMED, first.state)
            self.assertEqual(Decimal("25"), venue.lookup_effect(request).amount_usd)
            self.assertEqual("HELD", self.usage_status(i.intent_id))
            again = self.run_case(runtime, i)
            self.assertEqual(IntentState.CONFIRMED, again.state, "still resting: reconcile again later")
            if terminal == "complete":
                venue.complete_fill(request)
                expected = ()
            else:
                venue.cancel_order(request)
                expected = ("SETTLEMENT_CANCELLED_AFTER_PARTIAL_FILL",)
            done = self.run_case(runtime, i)
            self.assertEqual(IntentState.FINALIZED, done.state)
            self.assertEqual(expected, done.reason_codes)
            self.assertEqual("COMMITTED", self.usage_status(i.intent_id))
            self.assertEqual(1, venue.execute_call_count(i.intent_id))
            self.assertEqual(1, venue.successful_effect_count(i.intent_id))

    def test_quorum_agrees_on_partial_fills_and_contests_differing_fills(self):
        request = ExecutionRequest.from_intent(intent())

        def src(name, record):
            class Source:
                security_profile = REFERENCE_SETTLEMENT_PROFILE

                def __init__(self):
                    self.name = name

                def verify(self, req):
                    return record(req)
            return Source()

        same = QuorumSettlementVerifier(
            [src("a", _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "20")), src("b", _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "20.00"))],
            quorum=2,
        ).verify(request)
        self.assertEqual(SettlementStatus.PARTIALLY_FILLED, same.status)
        self.assertEqual("order-1", same.effect_id)
        differ = QuorumSettlementVerifier(
            [src("a", _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "20")), src("b", _auth(SettlementStatus.CANCELLED, "order-1", "20"))],
            quorum=2,
        ).verify(request)
        self.assertEqual(SettlementStatus.CONTRADICTORY, differ.status)


if __name__ == "__main__":
    unittest.main()
