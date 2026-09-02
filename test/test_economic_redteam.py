"""Economic-logic persona (RT-101..RT-107).

Aggregate limits that survive budget releases and grant versions, an executor-side
slippage bound carried in the hash-bound request, ownership agreement between the
two risk ledgers, cumulative-fill monotonicity, open (admitted, unfilled) orders,
and JSON numbers in the money grammar.
"""
from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

from faar.adapters import MockMode
from faar.canonical import canonical_hash, parse_bounded_decimal
from faar.gates import evaluate_capability
from faar.models import EconomicPrimitive, ExecutionReceipt, ExecutionRequest, IntentState, SettlementRecord, SettlementStatus, Verdict
from faar.runtime import FAARRuntime
from faar.store import SQLiteIntentStore
from support import AUTH, NOW, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, temp_path, trust, verification_trust
from test_runtime_hardening import ScriptedAdapter, ScriptedVerifier, _auth

RECEIPT = ExecutionReceipt("order-1", SettlementStatus.PARTIALLY_FILLED, {"venue": "mock-dex"}, Decimal("20"))
RECEIPT_OPEN = ExecutionReceipt("order-1", SettlementStatus.PARTIALLY_FILLED, {"venue": "mock-dex"}, Decimal("0"))


def _cancelled_per_intent(request):
    return SettlementRecord(
        SettlementStatus.CANCELLED, effect_id="order-" + request.intent_id[-4:], amount_usd=None,
        evidence={"source": "independent"}, authoritative=True, verified_request_hash=canonical_hash(request),
    )


class _RuntimeCase(unittest.TestCase):
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

    def run_case(self, runtime, i, g=None, now=NOW):
        g = g or grant()
        self.n += 1
        rs = risk(state_version=self.n, observed_at=now)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, now)
        return runtime.process(i, AUTH, g, rs, authority_attestation=aa, risk_attestation=ra, now=now)

    def usage_status(self, intent_id, grant_id="grant:test", version=1):
        rows = [r for r in self.store.usage(grant_id, version) if r["intent_id"] == intent_id]
        return rows[0]["status"] if rows else None

    def events(self, intent_id):
        return [e["event_type"] for e in self.store.evidence(intent_id)]


class VelocityBoundsVenueAttemptsTests(_RuntimeCase):
    def test_cancelled_unfilled_attempts_keep_their_velocity_slot(self):
        tight = grant(grant_id="grant:velocity", limits=replace(grant().limits, max_actions_per_window=2))
        self.store.provision_grant(tight, canonical_hash(tight))
        # Each intent's order has its own identity at the venue.
        adapter = ScriptedAdapter([RECEIPT, RECEIPT, RECEIPT], [_cancelled_per_intent])
        runtime = self.runtime_for(adapter)
        for n in (1, 2):
            i = intent(intent_id=f"intent_econ_00000000000{n}", grant_id="grant:velocity")
            result = self.run_case(runtime, i, g=tight)
            self.assertEqual(IntentState.FAILED_SAFE, result.state)
            self.assertEqual(("SETTLEMENT_CANCELLED_UNFILLED",), result.reason_codes)
            self.assertEqual("RELEASED", self.usage_status(i.intent_id, "grant:velocity"))
        # Two orders reached the venue inside the window; the budget they released
        # does not give a third order its slot back.
        third = self.run_case(runtime, intent(intent_id="intent_econ_000000000003", grant_id="grant:velocity"), g=tight)
        self.assertEqual(IntentState.DEFERRED, third.state)
        self.assertIn("ATOMIC_ACTION_VELOCITY_EXCEEDED", third.reason_codes)
        self.assertEqual(2, adapter.calls)
        # The slot frees once the window has passed.
        later = NOW + timedelta(seconds=61)
        fourth = self.run_case(
            runtime,
            intent(
                intent_id="intent_econ_000000000004", grant_id="grant:velocity",
                created_at=later - timedelta(seconds=1), expires_at=later + timedelta(seconds=14),
            ),
            g=tight, now=later,
        )
        self.assertEqual(IntentState.FAILED_SAFE, fourth.state)
        self.assertEqual(3, adapter.calls)

    def test_store_counts_submitted_rows_after_release_but_not_unsubmitted_ones(self):
        def reserve(g, iid, version, now=NOW):
            i = intent(intent_id=iid, grant_id=g.grant_id)
            self.store.register(i, canonical_hash(i))
            return self.store.reserve_usage(i, g, risk(state_version=version), now)

        # A released reservation that never reached a venue frees its slot.
        a = grant(grant_id="grant:vel-a", limits=replace(grant().limits, max_actions_per_window=2))
        self.store.provision_grant(a, canonical_hash(a))
        self.assertTrue(reserve(a, "intent_vela_00000000000001", 1)[0])
        self.store.release_usage("intent_vela_00000000000001")
        self.assertTrue(reserve(a, "intent_vela_00000000000002", 2)[0])
        self.assertTrue(reserve(a, "intent_vela_00000000000003", 3)[0])

        # A released reservation that reached a venue keeps counting.
        b = grant(grant_id="grant:vel-b", limits=replace(grant().limits, max_actions_per_window=2))
        self.store.provision_grant(b, canonical_hash(b))
        self.assertTrue(reserve(b, "intent_velb_00000000000001", 1)[0])
        self.store.transition("intent_velb_00000000000001", IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition("intent_velb_00000000000001", IntentState.AUTHORIZED, IntentState.RESERVED)
        started, _, _ = self.store.begin_submission("intent_velb_00000000000001", [IntentState.RESERVED], max_attempts=2)
        self.assertTrue(started)
        self.store.release_usage("intent_velb_00000000000001")
        row = next(r for r in self.store.usage("grant:vel-b", 1) if r["intent_id"] == "intent_velb_00000000000001")
        self.assertEqual(("RELEASED", 1), (row["status"], row["submitted"]))
        self.assertTrue(reserve(b, "intent_velb_00000000000002", 2)[0])
        ok, reasons = reserve(b, "intent_velb_00000000000003", 3)
        self.assertFalse(ok)
        self.assertEqual(("ATOMIC_ACTION_VELOCITY_EXCEEDED",), reasons)


class WindowsSpanGrantVersionsTests(_RuntimeCase):
    def test_new_grant_version_does_not_restart_turnover_or_velocity_windows(self):
        limits = replace(
            grant().limits, max_daily_turnover_usd=Decimal("100"), max_actions_per_window=1, action_window_seconds=3600,
        )
        v1 = grant(grant_id="grant:rotate", limits=limits)
        v2 = replace(v1, version=2)
        for g in (v1, v2):
            self.store.provision_grant(g, canonical_hash(g))

        def reserve(iid, g, version, now=NOW):
            i = intent(
                intent_id=iid, grant_id=g.grant_id, grant_version=g.version,
                payload={**intent().payload, "amount_usd": "75"},
            )
            self.store.register(i, canonical_hash(i))
            return self.store.reserve_usage(i, g, risk(state_version=version), now)

        self.assertTrue(reserve("intent_rot_00000000000001", v1, 1)[0])
        ok, reasons = reserve("intent_rot_00000000000002", v2, 1)
        self.assertFalse(ok)
        self.assertLessEqual({"ATOMIC_DAILY_TURNOVER_EXCEEDED", "ATOMIC_ACTION_VELOCITY_EXCEEDED"}, set(reasons))
        # Outside both trailing windows the new version reserves normally.
        self.assertTrue(reserve("intent_rot_00000000000003", v2, 2, NOW + timedelta(days=1, seconds=1))[0])


class ExecutorSideSlippageBoundTests(_RuntimeCase):
    def test_capped_grant_requires_a_bound_no_looser_than_the_cap(self):
        g = grant()  # max_slippage_bps=75
        without = intent(payload={k: v for k, v in intent().payload.items() if k != "max_slippage_bps"})
        decision = evaluate_capability(without, g, NOW)
        self.assertEqual(Verdict.DENY, decision.verdict)
        self.assertIn("PAYLOAD_FIELD_REQUIRED:max_slippage_bps", decision.reason_codes)
        for ok in (0, 50, 75):
            self.assertEqual(Verdict.ALLOW, evaluate_capability(intent(payload={**intent().payload, "max_slippage_bps": ok}), g, NOW).verdict, ok)
        looser = evaluate_capability(intent(payload={**intent().payload, "max_slippage_bps": 76}), g, NOW)
        self.assertEqual(Verdict.DENY, looser.verdict)
        self.assertIn("SLIPPAGE_BOUND_EXCEEDS_GRANT", looser.reason_codes)
        for bad in ("50", True, -1, 10_001, 5.5, None):
            decision = evaluate_capability(intent(payload={**intent().payload, "max_slippage_bps": bad}), g, NOW)
            self.assertEqual(Verdict.DENY, decision.verdict, repr(bad))
            self.assertIn("SLIPPAGE_BOUND_INVALID", decision.reason_codes, repr(bad))
        # A grant that allows a traded primitive cannot omit the cap: a missing
        # financial limit never reads as infinity.
        with self.assertRaisesRegex(ValueError, "max_slippage_bps"):
            grant(limits=replace(grant().limits, max_slippage_bps=None))
        pay_only = grant(allowed_primitives=frozenset({EconomicPrimitive.PAY}), limits=replace(grant().limits, max_slippage_bps=None))
        self.assertIsNone(pay_only.limits.max_slippage_bps)

    def test_orders_may_carry_a_limit_price_instead(self):
        g = grant(allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_assets=frozenset({"BTC", "USD"}))
        base = {"base_asset": "BTC", "quote_asset": "USD", "notional_usd": "10", "target": "router:approved"}
        market = evaluate_capability(intent(primitive=EconomicPrimitive.BUY, payload=base), g, NOW)
        self.assertIn("PAYLOAD_FIELD_REQUIRED:max_slippage_bps", market.reason_codes)
        for bounded in ({**base, "order_type": "limit", "limit_price": "60000"}, {**base, "max_slippage_bps": 10}):
            self.assertEqual(Verdict.ALLOW, evaluate_capability(intent(primitive=EconomicPrimitive.BUY, payload=bounded), g, NOW).verdict)
        # A limit price only bounds a limit order; a market order carrying one still
        # needs the slippage bound.
        for market in ({**base, "limit_price": "60000"}, {**base, "order_type": "market", "limit_price": "60000"}):
            decision = evaluate_capability(intent(primitive=EconomicPrimitive.BUY, payload=market), g, NOW)
            self.assertIn("PAYLOAD_FIELD_REQUIRED:max_slippage_bps", decision.reason_codes)
        for bad in ("0", "-1", "abc", "1e5", 60000.123456789):
            decision = evaluate_capability(intent(primitive=EconomicPrimitive.BUY, payload={**base, "order_type": "limit", "limit_price": bad}), g, NOW)
            self.assertIn("LIMIT_PRICE_INVALID", decision.reason_codes, repr(bad))

    def test_bound_travels_in_the_hash_bound_request(self):
        i = intent()
        req = ExecutionRequest.from_intent(i)
        self.assertEqual(50, req.payload["max_slippage_bps"])
        looser = ExecutionRequest.from_intent(intent(payload={**i.payload, "max_slippage_bps": 75}))
        self.assertNotEqual(canonical_hash(req), canonical_hash(looser))

    def test_runtime_denies_an_unbounded_swap_before_the_adapter(self):
        adapter = ScriptedAdapter([RECEIPT], [_auth(SettlementStatus.FINALIZED, "order-1")])
        runtime = self.runtime_for(adapter)
        i = intent(
            intent_id="intent_slip_00000000000001",
            payload={k: v for k, v in intent().payload.items() if k != "max_slippage_bps"},
        )
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.DENIED, result.state)
        self.assertIn("PAYLOAD_FIELD_REQUIRED:max_slippage_bps", result.reason_codes)
        self.assertEqual(0, adapter.calls)


class RiskVersionOwnershipTests(_RuntimeCase):
    def test_reservation_refuses_a_version_the_permit_ledger_bound_to_another_intent(self):
        a = intent(intent_id="intent_own_00000000000001")
        b = intent(intent_id="intent_own_00000000000002")
        for i in (a, b):
            self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(a, grant(), risk(state_version=1), NOW)[0])
        self.assertTrue(self.store.claim_permit_risk_state(a, grant(), risk(state_version=2))[0])
        ok, reasons = self.store.reserve_usage(b, grant(), risk(state_version=2), NOW)
        self.assertFalse(ok)
        self.assertEqual(("RISK_STATE_VERSION_ALREADY_CLAIMED",), reasons)
        self.assertIsNone(self.usage_status(b.intent_id))
        self.assertTrue(all(r["intent_id"] != b.intent_id for r in self.store.risk_claims("grant:test", 1)))
        self.assertTrue(self.store.reserve_usage(b, grant(), risk(state_version=3), NOW)[0])


class FillMonotonicityTests(_RuntimeCase):
    def test_a_shrinking_cumulative_fill_stops_the_intent(self):
        later_records = (
            (SettlementStatus.PARTIALLY_FILLED, "10"),
            (SettlementStatus.CANCELLED, "5"),
            (SettlementStatus.FINALIZED, "30"),
            (SettlementStatus.CONFIRMED, "39.99999999"),
        )
        for n, (status, amount) in enumerate(later_records):
            order = f"order-{n}"
            adapter = ScriptedAdapter([RECEIPT], [_auth(SettlementStatus.PARTIALLY_FILLED, order, "40"), _auth(status, order, amount)])
            runtime = self.runtime_for(adapter)
            i = intent(intent_id=f"intent_fill_0000000000{n:02d}")
            first = self.run_case(runtime, i)
            self.assertEqual(IntentState.CONFIRMED, first.state)
            self.assertEqual("40", self.store.get(i.intent_id).filled_amount_usd)
            second = self.run_case(runtime, i)
            self.assertEqual(IntentState.STOPPED, second.state, n)
            self.assertEqual(("SETTLEMENT_FILL_REGRESSED",), second.reason_codes)
            self.assertEqual(order, self.store.get(i.intent_id).effect_id)
            self.assertEqual("HELD", self.usage_status(i.intent_id))
            self.assertEqual(1, adapter.calls)
            self.assertTrue(self.run_case(runtime, i).replayed)

    def test_equal_or_growing_fills_progress(self):
        adapter = ScriptedAdapter([RECEIPT], [
            _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "40"),
            _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "45"),
            _auth(SettlementStatus.FINALIZED, "order-1", "45"),
        ])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_fill_000000000010")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        self.assertEqual("45", self.store.get(i.intent_id).filled_amount_usd)
        self.assertEqual(IntentState.FINALIZED, self.run_case(runtime, i).state)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))

    def test_cancel_with_nothing_filled_after_a_fill_keeps_its_own_code(self):
        adapter = ScriptedAdapter([RECEIPT], [
            _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "40"), _auth(SettlementStatus.CANCELLED, "order-1", "0"),
        ])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_fill_000000000011")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertEqual(("SETTLEMENT_CANCEL_CONTRADICTS_RECORDED_EFFECT",), result.reason_codes)


class OpenOrderTests(_RuntimeCase):
    def test_an_admitted_unfilled_order_is_open_not_a_stop(self):
        adapter = ScriptedAdapter([RECEIPT_OPEN], [
            _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "0"), _auth(SettlementStatus.FINALIZED, "order-1", "50"),
        ])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_open_00000000000001")
        first = self.run_case(runtime, i)
        self.assertEqual(IntentState.CONFIRMED, first.state)
        self.assertEqual(("SETTLEMENT_ORDER_OPEN",), first.reason_codes)
        self.assertEqual("order-1", self.store.get(i.intent_id).effect_id)
        self.assertEqual("0", self.store.get(i.intent_id).filled_amount_usd)
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        self.assertIn("order_open", self.events(i.intent_id))
        second = self.run_case(runtime, i)
        self.assertEqual(IntentState.FINALIZED, second.state)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))
        self.assertEqual(1, adapter.calls)

    def test_an_open_order_cancelled_unfilled_fails_safe_and_releases(self):
        adapter = ScriptedAdapter([RECEIPT_OPEN], [
            _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "0"), _auth(SettlementStatus.CANCELLED, "order-1", "0"),
        ])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_open_00000000000002")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.FAILED_SAFE, result.state)
        self.assertEqual(("SETTLEMENT_CANCELLED_UNFILLED",), result.reason_codes)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))
        self.assertEqual(1, adapter.calls)

    def test_an_open_order_that_starts_filling_becomes_a_partial_fill(self):
        adapter = ScriptedAdapter([RECEIPT_OPEN], [
            _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "0"), _auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "20"),
        ])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_open_00000000000003")
        self.assertEqual(("SETTLEMENT_ORDER_OPEN",), self.run_case(runtime, i).reason_codes)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.CONFIRMED, result.state)
        self.assertEqual(("SETTLEMENT_PARTIAL_FILL_OPEN",), result.reason_codes)
        self.assertEqual("20", self.store.get(i.intent_id).filled_amount_usd)

    def test_an_open_order_that_vanishes_is_a_lost_effect(self):
        adapter = ScriptedAdapter([RECEIPT_OPEN], [_auth(SettlementStatus.PARTIALLY_FILLED, "order-1", "0"), _auth(SettlementStatus.NONE)])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_open_00000000000004")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertEqual(("SETTLEMENT_LOST_PREVIOUS_EFFECT",), result.reason_codes)
        self.assertEqual("HELD", self.usage_status(i.intent_id))

    def test_mock_venue_open_order_end_to_end(self):
        runtime, venue, *_ = build_mock_runtime(self.store, self.trust, mode=MockMode.OPEN_ORDER)
        i = intent(intent_id="intent_open_00000000000005")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.CONFIRMED, result.state)
        self.assertEqual(("SETTLEMENT_ORDER_OPEN",), result.reason_codes)
        self.assertEqual(0, venue.successful_effect_count(i.intent_id))
        venue.cancel_order(ExecutionRequest.from_intent(i))
        cancelled = self.run_case(runtime, i)
        self.assertEqual(IntentState.FAILED_SAFE, cancelled.state)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))
        self.assertEqual(1, venue.execute_call_count(i.intent_id))

        j = intent(intent_id="intent_open_00000000000006")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, j).state)
        venue.complete_fill(ExecutionRequest.from_intent(j))
        self.assertEqual(IntentState.FINALIZED, self.run_case(runtime, j).state)
        self.assertEqual("COMMITTED", self.usage_status(j.intent_id))
        self.assertEqual(1, venue.successful_effect_count(j.intent_id))
        self.assertEqual(1, venue.execute_call_count(j.intent_id))


class JsonNumberGrammarTests(_RuntimeCase):
    def test_json_numbers_take_the_string_grammar(self):
        for raw in (1e-9, 50.123456789, 74.99999999999999, 0.1 + 0.2, 1e16, 10**18, float("nan"), float("inf"), True):
            self.assertIsNone(parse_bounded_decimal(raw), repr(raw))
        for raw, expected in ((50.0, "50.0"), (5e1, "50.0"), (50, "50"), (50.5, "50.5"), (10**17, "100000000000000000"), (-1, "-1")):
            parsed = parse_bounded_decimal(raw)
            self.assertEqual(Decimal(expected), parsed, repr(raw))
            self.assertEqual(expected, format(parsed, "f"), repr(raw))

    def test_gate_and_ledger_reject_numbers_outside_the_grammar(self):
        for n, raw in enumerate((1e-9, 50.123456789, 0.1 + 0.2)):
            i = intent(intent_id=f"intent_num_0000000000000{n}", payload={**intent().payload, "amount_usd": raw})
            decision = evaluate_capability(i, grant(), NOW)
            self.assertEqual(Verdict.DENY, decision.verdict, repr(raw))
            self.assertIn("AMOUNT_INVALID_OR_NONFINITE", decision.reason_codes)
            self.store.register(i, canonical_hash(i))
            ok, reasons = self.store.reserve_usage(i, grant(), risk(state_version=n + 1), NOW)
            self.assertFalse(ok)
            self.assertEqual(("USAGE_AMOUNT_INVALID",), reasons)
        self.assertEqual(Verdict.ALLOW, evaluate_capability(intent(payload={**intent().payload, "amount_usd": 50.5}), grant(), NOW).verdict)
        self.assertIn("AMOUNT_NOT_POSITIVE", evaluate_capability(intent(payload={**intent().payload, "amount_usd": -1}), grant(), NOW).reason_codes)


if __name__ == "__main__":
    unittest.main()
