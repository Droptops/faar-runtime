"""Paper gateway: venue-side permits, limit-price envelope, independent query path."""

from __future__ import annotations

import unittest
from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from faar.adapters import AmbiguousExecution, DeterministicFailure
from faar.canonical import canonical_hash
from faar.gates import evaluate_capability
from faar.models import (
    CapabilityGrant,
    EconomicPrimitive,
    ExecutionRequest,
    GrantStatus,
    Intent,
    IntentState,
    SettlementStatus,
    Verdict,
)
from faar.paper_gateway import (
    PaperHttpQueryClient,
    PaperHttpSubmitClient,
    PaperOrderState,
    PaperVenueBook,
    PaperVenueService,
    VenueCredential,
    VenueRole,
    client_order_id,
    permit_from_wire,
    permit_to_wire,
    paper_gateway_pair,
    paper_http_pair,
    request_from_wire,
    request_to_wire,
)
from faar.runtime import FAARRuntime
from faar.store import SQLiteIntentStore

from support import AUTH, NOW, PRINCIPAL, attest_pair, grant, permit_stack, temp_path, trust, verification_trust


VENUE = "paper-gateway"
TARGET = "router:approved"


def _order_grant(**changes) -> CapabilityGrant:
    return grant(
        grant_id="g-paper-gw",
        allowed_primitives=frozenset({
            EconomicPrimitive.PLACE_ORDER, EconomicPrimitive.BUY, EconomicPrimitive.SELL,
            EconomicPrimitive.CANCEL_ORDER,
        }),
        allowed_venues=frozenset({VENUE}),
        allowed_assets=frozenset({"USDC", "MEME"}),
        allowed_targets=frozenset({TARGET, "router:other"}),
        **changes,
    )


def _order_intent(*, intent_id: str, primitive=EconomicPrimitive.BUY, **payload_extra) -> Intent:
    payload = {
        "base_asset": "MEME",
        "quote_asset": "USDC",
        "amount_usd": "50",
        "order_type": "limit",
        "limit_price": "0.55",
        "target": TARGET,
    }
    payload.update(payload_extra)
    return Intent(
        principal_id=PRINCIPAL,
        intent_id=intent_id,
        actor_id="agent:quant",
        grant_id="g-paper-gw",
        grant_version=1,
        primitive=primitive,
        venue=VENUE,
        created_at=NOW,
        expires_at=NOW + timedelta(seconds=15),
        payload=payload,
    )


class PaperGatewayTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self))
        self.g = _order_grant()
        self.store.provision_grant(self.g, canonical_hash(self.g))
        self.trust = trust()
        self.permit_authority, self.permit_verifier = permit_stack(self.store, self.trust)
        self.book = PaperVenueBook(
            {"MEME": Decimal("0.50")},
            {"USDC": Decimal("1000"), "MEME": Decimal("200")},
        )
        self.service = PaperVenueService(
            VENUE, self.permit_verifier, self.book,
            principal_id=PRINCIPAL,
            target=TARGET,
            submit_token="submit-token-not-a-secret",
            query_token="query-token-not-a-secret",
            clock=lambda: NOW,
        )
        self.adapter, self.verifier = paper_gateway_pair(self.service)
        self.runtime = FAARRuntime(
            self.store, {VENUE: self.adapter}, verification_trust(self.trust),
            self.permit_authority, {VENUE: self.verifier},
            allow_test_time_override=True,
        )
        self._risk_version = 0

    def tearDown(self):
        self.store.close()

    def _risk(self, **changes):
        from support import risk
        self._risk_version += 1
        return risk(state_version=self._risk_version, **changes)

    def issue(self, i: Intent, rs=None, *, capability: CapabilityGrant | None = None):
        capability = capability or self.g
        rs = rs or self._risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs)
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, capability, rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        permit = self.permit_authority.issue(
            request, intent=i, authority=AUTH, grant=capability, risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )
        return request, permit, rs, aa, ra

    def process(self, i: Intent, rs=None, *, now=NOW):
        rs = rs or self._risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs)
        return self.runtime.process(i, AUTH, self.g, rs, authority_attestation=aa, risk_attestation=ra, now=now), rs

    def test_authorized_limit_order_fills_once_at_book_not_worse_than_limit(self):
        i = _order_intent(intent_id="paper_gw_intent_00000001")
        result, _ = self.process(i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(Decimal("950"), self.book.balances["USDC"])
        self.assertEqual(Decimal("300"), self.book.balances["MEME"])
        result2, _ = self.process(i)
        self.assertEqual(IntentState.FINALIZED, result2.state)
        self.assertEqual(result.effect_id, result2.effect_id)
        self.assertEqual(Decimal("950"), self.book.balances["USDC"])
        self.assertEqual(Decimal("300"), self.book.balances["MEME"])

    def test_fill_worse_than_limit_price_is_rejected_and_creates_no_effect(self):
        self.book.fill_prices_usd["MEME"] = Decimal("0.60")
        i = _order_intent(intent_id="paper_gw_intent_00000002", limit_price="0.55")
        result, _ = self.process(i)
        # Permit was consumed, then the book refused the fill. The venue leaves
        # an authoritative CANCELLED record so this is FAILED_SAFE, not a
        # consumed-permit / absence STOP.
        self.assertEqual(IntentState.FAILED_SAFE, result.state)
        self.assertEqual(("SETTLEMENT_CANCELLED_UNFILLED",), result.reason_codes)
        self.assertEqual(Decimal("1000"), self.book.balances["USDC"])
        self.assertEqual(0, sum(1 for o in self.book.orders.values() if o.state.value == "FILLED" and o.primitive != EconomicPrimitive.CANCEL_ORDER))
        later, _ = self.process(i)
        self.assertEqual(IntentState.FAILED_SAFE, later.state)
        self.assertTrue(later.replayed)

    def test_query_credential_cannot_submit(self):
        i = _order_intent(intent_id="paper_gw_intent_00000003")
        request, permit, *_ = self.issue(i)
        with self.assertRaisesRegex(DeterministicFailure, "CREDENTIAL_DENIED"):
            self.service.submit(request, permit, VenueCredential(VenueRole.QUERY, self.service.query_token))
        with self.assertRaisesRegex(DeterministicFailure, "QUERY_CLIENT_CANNOT_SUBMIT"):
            self.verifier.client.submit(request, permit)
        self.assertEqual(Decimal("1000"), self.book.balances["USDC"])
        self.assertFalse(self.book.orders)

    def test_submit_credential_cannot_query(self):
        i = _order_intent(intent_id="paper_gw_intent_00000004")
        request, permit, *_ = self.issue(i)
        self.adapter.execute(request, permit)
        with self.assertRaisesRegex(DeterministicFailure, "CREDENTIAL_DENIED"):
            self.service.lookup(request, VenueCredential(VenueRole.SUBMIT, self.service.submit_token))
        with self.assertRaisesRegex(DeterministicFailure, "SUBMIT_CLIENT_CANNOT_QUERY"):
            self.adapter.client.lookup(request)
        record = self.verifier.verify(request)
        self.assertEqual(SettlementStatus.FINALIZED, record.status)
        self.assertTrue(record.authoritative)

    def test_adapter_and_verifier_are_distinct_objects(self):
        self.assertIsNot(self.adapter, self.verifier)
        self.assertNotEqual(type(self.adapter.client), type(self.verifier.client))

    def test_stable_client_order_id_is_hashed_and_namespace_unambiguous(self):
        i = _order_intent(intent_id="paper_gw_intent_00000005")
        request, permit, *_ = self.issue(i)
        receipt = self.adapter.execute(request, permit)
        self.assertRegex(client_order_id(request), r"\Apco_[0-9a-f]{32}\Z")
        self.assertEqual(client_order_id(request), receipt.evidence["client_order_id"])
        again = self.adapter.execute(request, permit)
        self.assertEqual(receipt.effect_id, again.effect_id)

        # Delimiter concatenation aliases these two identity pairs. The gateway
        # hashes a canonical, domain-separated structure instead.
        first = ExecutionRequest(
            "principal:a:b", "intent_collision_0001", EconomicPrimitive.BUY, VENUE, request.payload,
        )
        second = ExecutionRequest(
            "principal:a", "b:intent_collision_0001", EconomicPrimitive.BUY, VENUE, request.payload,
        )
        self.assertEqual(
            f"{first.principal_id}:{first.intent_id}",
            f"{second.principal_id}:{second.intent_id}",
        )
        self.assertNotEqual(client_order_id(first), client_order_id(second))

    def test_place_order_without_a_signed_side_is_rejected_before_consume(self):
        i = _order_intent(
            intent_id="paper_gw_place_order_000001",
            primitive=EconomicPrimitive.PLACE_ORDER,
        )
        request, permit, *_ = self.issue(i)
        with self.assertRaisesRegex(DeterministicFailure, "UNSUPPORTED_PRIMITIVE:PLACE_ORDER"):
            self.adapter.execute(request, permit)
        self.assertEqual((1, 0), self.store.permit_counts(i.intent_id))
        self.assertFalse(self.book.orders)

    def test_order_semantics_are_exact_and_rejected_before_consume(self):
        cases = (
            ("paper_gw_bad_order_type_01", {"order_type": "market", "max_slippage_bps": 1}, "LIMIT_ORDER_REQUIRED"),
            ("paper_gw_bad_tif_0000001", {"time_in_force": "FOK"}, "TIME_IN_FORCE_UNSUPPORTED"),
            ("paper_gw_bad_tif_type_01", {"time_in_force": 1}, "TIME_IN_FORCE_UNSUPPORTED"),
            ("paper_gw_second_bound_001", {"max_slippage_bps": 1}, "ABSOLUTE_LIMIT_ONLY"),
            ("paper_gw_bad_quote_00001", {"quote_asset": "MEME", "base_asset": "USDC"}, "USDC_QUOTE_REQUIRED"),
            ("paper_gw_bad_target_0001", {"target": "router:other"}, "TARGET_MISMATCH"),
        )
        for intent_id, changes, reason in cases:
            with self.subTest(reason=reason):
                i = _order_intent(intent_id=intent_id, **changes)
                request, permit, *_ = self.issue(i)
                with self.assertRaisesRegex(DeterministicFailure, reason):
                    self.adapter.execute(request, permit)
                self.assertEqual((1, 0), self.store.permit_counts(i.intent_id))
        self.assertFalse(self.book.orders)

    def test_service_is_bound_to_one_principal_before_permit_consume(self):
        attacker = "principal:attacker"
        attacker_grant = replace(
            self.g,
            principal_id=attacker,
            grant_id="g-paper-gw-attacker",
        )
        self.store.provision_grant(attacker_grant, canonical_hash(attacker_grant))
        attack = replace(
            _order_intent(intent_id="paper_gw_attacker_buy_001"),
            principal_id=attacker,
            grant_id=attacker_grant.grant_id,
        )
        request, permit, *_ = self.issue(attack, capability=attacker_grant)
        with self.assertRaisesRegex(DeterministicFailure, "PRINCIPAL_MISMATCH"):
            self.adapter.execute(request, permit)
        with self.assertRaisesRegex(DeterministicFailure, "PRINCIPAL_MISMATCH"):
            self.service.lookup(
                request,
                VenueCredential(VenueRole.QUERY, self.service.query_token),
            )
        self.assertEqual((1, 0), self.store.permit_counts(attack.intent_id))
        self.assertFalse(self.book.orders)

    def test_other_principal_cannot_cancel_an_order_in_a_shared_book(self):
        place = _order_intent(
            intent_id="paper_gw_owner_order_0001",
            limit_price="0.40",
            time_in_force="GTC",
        )
        place_request, place_permit, *_ = self.issue(place)
        receipt = self.adapter.execute(place_request, place_permit)

        attacker = "principal:attacker"
        attacker_grant = replace(
            self.g,
            principal_id=attacker,
            grant_id="g-paper-gw-attacker-cancel",
        )
        self.store.provision_grant(attacker_grant, canonical_hash(attacker_grant))
        cancel = Intent(
            principal_id=attacker,
            intent_id="paper_gw_attacker_cancel_01",
            actor_id="agent:quant",
            grant_id=attacker_grant.grant_id,
            grant_version=1,
            primitive=EconomicPrimitive.CANCEL_ORDER,
            venue=VENUE,
            created_at=NOW,
            expires_at=NOW + timedelta(seconds=15),
            payload={"order_id": receipt.evidence["order_id"], "target": TARGET},
        )
        cancel_request, cancel_permit, *_ = self.issue(cancel, capability=attacker_grant)
        attacker_service = PaperVenueService(
            VENUE,
            self.permit_verifier,
            self.book,
            principal_id=attacker,
            target=TARGET,
            submit_token="attacker-submit-token",
            query_token="attacker-query-token",
            clock=lambda: NOW,
        )
        with self.assertRaisesRegex(DeterministicFailure, "ORDER_NOT_OWNED"):
            attacker_service.submit(
                cancel_request,
                cancel_permit,
                VenueCredential(VenueRole.SUBMIT, "attacker-submit-token"),
            )
        self.assertEqual((1, 0), self.store.permit_counts(cancel.intent_id))
        self.assertEqual(PaperOrderState.PENDING, self.book.orders[client_order_id(place_request)].state)

    def test_lookup_of_a_rebound_request_is_contradictory(self):
        i = _order_intent(intent_id="paper_gw_intent_00000006")
        request, permit, *_ = self.issue(i)
        self.adapter.execute(request, permit)
        forged = ExecutionRequest(
            i.principal_id, i.intent_id, i.primitive, i.venue,
            {
                "base_asset": "MEME",
                "quote_asset": "USDC",
                "amount_usd": "5000",
                "limit_price": "0.55",
                "target": TARGET,
            },
        )
        self.assertEqual(SettlementStatus.CONTRADICTORY, self.verifier.verify(forged).status)

    def test_cancelled_gtc_order_never_fills_after_the_book_moves(self):
        place = _order_intent(intent_id="paper_gw_intent_00000007", limit_price="0.40", time_in_force="GTC")
        place_req, place_permit, *_ = self.issue(place)
        receipt = self.adapter.execute(place_req, place_permit)
        self.assertEqual(SettlementStatus.PARTIALLY_FILLED, receipt.status)
        pending = self.verifier.verify(place_req)
        self.assertEqual(SettlementStatus.PARTIALLY_FILLED, pending.status)
        self.assertEqual(Decimal("0"), pending.amount_usd)
        self.assertTrue(pending.authoritative)
        self.assertEqual(receipt.effect_id, pending.effect_id)

        cancel = Intent(
            principal_id=PRINCIPAL, intent_id="paper_gw_cancel_00000007",
            actor_id="agent:quant", grant_id="g-paper-gw", grant_version=1,
            primitive=EconomicPrimitive.CANCEL_ORDER, venue=VENUE,
            created_at=NOW, expires_at=NOW + timedelta(seconds=15),
            payload={"order_id": receipt.evidence["order_id"], "target": "router:approved"},
        )
        cancel_req, cancel_permit, *_ = self.issue(cancel)
        cancel_receipt = self.adapter.execute(cancel_req, cancel_permit)
        self.assertEqual(SettlementStatus.FINALIZED, self.verifier.verify(cancel_req).status)
        self.assertIsNone(self.verifier.verify(cancel_req).amount_usd)
        self.assertTrue(cancel_receipt.evidence["fill"]["cancelled_order_id"])

        filled_keys = self.service.set_quote("MEME", Decimal("0.40"))
        self.assertEqual([], filled_keys)
        self.assertEqual(Decimal("1000"), self.book.balances["USDC"])
        cancelled = self.verifier.verify(place_req)
        self.assertEqual(SettlementStatus.CANCELLED, cancelled.status)
        self.assertEqual(Decimal("0"), cancelled.amount_usd)
        self.assertTrue(cancelled.authoritative)
        self.assertEqual(receipt.effect_id, cancelled.effect_id)
        # Cancel is idempotent: a second cancel of the same order does not fill it.
        cancel2 = Intent(
            principal_id=PRINCIPAL, intent_id="paper_gw_cancel_00000008",
            actor_id="agent:quant", grant_id="g-paper-gw", grant_version=1,
            primitive=EconomicPrimitive.CANCEL_ORDER, venue=VENUE,
            created_at=NOW, expires_at=NOW + timedelta(seconds=15),
            payload={"order_id": receipt.evidence["order_id"], "target": "router:approved"},
        )
        cancel2_req, cancel2_permit, *_ = self.issue(cancel2)
        self.adapter.execute(cancel2_req, cancel2_permit)
        self.assertEqual([], self.service.match_pending())
        self.assertEqual(Decimal("1000"), self.book.balances["USDC"])

    def test_gtc_order_fills_when_the_book_moves_if_not_cancelled(self):
        place = _order_intent(intent_id="paper_gw_intent_00000009", limit_price="0.40", time_in_force="GTC")
        request, permit, *_ = self.issue(place)
        receipt = self.adapter.execute(request, permit)
        open_order = self.verifier.verify(request)
        self.assertEqual(SettlementStatus.PARTIALLY_FILLED, open_order.status)
        self.assertEqual(Decimal("0"), open_order.amount_usd)
        self.assertEqual(receipt.effect_id, open_order.effect_id)
        filled = self.service.set_quote("MEME", Decimal("0.40"))
        self.assertEqual([client_order_id(request)], filled)
        record = self.verifier.verify(request)
        self.assertEqual(SettlementStatus.FINALIZED, record.status)
        self.assertEqual(Decimal("50"), record.amount_usd)
        self.assertEqual(open_order.effect_id, record.effect_id)
        self.assertEqual(Decimal("950"), self.book.balances["USDC"])
        self.assertEqual(Decimal("325"), self.book.balances["MEME"])
        self.assertEqual("0.40", record.evidence["fill"]["fill_price"])
        self.assertEqual("125", record.evidence["fill"]["base_quantity"])
        self.assertEqual("50", record.evidence["fill"]["quote_quantity"])

    def test_gtc_failed_match_becomes_authoritative_unfilled_cancel(self):
        self.book.balances["USDC"] = Decimal("0")
        place = _order_intent(
            intent_id="paper_gw_gtc_match_fail_01",
            limit_price="0.40",
            time_in_force="GTC",
        )
        request, permit, *_ = self.issue(place)
        receipt = self.adapter.execute(request, permit)
        self.assertEqual(SettlementStatus.PARTIALLY_FILLED, receipt.status)

        self.assertEqual([], self.service.set_quote("MEME", Decimal("0.40")))
        record = self.verifier.verify(request)
        self.assertEqual(SettlementStatus.CANCELLED, record.status)
        self.assertEqual(Decimal("0"), record.amount_usd)
        self.assertTrue(record.authoritative)
        self.assertIn("INSUFFICIENT_BALANCE:USDC", record.evidence["reasons"])
        self.assertEqual(Decimal("0"), self.book.balances["USDC"])
        self.assertEqual(Decimal("200"), self.book.balances["MEME"])
        self.assertEqual((1, 1), self.store.permit_counts(place.intent_id))

    def test_sell_limit_uses_the_signed_side_and_fill_time_quote(self):
        sell = _order_intent(
            intent_id="paper_gw_sell_order_00001",
            primitive=EconomicPrimitive.SELL,
            limit_price="0.50",
        )
        request, permit, *_ = self.issue(sell)
        receipt = self.adapter.execute(request, permit)
        record = self.verifier.verify(request)
        self.assertEqual(SettlementStatus.FINALIZED, record.status)
        self.assertEqual("SELL", receipt.evidence["fill"]["side"])
        self.assertEqual("0.50", record.evidence["fill"]["fill_price"])
        self.assertEqual(Decimal("100"), self.book.balances["MEME"])
        self.assertEqual(Decimal("1050"), self.book.balances["USDC"])

    def test_invalid_credit_balance_cancels_without_a_partial_balance_leg(self):
        self.book.balances["USDC"] = Decimal("NaN")
        before_base = self.book.balances["MEME"]
        sell = _order_intent(
            intent_id="paper_gw_atomic_fill_0001",
            primitive=EconomicPrimitive.SELL,
            limit_price="0.50",
        )
        request, permit, *_ = self.issue(sell)
        with self.assertRaisesRegex(DeterministicFailure, "INVALID_PAPER_BALANCE:USDC"):
            self.adapter.execute(request, permit)
        self.assertEqual(before_base, self.book.balances["MEME"])
        self.assertTrue(self.book.balances["USDC"].is_nan())
        order = self.book.orders[client_order_id(request)]
        self.assertEqual(PaperOrderState.CANCELLED, order.state)
        self.assertEqual((1, 1), self.store.permit_counts(sell.intent_id))

    def test_cancel_of_a_filled_order_is_deterministic_and_does_not_unwind(self):
        place = _order_intent(intent_id="paper_gw_intent_00000010")
        place_req, place_permit, *_ = self.issue(place)
        place_receipt = self.adapter.execute(place_req, place_permit)
        cancel = Intent(
            principal_id=PRINCIPAL, intent_id="paper_gw_cancel_00000010",
            actor_id="agent:quant", grant_id="g-paper-gw", grant_version=1,
            primitive=EconomicPrimitive.CANCEL_ORDER, venue=VENUE,
            created_at=NOW, expires_at=NOW + timedelta(seconds=15),
            payload={"order_id": place_receipt.evidence["order_id"], "target": "router:approved"},
        )
        cancel_req, cancel_permit, *_ = self.issue(cancel)
        with self.assertRaisesRegex(DeterministicFailure, "ORDER_ALREADY_FILLED"):
            self.adapter.execute(cancel_req, cancel_permit)
        self.assertEqual(Decimal("950"), self.book.balances["USDC"])
        self.assertEqual(SettlementStatus.FINALIZED, self.verifier.verify(place_req).status)

    def test_runtime_refuses_a_collapsed_submitter_as_verifier(self):
        with self.assertRaisesRegex(ValueError, "distinct"):
            FAARRuntime(
                self.store, {VENUE: self.adapter}, verification_trust(self.trust),
                self.permit_authority, {VENUE: self.adapter},
                allow_test_time_override=True,
            )

    def test_permit_for_another_venue_is_refused_before_any_book_change(self):
        i = _order_intent(intent_id="paper_gw_intent_00000011")
        request, permit, *_ = self.issue(i)
        foreign = ExecutionRequest(
            request.principal_id, request.intent_id, request.primitive, "other-venue", dict(request.payload),
        )
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_VENUE_MISMATCH"):
            self.service.submit(foreign, permit, VenueCredential(VenueRole.SUBMIT, self.service.submit_token))
        self.assertFalse(self.book.orders)
        self.assertEqual(Decimal("1000"), self.book.balances["USDC"])

    def test_halted_grant_cannot_create_an_effect(self):
        i = _order_intent(intent_id="paper_gw_intent_00000012")
        request, permit, *_ = self.issue(i)
        self.store.halt("global", reason="paper-gateway-halt-drill")
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_REJECTED"):
            self.adapter.execute(request, permit)
        self.assertFalse(self.book.orders)
        self.assertEqual(Decimal("1000"), self.book.balances["USDC"])

    def test_gtc_resting_order_is_confirmed_open_and_never_resubmitted(self):
        place = _order_intent(intent_id="paper_gw_intent_00000013", limit_price="0.40", time_in_force="GTC")
        result, _ = self.process(place)
        self.assertEqual(IntentState.CONFIRMED, result.state)
        self.assertEqual(("SETTLEMENT_ORDER_OPEN",), result.reason_codes)
        self.assertEqual(Decimal("1000"), self.book.balances["USDC"])
        again, _ = self.process(place)
        self.assertEqual(IntentState.CONFIRMED, again.state)
        self.assertEqual(result.effect_id, again.effect_id)
        self.assertEqual(1, sum(1 for o in self.book.orders.values() if o.state.value == "PENDING"))


class PaperGatewayHttpTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self))
        self.g = _order_grant()
        self.store.provision_grant(self.g, canonical_hash(self.g))
        self.trust = trust()
        self.permit_authority, self.permit_verifier = permit_stack(self.store, self.trust)
        self.book = PaperVenueBook({"MEME": Decimal("0.50")}, {"USDC": Decimal("1000")})
        self.service = PaperVenueService(
            VENUE, self.permit_verifier, self.book,
            principal_id=PRINCIPAL,
            target=TARGET,
            submit_token="submit-http-token",
            query_token="query-http-token",
            clock=lambda: NOW,
        )
        self.adapter, self.verifier, self.server = paper_http_pair(self.service)
        self.addCleanup(self.server.stop)
        self.addCleanup(self.store.close)

    def issue(self, i: Intent):
        from support import risk
        rs = risk(state_version=abs(hash(i.intent_id)) % 10000 + 1)
        aa, ra = attest_pair(self.trust, i, AUTH, rs)
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, self.g, rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        permit = self.permit_authority.issue(
            request, intent=i, authority=AUTH, grant=self.g, risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )
        return request, permit

    def test_http_submit_and_independent_http_query_agree_on_one_fill(self):
        from support import risk
        i = _order_intent(intent_id="paper_gw_http_intent_0001")
        runtime = FAARRuntime(
            self.store, {VENUE: self.adapter}, verification_trust(self.trust),
            self.permit_authority, {VENUE: self.verifier},
            allow_test_time_override=True,
        )
        rs = risk(state_version=7)
        aa, ra = attest_pair(self.trust, i, AUTH, rs)
        result = runtime.process(i, AUTH, self.g, rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertEqual(IntentState.FINALIZED, result.state)
        record = self.verifier.verify(ExecutionRequest.from_intent(i))
        self.assertEqual(SettlementStatus.FINALIZED, record.status)
        self.assertEqual(result.effect_id, record.effect_id)
        self.assertEqual(Decimal("50"), record.amount_usd)
        self.assertTrue(record.authoritative)
        self.assertEqual(canonical_hash(ExecutionRequest.from_intent(i)), record.verified_request_hash)
        self.assertIsInstance(self.adapter.client, PaperHttpSubmitClient)
        self.assertIsInstance(self.verifier.client, PaperHttpQueryClient)
        again = runtime.process(i, AUTH, self.g, rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertEqual(result.effect_id, again.effect_id)
        self.assertEqual(Decimal("950"), self.book.balances["USDC"])

    def test_http_query_token_cannot_create_an_order(self):
        i = _order_intent(intent_id="paper_gw_http_intent_0002")
        request, permit = self.issue(i)
        rogue = PaperHttpSubmitClient(self.server.url, self.service.query_token)
        with self.assertRaisesRegex(DeterministicFailure, "CREDENTIAL_DENIED"):
            rogue.submit(request, permit)
        self.assertFalse(self.book.orders)
        self.assertEqual(Decimal("1000"), self.book.balances["USDC"])

    def test_http_submit_token_cannot_reconcile(self):
        i = _order_intent(intent_id="paper_gw_http_intent_0003")
        request, permit = self.issue(i)
        self.adapter.execute(request, permit)
        rogue = PaperHttpQueryClient(self.server.url, self.service.submit_token)
        record = rogue.lookup(request)
        self.assertEqual(SettlementStatus.UNKNOWN, record.status)
        self.assertFalse(record.authoritative)
        honest = self.verifier.verify(request)
        self.assertEqual(SettlementStatus.FINALIZED, honest.status)

    def test_http_clients_reject_non_loopback_or_ambiguous_origins(self):
        bad_origins = (
            "http://example.com:80",
            "https://127.0.0.1:443",
            "http://localhost:8080",
            "http://user:pass@127.0.0.1:8080",
            "http://127.0.0.1:8080/prefix",
            "http://127.0.0.1:8080?redirect=example.com",
            "http://127.0.0.1",
        )
        for origin in bad_origins:
            with self.subTest(origin=origin):
                with self.assertRaisesRegex(ValueError, "numeric loopback HTTP origin"):
                    PaperHttpSubmitClient(origin, "submit-token")
                with self.assertRaisesRegex(ValueError, "numeric loopback HTTP origin"):
                    PaperHttpQueryClient(origin, "query-token")

    def test_malformed_authoritative_flag_never_becomes_authoritative(self):
        request = ExecutionRequest.from_intent(
            _order_intent(intent_id="paper_gw_bad_record_00001"),
        )
        client = PaperHttpQueryClient("http://127.0.0.1:1", "query-token")
        malicious = {
            "ok": True,
            "record": {
                "status": "NONE",
                "effect_id": None,
                "amount_usd": None,
                "evidence": {"order_state": "ABSENT"},
                "authoritative": "false",
                "verified_request_hash": canonical_hash(request),
            },
        }
        with patch("faar.paper_gateway._http_json", return_value=(200, malicious)):
            with self.assertRaisesRegex(AmbiguousExecution, "RECORD"):
                client.lookup(request)

    def test_malformed_submit_response_is_ambiguous_not_a_false_receipt(self):
        i = _order_intent(intent_id="paper_gw_bad_receipt_0001")
        request, permit = self.issue(i)
        client = PaperHttpSubmitClient("http://127.0.0.1:1", "submit-token")
        malicious = {
            "ok": True,
            "receipt": {
                "status": "FINALIZED",
                "effect_id": 123,
                "amount_usd": "50",
                "evidence": {},
            },
        }
        with patch("faar.paper_gateway._http_json", return_value=(200, malicious)):
            with self.assertRaisesRegex(AmbiguousExecution, "RECEIPT"):
                client.submit(request, permit)

    def test_wire_decoders_reject_scalar_coercion(self):
        i = _order_intent(intent_id="paper_gw_wire_types_00001")
        request, permit = self.issue(i)
        request_wire = request_to_wire(request)
        request_wire["principal_id"] = 123
        with self.assertRaisesRegex(DeterministicFailure, "MALFORMED_REQUEST"):
            request_from_wire(request_wire)

        permit_wire = deepcopy(permit_to_wire(permit))
        permit_wire["permit"]["grant_version"] = True
        with self.assertRaisesRegex(DeterministicFailure, "MALFORMED_PERMIT"):
            permit_from_wire(permit_wire)


class PaperVenueBookValidationTests(unittest.TestCase):
    def test_nonfinite_or_negative_operator_state_is_rejected(self):
        invalid = (
            ({"MEME": Decimal("NaN")}, {"USDC": Decimal("10")}),
            ({"MEME": Decimal("0")}, {"USDC": Decimal("10")}),
            ({"MEME": Decimal("0.5")}, {"USDC": Decimal("-1")}),
        )
        for prices, balances in invalid:
            with self.subTest(prices=prices, balances=balances):
                with self.assertRaises(ValueError):
                    PaperVenueBook(prices, balances)

        book = PaperVenueBook({"MEME": Decimal("0.5")}, {"USDC": Decimal("10")})
        with self.assertRaisesRegex(DeterministicFailure, "INVALID_PAPER_PRICE"):
            book.set_quote("MEME", Decimal("NaN"))
        self.assertEqual(Decimal("0.5"), book.price("MEME"))


class LimitPriceGateTests(unittest.TestCase):
    def test_invalid_limit_price_is_denied_before_any_adapter(self):
        g = grant(
            allowed_primitives=frozenset({EconomicPrimitive.PLACE_ORDER}),
            allowed_venues=frozenset({"v"}),
            allowed_assets=frozenset({"MEME", "USDC"}),
            allowed_targets=frozenset(),
        )
        for raw in ("0", "-1", "1e2", "abc", "00.5"):
            i = Intent(
                principal_id=PRINCIPAL, intent_id="intent_limit_price_00001",
                actor_id="agent:quant", grant_id="grant:test", grant_version=1,
                primitive=EconomicPrimitive.PLACE_ORDER, venue="v",
                created_at=NOW, expires_at=NOW + timedelta(seconds=10),
                payload={"base_asset": "MEME", "quote_asset": "USDC", "amount_usd": "10", "order_type": "limit", "limit_price": raw, "target": "router:approved"},
            )
            decision = evaluate_capability(i, g, NOW)
            self.assertEqual(Verdict.DENY, decision.verdict, raw)
            self.assertIn("LIMIT_PRICE_INVALID", decision.reason_codes, raw)

    def test_valid_limit_price_is_not_a_capability_denial(self):
        g = grant(
            allowed_primitives=frozenset({EconomicPrimitive.PLACE_ORDER}),
            allowed_venues=frozenset({"v"}),
            allowed_assets=frozenset({"MEME", "USDC"}),
            allowed_targets=frozenset(),
        )
        i = Intent(
            principal_id=PRINCIPAL, intent_id="intent_limit_price_00002",
            actor_id="agent:quant", grant_id="grant:test", grant_version=1,
            primitive=EconomicPrimitive.PLACE_ORDER, venue="v",
            created_at=NOW, expires_at=NOW + timedelta(seconds=10),
            payload={"base_asset": "MEME", "quote_asset": "USDC", "amount_usd": "10", "order_type": "limit", "limit_price": "0.55", "target": "router:approved"},
        )
        decision = evaluate_capability(i, g, NOW)
        self.assertEqual(Verdict.ALLOW, decision.verdict)
        self.assertNotIn("LIMIT_PRICE_INVALID", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
