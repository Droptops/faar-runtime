from __future__ import annotations

import json
import unittest
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

from faar.adapters import AmbiguousExecution, DeterministicFailure
import faar.hyperliquid as hyperliquid_module
from faar.canonical import canonical_hash
from faar.hyperliquid import (
    HYPERLIQUID_TESTNET_URL,
    HYPERLIQUID_TESTNET_VENUE,
    HyperliquidIOCOrder,
    HyperliquidSpotMarket,
    HyperliquidTestnetAdapter,
    HyperliquidTestnetHTTPTransport,
    HyperliquidTestnetSettlementVerifier,
    hyperliquid_cloid,
)
from faar.models import (
    EconomicPrimitive,
    ExecutionPermit,
    ExecutionRequest,
    IntentState,
    PermitAlgorithm,
    SignedExecutionPermit,
    SettlementStatus,
)
from faar.runtime import FAARRuntime
from faar.store import SQLiteIntentStore

from support import AUTH, NOW, PRINCIPAL, attest_pair, grant, intent, permit_stack, risk, temp_path, trust, verification_trust


ACCOUNT = "0x1111111111111111111111111111111111111111"
TARGET = "hyperliquid:spot"
MARKET = HyperliquidSpotMarket(
    base_asset="HYPE", quote_asset="USDC", coin="@42", asset_id=10_042, sz_decimals=2
)


def request(**payload_changes) -> ExecutionRequest:
    payload = {
        "base_asset": "HYPE",
        "quote_asset": "USDC",
        "notional_usd": "50",
        "target": TARGET,
        "order_type": "limit",
        "limit_price": "2",
        "time_in_force": "IOC",
    }
    payload.update(payload_changes)
    return ExecutionRequest(
        principal_id=PRINCIPAL,
        intent_id="hl_testnet_intent_00000001",
        primitive=EconomicPrimitive.BUY,
        venue=HYPERLIQUID_TESTNET_VENUE,
        payload=payload,
    )


def signed_permit(req: ExecutionRequest, *, issued_at=NOW, expires_at=None) -> SignedExecutionPermit:
    expires_at = expires_at or issued_at + timedelta(seconds=5)
    permit = ExecutionPermit(
        permit_id="permit_hl_testnet_00000001",
        principal_id=req.principal_id,
        intent_id=req.intent_id,
        grant_id="grant:test",
        grant_version=1,
        grant_hash="grant-hash",
        request_hash=canonical_hash(req),
        authority_attestation_hash="authority-hash",
        risk_attestation_hash="risk-hash",
        grant_epoch=1,
        fence_token=1,
        max_amount_usd=Decimal("50"),
        issued_at=issued_at,
        expires_at=expires_at,
    )
    return SignedExecutionPermit(
        permit=permit,
        signer_id="permit-test",
        algorithm=PermitAlgorithm.ED25519,
        signature="test-signature",
    )


class FakePermitVerifier:
    def __init__(self):
        self.calls = []
        self.consumed = set()

    def consume(self, permit, req, *, now, venue=None):
        self.calls.append((permit, req, now, venue))
        if permit.permit.permit_id in self.consumed:
            return False, ("PERMIT_ALREADY_CONSUMED",)
        self.consumed.add(permit.permit.permit_id)
        return True, ()


class FakeTransport:
    base_url = HYPERLIQUID_TESTNET_URL

    def __init__(self, response=None, error=None):
        self.response = response or filled_response()
        self.error = error
        self.calls = []

    def submit_ioc_order(self, order, *, nonce, expires_after_ms):
        self.calls.append((order, nonce, expires_after_ms))
        if self.error:
            raise self.error
        return self.response


def filled_response(*, oid=101, total_size="25", average_price="1.9"):
    return {
        "status": "ok",
        "response": {
            "type": "order",
            "data": {"statuses": [{"filled": {"oid": oid, "totalSz": total_size, "avgPx": average_price}}]},
        },
    }


def order_lookup(req: ExecutionRequest, *, status="filled", oid=101, remaining="0", **changes):
    details = {
        "coin": MARKET.coin,
        "side": "B",
        "limitPx": "2",
        "sz": remaining,
        "origSz": "25",
        "oid": oid,
        "timestamp": 1_788_112_800_000,
        "isTrigger": False,
        "reduceOnly": False,
        "orderType": "Limit",
        "tif": "Ioc",
        "cloid": hyperliquid_cloid(req),
    }
    details.update(changes)
    return {"status": "order", "order": {"order": details, "status": status, "statusTimestamp": 1_788_112_800_001}}


def fill(*, oid=101, size="25", price="1.9", tid=9001, **changes):
    value = {"oid": oid, "coin": MARKET.coin, "side": "B", "sz": size, "px": price, "tid": tid}
    value.update(changes)
    return value


class FakeInfoClient:
    base_url = HYPERLIQUID_TESTNET_URL

    def __init__(self, lookup, fills=()):
        self.lookup = lookup
        self.fills = list(fills)
        self.calls = []

    def query_order_by_cloid(self, account_address, cloid):
        self.calls.append(("order", account_address, cloid))
        if isinstance(self.lookup, BaseException):
            raise self.lookup
        return self.lookup

    def user_fills_by_time(self, account_address, start_time_ms, *, aggregate_by_time):
        self.calls.append(("fills", account_address, start_time_ms, aggregate_by_time))
        if isinstance(self.fills, BaseException):
            raise self.fills
        return self.fills


def adapter(verifier=None, transport=None, *, now=NOW, window=250):
    return HyperliquidTestnetAdapter(
        principal_id=PRINCIPAL,
        target=TARGET,
        markets=[MARKET],
        permit_verifier=verifier or FakePermitVerifier(),
        transport=transport or FakeTransport(),
        clock=lambda: now,
        minimum_submission_window_ms=window,
    )


def settlement(req, lookup, fills=(), *, fill_page_limit=2_000):
    return HyperliquidTestnetSettlementVerifier(
        principal_id=PRINCIPAL,
        account_address=ACCOUNT,
        target=TARGET,
        markets=[MARKET],
        info_client=FakeInfoClient(lookup, fills),
        fill_page_limit=fill_page_limit,
    )


class HyperliquidAdapterContractTests(unittest.TestCase):
    def test_mainnet_or_other_origin_transport_is_refused(self):
        transport = FakeTransport()
        transport.base_url = "https://api.hyperliquid.xyz"
        with self.assertRaisesRegex(ValueError, "testnet origin"):
            adapter(transport=transport)

    def test_submission_is_exact_limit_ioc_and_consumes_one_permit(self):
        verifier = FakePermitVerifier()
        transport = FakeTransport()
        req = request()
        permit = signed_permit(req)

        receipt = adapter(verifier, transport).execute(req, permit)

        self.assertEqual(SettlementStatus.FINALIZED, receipt.status)
        self.assertEqual(Decimal("47.5"), receipt.amount_usd)
        self.assertEqual(1, len(verifier.calls))
        self.assertEqual(HYPERLIQUID_TESTNET_VENUE, verifier.calls[0][3])
        self.assertEqual(1, len(transport.calls))
        submitted, nonce, expires_after = transport.calls[0]
        self.assertEqual(hyperliquid_cloid(req), submitted.cloid)
        self.assertEqual(MARKET.asset_id, submitted.asset_id)
        self.assertEqual(Decimal("2"), submitted.limit_price)
        self.assertEqual(Decimal("25.00"), submitted.size)
        self.assertEqual(int(NOW.timestamp() * 1000), nonce)
        self.assertEqual(int((NOW + timedelta(seconds=5)).timestamp() * 1000), expires_after)

    def test_consumed_permit_replay_never_reaches_transport_twice(self):
        verifier = FakePermitVerifier()
        transport = FakeTransport()
        venue = adapter(verifier, transport)
        req = request()
        permit = signed_permit(req)

        venue.execute(req, permit)
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_ALREADY_CONSUMED"):
            venue.execute(req, permit)

        self.assertEqual(2, len(verifier.calls))
        self.assertEqual(1, len(transport.calls))

    def test_unsupported_or_unbounded_order_shapes_fail_before_permit_consumption(self):
        without_amount = dict(request().payload)
        without_amount.pop("notional_usd")
        cases = {
            "sell": replace(request(), primitive=EconomicPrimitive.SELL),
            "wrong venue": replace(request(), venue="other-testnet"),
            "wrong principal": replace(request(), principal_id="principal:other"),
            "market": request(order_type="market"),
            "gtc": request(time_in_force="GTC"),
            "target": request(target="other"),
            "non-string target": request(target=123),
            "non-string order type": request(order_type=123),
            "non-string time in force": request(time_in_force=123),
            "non-string asset": request(base_asset=123),
            "relative slippage": request(max_slippage_bps=10),
            "unpinned market": request(base_asset="OTHER"),
            "price precision": request(limit_price="1.23456"),
            "missing amount": replace(request(), payload=without_amount),
            "dual amount": request(amount_usd="50"),
            "zero notional": request(notional_usd="0"),
            "zero limit": request(limit_price="0"),
            "zero size": request(notional_usd="10", limit_price="1000000"),
            "venue minimum": request(notional_usd="10", limit_price="2.01"),
        }
        for label, req in cases.items():
            with self.subTest(label=label):
                verifier = FakePermitVerifier()
                transport = FakeTransport()
                with self.assertRaises(DeterministicFailure):
                    adapter(verifier, transport).execute(req, signed_permit(req))
                self.assertEqual([], verifier.calls)
                self.assertEqual([], transport.calls)

    def test_gateway_permit_rejection_never_reaches_transport(self):
        verifier = FakePermitVerifier()
        transport = FakeTransport()
        req = request()
        permit = signed_permit(req)
        verifier.consumed.add(permit.permit.permit_id)
        with self.assertRaisesRegex(DeterministicFailure, "HL_PERMIT_REJECTED"):
            adapter(verifier, transport).execute(req, permit)
        self.assertEqual([], transport.calls)

    def test_nearly_expired_permit_is_refused_before_consumption(self):
        verifier = FakePermitVerifier()
        transport = FakeTransport()
        req = request()
        permit = signed_permit(req, expires_at=NOW + timedelta(milliseconds=100))
        with self.assertRaisesRegex(DeterministicFailure, "HL_PERMIT_WINDOW_TOO_SHORT"):
            adapter(verifier, transport).execute(req, permit)
        self.assertEqual([], verifier.calls)
        self.assertEqual([], transport.calls)

    def test_post_consumption_transport_failure_is_ambiguous_and_never_retried(self):
        verifier = FakePermitVerifier()
        transport = FakeTransport(error=TimeoutError("lost response"))
        req = request()
        with self.assertRaisesRegex(AmbiguousExecution, "HL_SUBMISSION_AMBIGUOUS"):
            adapter(verifier, transport).execute(req, signed_permit(req))
        self.assertEqual(1, len(verifier.calls))
        self.assertEqual(1, len(transport.calls))

    def test_ioc_resting_or_error_response_requires_reconciliation(self):
        req = request()
        for status in ({"resting": {"oid": 101}}, {"error": "IocCancel"}):
            response = {"status": "ok", "response": {"type": "order", "data": {"statuses": [status]}}}
            with self.subTest(status=status):
                with self.assertRaisesRegex(AmbiguousExecution, "HL_RESPONSE_REQUIRES_RECONCILIATION"):
                    adapter(transport=FakeTransport(response=response)).execute(req, signed_permit(req))


class HyperliquidSettlementContractTests(unittest.TestCase):
    def test_committed_fill_is_finalized_from_order_and_fill_evidence(self):
        req = request()
        verifier = settlement(req, order_lookup(req), [fill()])

        record = verifier.verify(req)

        self.assertTrue(record.authoritative)
        self.assertEqual(SettlementStatus.FINALIZED, record.status)
        self.assertEqual("hyperliquid-testnet:order:101", record.effect_id)
        self.assertEqual(Decimal("47.50000000"), record.amount_usd)
        self.assertEqual(canonical_hash(req), record.verified_request_hash)
        self.assertEqual(1, record.evidence["fill_count"])

    def test_terminal_cancel_preserves_partial_fill_and_unfilled_cancel_releases(self):
        req = request()
        partial = settlement(
            req,
            order_lookup(req, status="canceled", remaining="15"),
            [fill(size="10", price="1.8")],
        ).verify(req)
        unfilled = settlement(req, order_lookup(req, status="iocCancelRejected", remaining="25"), []).verify(req)

        self.assertEqual(SettlementStatus.CANCELLED, partial.status)
        self.assertEqual(Decimal("18.00000000"), partial.amount_usd)
        self.assertEqual(SettlementStatus.CANCELLED, unfilled.status)
        self.assertEqual(Decimal("0E-8"), unfilled.amount_usd)

    def test_missing_order_is_not_authoritative_absence(self):
        req = request()
        record = settlement(req, {"status": "unknownOid"}).verify(req)
        self.assertEqual(SettlementStatus.UNKNOWN, record.status)
        self.assertFalse(record.authoritative)
        self.assertEqual("HL_ORDER_NOT_FOUND", record.evidence["reason"])

    def test_every_order_term_is_bound_back_to_the_request(self):
        req = request()
        changes = {
            "cloid": {"cloid": "0x" + "0" * 32},
            "coin": {"coin": "@99"},
            "side": {"side": "A"},
            "type": {"orderType": "Market"},
            "tif": {"tif": "Gtc"},
            "limit": {"limitPx": "2.1"},
            "size": {"origSz": "24"},
            "reduce": {"reduceOnly": True},
            "trigger": {"isTrigger": True},
        }
        for label, changed in changes.items():
            with self.subTest(label=label):
                record = settlement(req, order_lookup(req, **changed), [fill()]).verify(req)
                self.assertEqual(SettlementStatus.CONTRADICTORY, record.status)
                self.assertTrue(record.authoritative)

    def test_ioc_open_state_is_a_terminal_contradiction(self):
        req = request()
        record = settlement(req, order_lookup(req, status="open", remaining="25"), []).verify(req)
        self.assertEqual(SettlementStatus.CONTRADICTORY, record.status)
        self.assertEqual("HL_IOC_NONTERMINAL_STATUS", record.evidence["reason"])

    def test_incomplete_or_truncated_fill_history_has_no_weight(self):
        req = request()
        incomplete = settlement(
            req,
            order_lookup(req, remaining="0"),
            [fill(size="24")],
        ).verify(req)
        truncated = settlement(
            req,
            order_lookup(req, remaining="0"),
            [fill()],
            fill_page_limit=1,
        ).verify(req)
        for record in (incomplete, truncated):
            self.assertEqual(SettlementStatus.UNKNOWN, record.status)
            self.assertFalse(record.authoritative)
        with self.assertRaisesRegex(ValueError, "1 through 2000"):
            settlement(req, order_lookup(req), [fill()], fill_page_limit=2_001)

    def test_price_above_limit_or_fill_above_notional_is_contradictory(self):
        req = request()
        above_limit = settlement(req, order_lookup(req), [fill(price="2.01")]).verify(req)
        # A venue claim larger than the deterministic order size is contradictory
        # even if the price itself stays at the signed limit.
        above_size = settlement(
            req,
            order_lookup(req, remaining="0", origSz="25"),
            [fill(size="26", price="2")],
        ).verify(req)
        self.assertEqual(SettlementStatus.CONTRADICTORY, above_limit.status)
        self.assertEqual(SettlementStatus.CONTRADICTORY, above_size.status)

    def test_conflicting_duplicate_fill_identity_is_contradictory(self):
        req = request()
        record = settlement(req, order_lookup(req), [fill(), fill(price="1.8")]).verify(req)
        self.assertEqual(SettlementStatus.CONTRADICTORY, record.status)
        self.assertEqual("HL_FILL_ID_CONTRADICTION", record.evidence["reason"])

    def test_info_transport_error_remains_non_authoritative_unknown(self):
        req = request()
        record = settlement(req, RuntimeError("provider down")).verify(req)
        self.assertEqual(SettlementStatus.UNKNOWN, record.status)
        self.assertFalse(record.authoritative)
        self.assertEqual("HL_INFO_UNAVAILABLE", record.evidence["reason"])

    def test_unknown_status_or_malformed_envelope_has_no_settlement_weight(self):
        req = request()
        unknown = settlement(req, order_lookup(req, status="futureStatus"), []).verify(req)
        malformed = settlement(req, {"status": "order", "order": []}, []).verify(req)
        for record in (unknown, malformed):
            self.assertEqual(SettlementStatus.UNKNOWN, record.status)
            self.assertFalse(record.authoritative)

    def test_impossible_remaining_size_or_timestamp_is_contradictory(self):
        req = request()
        remaining = settlement(req, order_lookup(req, remaining="26"), []).verify(req)
        timestamp = settlement(req, order_lookup(req, timestamp=-1), []).verify(req)
        self.assertEqual("HL_REMAINING_SIZE_INVALID", remaining.evidence["reason"])
        self.assertEqual("HL_ORDER_TIMESTAMP_INVALID", timestamp.evidence["reason"])

    def test_malformed_or_wrong_leg_fill_is_contradictory(self):
        req = request()
        cases = {
            "coin": fill(coin="@99"),
            "side": fill(side="A"),
            "size": fill(size="0"),
            "price": fill(price="nan"),
            "id": fill(tid=True),
        }
        for label, bad_fill in cases.items():
            with self.subTest(label=label):
                record = settlement(req, order_lookup(req), [bad_fill]).verify(req)
                self.assertEqual(SettlementStatus.CONTRADICTORY, record.status)

    def test_rejected_order_cannot_carry_a_fill(self):
        req = request()
        record = settlement(
            req,
            order_lookup(req, status="perpMarginRejected", remaining="15"),
            [fill(size="10")],
        ).verify(req)
        self.assertEqual(SettlementStatus.CONTRADICTORY, record.status)
        self.assertEqual("HL_REJECTION_HAS_FILL", record.evidence["reason"])

    def test_verifier_refuses_non_testnet_read_origin(self):
        req = request()
        client = FakeInfoClient(order_lookup(req), [fill()])
        client.base_url = "https://api.hyperliquid.xyz"
        with self.assertRaisesRegex(ValueError, "testnet origin"):
            HyperliquidTestnetSettlementVerifier(
                principal_id=PRINCIPAL,
                account_address=ACCOUNT,
                target=TARGET,
                markets=[MARKET],
                info_client=client,
            )


class FakeSigner:
    signer_id = "isolated-test-signer"

    def __init__(self):
        self.calls = []

    def sign_ioc_order_action(self, action, *, nonce, expires_after_ms, vault_address):
        self.calls.append((action, nonce, expires_after_ms, vault_address))
        return {"r": "0x" + "1" * 64, "s": "0x" + "2" * 64, "v": 27}


class FakeHTTPResponse:
    def __init__(self, payload):
        self.payload = payload
        self.closed = False

    def read(self, limit):
        return self.payload[:limit]

    def close(self):
        self.closed = True


class HyperliquidHTTPBoundaryTests(unittest.TestCase):
    def test_ioc_order_object_cannot_exceed_its_authorization(self):
        with self.assertRaisesRegex(ValueError, "exceeds its authorized notional"):
            HyperliquidIOCOrder(
                cloid="0x" + "a" * 32,
                coin="@42",
                asset_id=10_042,
                limit_price=Decimal("2"),
                size=Decimal("26"),
                authorized_notional_usd=Decimal("50"),
            )

    def test_default_http_stack_refuses_redirects(self):
        handler = hyperliquid_module._NoRedirectHandler()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://api.hyperliquid.xyz/exchange"))

    def test_http_transport_builds_only_the_pinned_testnet_ioc_action(self):
        signer = FakeSigner()
        opened = []

        def opener(req, *, timeout):
            opened.append((req, timeout))
            return FakeHTTPResponse(json.dumps(filled_response()).encode())

        transport = HyperliquidTestnetHTTPTransport(signer, timeout_seconds=1.5, opener=opener)
        order = HyperliquidIOCOrder(
            cloid="0x" + "a" * 32,
            coin="@42",
            asset_id=10_042,
            limit_price=Decimal("2"),
            size=Decimal("25"),
            authorized_notional_usd=Decimal("50"),
        )
        transport.submit_ioc_order(order, nonce=1000, expires_after_ms=2000)

        self.assertEqual(1, len(opened))
        req, timeout = opened[0]
        self.assertEqual(HYPERLIQUID_TESTNET_URL + "/exchange", req.full_url)
        self.assertEqual(1.5, timeout)
        body = json.loads(req.data)
        self.assertEqual({"type", "orders", "grouping"}, set(body["action"]))
        self.assertEqual({"a", "b", "p", "s", "r", "t", "c"}, set(body["action"]["orders"][0]))
        self.assertEqual({"limit": {"tif": "Ioc"}}, body["action"]["orders"][0]["t"])
        self.assertIs(body["action"]["orders"][0]["b"], True)
        self.assertIs(body["action"]["orders"][0]["r"], False)
        self.assertEqual(2000, body["expiresAfter"])
        self.assertEqual(body["action"], signer.calls[0][0])

    def test_malformed_or_mutating_signer_never_reaches_the_network(self):
        signer = FakeSigner()
        signer.sign_ioc_order_action = lambda *args, **kwargs: {"r": "bad", "s": "bad", "v": 1}
        calls = []
        transport = HyperliquidTestnetHTTPTransport(
            signer, opener=lambda *args, **kwargs: calls.append(args)
        )
        order = HyperliquidIOCOrder(
            cloid="0x" + "a" * 32, coin="@42", asset_id=10_042,
            limit_price=Decimal("2"), size=Decimal("25"), authorized_notional_usd=Decimal("50"),
        )
        with self.assertRaisesRegex(RuntimeError, "HL_SIGNATURE_MALFORMED"):
            transport.submit_ioc_order(order, nonce=1000, expires_after_ms=2000)
        self.assertEqual([], calls)

        def mutating_signer(action, **kwargs):
            action["orders"][0]["b"] = False
            return {"r": "0x" + "1" * 64, "s": "0x" + "2" * 64, "v": 27}

        signer.sign_ioc_order_action = mutating_signer
        with self.assertRaisesRegex(RuntimeError, "HL_SIGNED_ACTION_MUTATED"):
            transport.submit_ioc_order(order, nonce=1000, expires_after_ms=2000)
        self.assertEqual([], calls)

    def test_invalid_nonce_or_expiry_never_reaches_the_signer(self):
        signer = FakeSigner()
        transport = HyperliquidTestnetHTTPTransport(signer, opener=lambda *args, **kwargs: None)
        order = HyperliquidIOCOrder(
            cloid="0x" + "a" * 32, coin="@42", asset_id=10_042,
            limit_price=Decimal("2"), size=Decimal("25"), authorized_notional_usd=Decimal("50"),
        )
        for nonce, expiry in ((True, 2000), (1000, 1000), (1000, False)):
            with self.subTest(nonce=nonce, expiry=expiry):
                with self.assertRaises(RuntimeError):
                    transport.submit_ioc_order(order, nonce=nonce, expires_after_ms=expiry)
        self.assertEqual([], signer.calls)


class SharedTestnetLedger:
    def __init__(self, *, raise_after_effect=False):
        self.order = None
        self.calls = 0
        self.raise_after_effect = raise_after_effect


class LedgerTransport:
    base_url = HYPERLIQUID_TESTNET_URL

    def __init__(self, ledger):
        self.ledger = ledger

    def submit_ioc_order(self, order, *, nonce, expires_after_ms):
        self.ledger.calls += 1
        self.ledger.order = order
        if self.ledger.raise_after_effect:
            raise TimeoutError("response lost after committed fill")
        return filled_response()


class LedgerInfo:
    base_url = HYPERLIQUID_TESTNET_URL

    def __init__(self, ledger, req):
        self.ledger = ledger
        self.req = req

    def query_order_by_cloid(self, account_address, cloid):
        if self.ledger.order is None:
            return {"status": "unknownOid"}
        return order_lookup(self.req)

    def user_fills_by_time(self, account_address, start_time_ms, *, aggregate_by_time):
        return [fill()] if self.ledger.order is not None else []


class HyperliquidRuntimeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self))
        self.trust = trust()
        self.req_intent = replace(
            intent(),
            intent_id="hl_runtime_intent_00000001",
            primitive=EconomicPrimitive.BUY,
            venue=HYPERLIQUID_TESTNET_VENUE,
            payload={
                "base_asset": "HYPE",
                "quote_asset": "USDC",
                "notional_usd": "50",
                "target": TARGET,
                "order_type": "limit",
                "limit_price": "2",
                "time_in_force": "IOC",
            },
        )
        self.grant = replace(
            grant(),
            allowed_primitives=frozenset({EconomicPrimitive.BUY}),
            allowed_venues=frozenset({HYPERLIQUID_TESTNET_VENUE}),
            allowed_assets=frozenset({"HYPE", "USDC"}),
            allowed_targets=frozenset({TARGET}),
        )
        self.store.provision_grant(self.grant, canonical_hash(self.grant))
        self.permit_authority, self.permit_verifier = permit_stack(self.store, self.trust)
        self.risk = risk()

    def tearDown(self):
        self.store.close()

    def run_case(self, *, raise_after_effect):
        ledger = SharedTestnetLedger(raise_after_effect=raise_after_effect)
        submitter = HyperliquidTestnetAdapter(
            principal_id=PRINCIPAL,
            target=TARGET,
            markets=[MARKET],
            permit_verifier=self.permit_verifier,
            transport=LedgerTransport(ledger),
            clock=lambda: NOW,
        )
        verifier = HyperliquidTestnetSettlementVerifier(
            principal_id=PRINCIPAL,
            account_address=ACCOUNT,
            target=TARGET,
            markets=[MARKET],
            info_client=LedgerInfo(ledger, ExecutionRequest.from_intent(self.req_intent)),
        )
        runtime = FAARRuntime(
            self.store,
            {HYPERLIQUID_TESTNET_VENUE: submitter},
            verification_trust(self.trust),
            self.permit_authority,
            {HYPERLIQUID_TESTNET_VENUE: verifier},
            allow_test_time_override=True,
        )
        aa, ra = attest_pair(self.trust, self.req_intent, AUTH, self.risk)
        first = runtime.process(
            self.req_intent,
            AUTH,
            self.grant,
            self.risk,
            authority_attestation=aa,
            risk_attestation=ra,
            now=NOW,
        )
        replay = runtime.process(
            self.req_intent,
            AUTH,
            self.grant,
            self.risk,
            authority_attestation=aa,
            risk_attestation=ra,
            now=NOW,
        )
        return ledger, first, replay

    def test_runtime_finalizes_once_from_independent_testnet_read_path(self):
        ledger, first, replay = self.run_case(raise_after_effect=False)
        self.assertEqual(IntentState.FINALIZED, first.state)
        self.assertEqual("hyperliquid-testnet:order:101", first.effect_id)
        self.assertEqual(1, ledger.calls)
        self.assertTrue(replay.replayed)
        self.assertEqual(1, ledger.calls)

    def test_lost_submit_response_finalizes_only_from_independent_verifier(self):
        ledger, first, replay = self.run_case(raise_after_effect=True)
        self.assertEqual(IntentState.FINALIZED, first.state)
        self.assertEqual("hyperliquid-testnet:order:101", first.effect_id)
        self.assertEqual(1, ledger.calls)
        self.assertTrue(replay.replayed)
        self.assertEqual(1, ledger.calls)


if __name__ == "__main__":
    unittest.main()
