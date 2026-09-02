from __future__ import annotations

import hashlib
import json
import re
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_DOWN
from typing import Any, Callable, Mapping, Protocol, Sequence

from .adapters import AmbiguousExecution, DeterministicFailure, REFERENCE_SAFE_PROFILE
from .canonical import canonical_hash, canonical_json, parse_bounded_decimal
from .models import (
    EconomicPrimitive,
    ExecutionReceipt,
    ExecutionRequest,
    SettlementRecord,
    SettlementStatus,
    SignedExecutionPermit,
    utcnow,
)
from .permits import ExecutionPermitVerifier
from .settlement import REFERENCE_SETTLEMENT_PROFILE


HYPERLIQUID_TESTNET_URL = "https://api.hyperliquid-testnet.xyz"
HYPERLIQUID_TESTNET_VENUE = "hyperliquid-testnet"

_MAX_HTTP_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_FILL_PAGE_ITEMS = 2_000
_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
_CLOID_RE = re.compile(r"0x[0-9a-f]{32}\Z")
_SIGNATURE_RE = re.compile(r"0x[0-9a-fA-F]{64}\Z")
_AMOUNT_QUANTUM = Decimal("0.00000001")

_CANCELLED_STATUSES = frozenset({
    "canceled",
    "marginCanceled",
    "vaultWithdrawalCanceled",
    "openInterestCapCanceled",
    "selfTradeCanceled",
    "reduceOnlyCanceled",
    "siblingFilledCanceled",
    "delistedCanceled",
    "liquidatedCanceled",
    "scheduledCancel",
})
_REJECTED_STATUSES = frozenset({
    "rejected",
    "tickRejected",
    "minTradeNtlRejected",
    "perpMarginRejected",
    "reduceOnlyRejected",
    "badAloPxRejected",
    "iocCancelRejected",
    "badTriggerPxRejected",
    "marketOrderNoLiquidityRejected",
    "positionIncreaseAtOpenInterestCapRejected",
    "positionFlipAtOpenInterestCapRejected",
    "tooAggressiveAtOpenInterestCapRejected",
    "openInterestIncreaseRejected",
    "insufficientSpotBalanceRejected",
    "oracleRejected",
    "perpMaxPositionRejected",
})


class HyperliquidTransportError(RuntimeError):
    """A bounded transport/signing failure with no settlement interpretation."""


@dataclass(frozen=True)
class HyperliquidSpotMarket:
    """Operator-pinned testnet market identity and precision."""

    base_asset: str
    quote_asset: str
    coin: str
    asset_id: int
    sz_decimals: int
    min_notional_usd: Decimal = Decimal("10")

    def __post_init__(self) -> None:
        if not all(isinstance(v, str) and 0 < len(v) <= 128 for v in (self.base_asset, self.quote_asset, self.coin)):
            raise ValueError("Hyperliquid market names must be non-empty bounded strings")
        if self.quote_asset != "USDC":
            raise ValueError("the testnet adapter supports USDC-quoted spot markets only")
        if isinstance(self.asset_id, bool) or not isinstance(self.asset_id, int) or not 10_000 <= self.asset_id < 100_000_000:
            raise ValueError("Hyperliquid spot asset_id must be in the non-outcome spot range")
        if isinstance(self.sz_decimals, bool) or not isinstance(self.sz_decimals, int) or not 0 <= self.sz_decimals <= 8:
            raise ValueError("Hyperliquid spot sz_decimals must be an integer from 0 through 8")
        minimum = parse_bounded_decimal(self.min_notional_usd)
        if minimum is None or minimum <= 0:
            raise ValueError("Hyperliquid min_notional_usd must be a positive bounded Decimal")
        object.__setattr__(self, "min_notional_usd", minimum)


@dataclass(frozen=True)
class HyperliquidIOCOrder:
    """The complete order shape the constrained signer may authorize."""

    cloid: str
    coin: str
    asset_id: int
    limit_price: Decimal
    size: Decimal
    authorized_notional_usd: Decimal

    def __post_init__(self) -> None:
        if not _CLOID_RE.fullmatch(self.cloid):
            raise ValueError("Hyperliquid cloid must be a lowercase 128-bit hex string")
        if not isinstance(self.coin, str) or not 0 < len(self.coin) <= 128:
            raise ValueError("Hyperliquid coin must be a non-empty bounded string")
        if isinstance(self.asset_id, bool) or not isinstance(self.asset_id, int) or not 10_000 <= self.asset_id < 100_000_000:
            raise ValueError("Hyperliquid IOC asset_id must be in the non-outcome spot range")
        for name in ("limit_price", "size", "authorized_notional_usd"):
            value = getattr(self, name)
            if not isinstance(value, Decimal) or not value.is_finite() or value <= 0:
                raise ValueError(f"Hyperliquid IOC {name} must be a positive finite Decimal")
        authorized = parse_bounded_decimal(self.authorized_notional_usd)
        if authorized is None:
            raise ValueError("Hyperliquid IOC authorization is outside FAAR's amount bounds")
        if _quote_amount_ceiling(self.size * self.limit_price) > authorized:
            raise ValueError("Hyperliquid IOC order exceeds its authorized notional")
        object.__setattr__(self, "authorized_notional_usd", authorized)

    @property
    def price_wire(self) -> str:
        return _wire_decimal(self.limit_price)

    @property
    def size_wire(self) -> str:
        return _wire_decimal(self.size)


class HyperliquidOrderTransport(Protocol):
    base_url: str

    def submit_ioc_order(
        self, order: HyperliquidIOCOrder, *, nonce: int, expires_after_ms: int
    ) -> Mapping[str, Any]: ...


class HyperliquidInfoClient(Protocol):
    base_url: str

    def query_order_by_cloid(self, account_address: str, cloid: str) -> Mapping[str, Any]: ...

    def user_fills_by_time(
        self, account_address: str, start_time_ms: int, *, aggregate_by_time: bool
    ) -> Sequence[Mapping[str, Any]]: ...


class HyperliquidTestnetActionSigner(Protocol):
    """Narrow signer boundary. Implementations must independently validate the action."""

    signer_id: str

    def sign_ioc_order_action(
        self,
        action: Mapping[str, Any],
        *,
        nonce: int,
        expires_after_ms: int,
        vault_address: str | None,
    ) -> Mapping[str, Any]: ...


def hyperliquid_cloid(request: ExecutionRequest) -> str:
    """Stable 128-bit client-order identity for one principal-namespaced intent."""

    seed = canonical_json({
        "domain": "faar:hyperliquid-testnet:cloid:v1",
        "principal_id": request.principal_id,
        "intent_id": request.intent_id,
    })
    return "0x" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def _epoch_millis(value: datetime) -> int:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Hyperliquid timestamps must be timezone-aware")
    delta = value.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (delta.days * 86_400 + delta.seconds) * 1_000 + delta.microseconds // 1_000


def _wire_decimal(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    return format(normalized, "f")


def _quote_amount_ceiling(value: Decimal) -> Decimal:
    """Conservatively fit a quote notional into FAAR's eight-decimal ledger."""

    if not value.is_finite() or value < 0:
        raise ValueError("quote amount must be finite and non-negative")
    try:
        rounded = value.quantize(_AMOUNT_QUANTUM, rounding=ROUND_CEILING)
    except InvalidOperation:
        raise ValueError("quote amount cannot be represented") from None
    bounded = parse_bounded_decimal(rounded)
    if bounded is None:
        raise ValueError("quote amount is outside FAAR's amount bounds")
    return bounded


def _valid_spot_price(price: Decimal, sz_decimals: int) -> bool:
    normalized = price.normalize()
    if normalized == normalized.to_integral_value():
        return True
    decimal_places = max(0, -normalized.as_tuple().exponent)
    significant_figures = len(normalized.as_tuple().digits)
    return significant_figures <= 5 and decimal_places <= 8 - sz_decimals


def _request_order(
    request: ExecutionRequest,
    *,
    principal_id: str,
    target: str,
    markets: Mapping[tuple[str, str], HyperliquidSpotMarket],
) -> HyperliquidIOCOrder:
    if request.venue != HYPERLIQUID_TESTNET_VENUE:
        raise DeterministicFailure("HL_VENUE_MISMATCH")
    if request.principal_id != principal_id:
        raise DeterministicFailure("HL_PRINCIPAL_MISMATCH")
    if request.primitive != EconomicPrimitive.BUY:
        raise DeterministicFailure("HL_BUY_ONLY")

    payload = request.payload
    if not isinstance(payload.get("target"), str) or payload["target"] != target:
        raise DeterministicFailure("HL_TARGET_MISMATCH")
    if not isinstance(payload.get("order_type"), str) or payload["order_type"].lower() != "limit":
        raise DeterministicFailure("HL_LIMIT_ORDER_REQUIRED")
    if not isinstance(payload.get("time_in_force"), str) or payload["time_in_force"].upper() != "IOC":
        raise DeterministicFailure("HL_IOC_REQUIRED")
    if "max_slippage_bps" in payload:
        # A second price-relative bound would require an independently sourced
        # reference price. This slice enforces exactly the signed absolute limit.
        raise DeterministicFailure("HL_ABSOLUTE_LIMIT_ONLY")

    amount_fields = [field for field in ("amount_usd", "notional_usd") if field in payload]
    if len(amount_fields) != 1:
        raise DeterministicFailure("HL_ONE_NOTIONAL_REQUIRED")
    notional = parse_bounded_decimal(payload.get(amount_fields[0]))
    if notional is None or notional <= 0:
        raise DeterministicFailure("HL_NOTIONAL_INVALID")
    limit_price = parse_bounded_decimal(payload.get("limit_price"))
    if limit_price is None or limit_price <= 0:
        raise DeterministicFailure("HL_LIMIT_PRICE_INVALID")

    base_asset = payload.get("base_asset")
    quote_asset = payload.get("quote_asset")
    if not isinstance(base_asset, str) or not isinstance(quote_asset, str):
        raise DeterministicFailure("HL_MARKET_NOT_PINNED")
    pair = (base_asset, quote_asset)
    market = markets.get(pair)
    if market is None:
        raise DeterministicFailure("HL_MARKET_NOT_PINNED")
    if not _valid_spot_price(limit_price, market.sz_decimals):
        raise DeterministicFailure("HL_LIMIT_PRICE_PRECISION_INVALID")

    quantum = Decimal(1).scaleb(-market.sz_decimals)
    try:
        size = (notional / limit_price).quantize(quantum, rounding=ROUND_DOWN)
    except (InvalidOperation, ZeroDivisionError):
        raise DeterministicFailure("HL_SIZE_UNREPRESENTABLE") from None
    if size <= 0:
        raise DeterministicFailure("HL_SIZE_ROUNDS_TO_ZERO")
    try:
        bounded_order_notional = _quote_amount_ceiling(size * limit_price)
    except ValueError:
        raise DeterministicFailure("HL_ORDER_NOTIONAL_INVALID") from None
    if bounded_order_notional > notional:
        size -= quantum
        if size <= 0:
            raise DeterministicFailure("HL_SIZE_ROUNDS_TO_ZERO")
        try:
            bounded_order_notional = _quote_amount_ceiling(size * limit_price)
        except ValueError:
            raise DeterministicFailure("HL_ORDER_NOTIONAL_INVALID") from None
    if bounded_order_notional > notional:
        raise DeterministicFailure("HL_ORDER_NOTIONAL_INVALID")
    if bounded_order_notional < market.min_notional_usd:
        # Never round up to satisfy a venue minimum: that broadens authority.
        raise DeterministicFailure("HL_ORDER_BELOW_VENUE_MINIMUM")

    return HyperliquidIOCOrder(
        cloid=hyperliquid_cloid(request),
        coin=market.coin,
        asset_id=market.asset_id,
        limit_price=limit_price,
        size=size,
        authorized_notional_usd=notional,
    )


class HyperliquidTestnetAdapter:
    """Permit-consuming Hyperliquid spot BUY adapter, hard-bound to testnet.

    Only signed limit-IOC orders are admitted. The venue nonce is the permit's
    millisecond issue time and the signed action expires with the permit. Replaying
    the same envelope is rejected by the venue nonce set; replaying through this
    object is additionally stopped by the durable single-use permit ledger.
    """

    name = HYPERLIQUID_TESTNET_VENUE
    security_profile = REFERENCE_SAFE_PROFILE

    def __init__(
        self,
        *,
        principal_id: str,
        target: str,
        markets: Sequence[HyperliquidSpotMarket],
        permit_verifier: ExecutionPermitVerifier,
        transport: HyperliquidOrderTransport,
        clock: Callable[[], datetime] = utcnow,
        minimum_submission_window_ms: int = 250,
    ) -> None:
        if not principal_id or not target:
            raise ValueError("Hyperliquid principal_id and target are required")
        if getattr(transport, "base_url", None) != HYPERLIQUID_TESTNET_URL:
            raise ValueError("Hyperliquid adapter transport must be hard-bound to the testnet origin")
        if isinstance(minimum_submission_window_ms, bool) or not isinstance(minimum_submission_window_ms, int) or minimum_submission_window_ms < 0:
            raise ValueError("minimum_submission_window_ms must be a non-negative integer")
        pinned: dict[tuple[str, str], HyperliquidSpotMarket] = {}
        for market in markets:
            key = (market.base_asset, market.quote_asset)
            if key in pinned:
                raise ValueError("duplicate Hyperliquid market mapping")
            pinned[key] = market
        if not pinned:
            raise ValueError("at least one Hyperliquid testnet market must be pinned")
        self.principal_id = principal_id
        self.target = target
        self.markets = pinned
        self.permit_verifier = permit_verifier
        self.transport = transport
        self.clock = clock
        self.minimum_submission_window_ms = minimum_submission_window_ms

    def execute(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        order = _request_order(
            request, principal_id=self.principal_id, target=self.target, markets=self.markets
        )
        now = self.clock()
        expires_after_ms = _epoch_millis(permit.permit.expires_at)
        now_ms = _epoch_millis(now)
        if expires_after_ms - now_ms < self.minimum_submission_window_ms:
            raise DeterministicFailure("HL_PERMIT_WINDOW_TOO_SHORT")

        ok, reasons = self.permit_verifier.consume(permit, request, now=now, venue=self.name)
        if not ok:
            raise DeterministicFailure("HL_PERMIT_REJECTED:" + ",".join(reasons))

        # The nonce and expiry are both signed into the exact action. There is no
        # automatic application retry here; a lost response is reconciled by cloid.
        nonce = _epoch_millis(permit.permit.issued_at)
        try:
            response = self.transport.submit_ioc_order(
                order, nonce=nonce, expires_after_ms=expires_after_ms
            )
            return self._receipt(request, order, response)
        except AmbiguousExecution:
            raise
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise AmbiguousExecution("HL_SUBMISSION_AMBIGUOUS:" + type(exc).__name__) from exc

    def _receipt(
        self,
        request: ExecutionRequest,
        order: HyperliquidIOCOrder,
        response: Mapping[str, Any],
    ) -> ExecutionReceipt:
        try:
            if not isinstance(response, Mapping) or response.get("status") != "ok":
                raise ValueError("top-level response was not ok")
            body = response["response"]
            if not isinstance(body, Mapping) or body.get("type") != "order":
                raise ValueError("response was not an order")
            data = body["data"]
            statuses = data["statuses"] if isinstance(data, Mapping) else None
            if not isinstance(statuses, (list, tuple)) or len(statuses) != 1:
                raise ValueError("response did not contain one status")
            status = statuses[0]
            if not isinstance(status, Mapping):
                raise ValueError("order status was malformed")
            if "filled" in status:
                fill = status["filled"]
                if not isinstance(fill, Mapping):
                    raise ValueError("fill status was malformed")
                oid = _positive_int(fill.get("oid"))
                total_size = _positive_decimal(fill.get("totalSz"))
                average_price = _positive_decimal(fill.get("avgPx"))
                amount = _quote_amount_ceiling(total_size * average_price)
                effect_id = _effect_id(self.name, oid)
                return ExecutionReceipt(
                    effect_id=effect_id,
                    status=SettlementStatus.FINALIZED,
                    amount_usd=amount,
                    evidence={
                        "venue": self.name,
                        "network": "testnet",
                        "cloid": order.cloid,
                        "oid": oid,
                        "request_hash": canonical_hash(request),
                        "reported_total_size": _wire_decimal(total_size),
                        "reported_average_price": _wire_decimal(average_price),
                    },
                )
            # An IOC must never rest. Rejections may or may not have made an
            # authoritative order-status record, so both cases require lookup.
            if "resting" in status:
                raise ValueError("IOC unexpectedly rested")
            if "error" in status:
                raise ValueError("venue reported an order error")
            raise ValueError("unknown order response")
        except Exception as exc:
            raise AmbiguousExecution("HL_RESPONSE_REQUIRES_RECONCILIATION:" + type(exc).__name__) from exc


def _positive_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError("expected a positive integer")
    return value


def _decimal(value: object) -> Decimal:
    parsed = parse_bounded_decimal(value)
    if parsed is None:
        raise ValueError("expected a bounded decimal")
    return parsed


def _positive_decimal(value: object) -> Decimal:
    parsed = _decimal(value)
    if parsed <= 0:
        raise ValueError("expected a positive decimal")
    return parsed


def _effect_id(venue: str, oid: int) -> str:
    return f"{venue}:order:{oid}"


class HyperliquidTestnetSettlementVerifier:
    """Independent order/fill read path for the constrained testnet adapter.

    Missing orders and transport failures are deliberately non-authoritative.
    Positive and terminal order records are bound back to every submitted order
    term before they receive weight.
    """

    name = "hyperliquid-testnet-info"
    security_profile = REFERENCE_SETTLEMENT_PROFILE

    def __init__(
        self,
        *,
        principal_id: str,
        account_address: str,
        target: str,
        markets: Sequence[HyperliquidSpotMarket],
        info_client: HyperliquidInfoClient,
        fill_page_limit: int = 2_000,
    ) -> None:
        if not principal_id or not target:
            raise ValueError("Hyperliquid principal_id and target are required")
        if not _ADDRESS_RE.fullmatch(account_address):
            raise ValueError("Hyperliquid account_address must be a 20-byte hex address")
        if getattr(info_client, "base_url", None) != HYPERLIQUID_TESTNET_URL:
            raise ValueError("Hyperliquid verifier client must be hard-bound to the testnet origin")
        if (
            isinstance(fill_page_limit, bool)
            or not isinstance(fill_page_limit, int)
            or not 1 <= fill_page_limit <= _MAX_FILL_PAGE_ITEMS
        ):
            raise ValueError("fill_page_limit must be an integer from 1 through 2000")
        pinned: dict[tuple[str, str], HyperliquidSpotMarket] = {}
        for market in markets:
            key = (market.base_asset, market.quote_asset)
            if key in pinned:
                raise ValueError("duplicate Hyperliquid market mapping")
            pinned[key] = market
        if not pinned:
            raise ValueError("at least one Hyperliquid testnet market must be pinned")
        self.principal_id = principal_id
        self.account_address = account_address.lower()
        self.target = target
        self.markets = pinned
        self.info_client = info_client
        self.fill_page_limit = fill_page_limit

    def verify(self, request: ExecutionRequest) -> SettlementRecord:
        request_hash = canonical_hash(request)
        cloid = hyperliquid_cloid(request)
        try:
            order = _request_order(
                request, principal_id=self.principal_id, target=self.target, markets=self.markets
            )
            response = self.info_client.query_order_by_cloid(self.account_address, cloid)
            return self._record(request_hash, order, response)
        except DeterministicFailure as exc:
            return SettlementRecord(
                SettlementStatus.UNKNOWN,
                evidence={"verifier": self.name, "reason": str(exc)[:256]},
                authoritative=False,
            )
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            return SettlementRecord(
                SettlementStatus.UNKNOWN,
                evidence={"verifier": self.name, "reason": "HL_INFO_UNAVAILABLE", "type": type(exc).__name__},
                authoritative=False,
            )

    def _record(
        self,
        request_hash: str,
        expected: HyperliquidIOCOrder,
        response: Mapping[str, Any],
    ) -> SettlementRecord:
        if not isinstance(response, Mapping):
            raise ValueError("order lookup did not return an object")
        if response.get("status") == "unknownOid":
            return SettlementRecord(
                SettlementStatus.UNKNOWN,
                evidence={"verifier": self.name, "reason": "HL_ORDER_NOT_FOUND", "cloid": expected.cloid},
                authoritative=False,
            )
        if response.get("status") != "order" or not isinstance(response.get("order"), Mapping):
            raise ValueError("order lookup envelope was malformed")
        result = response["order"]
        details = result.get("order")
        status = result.get("status")
        if not isinstance(details, Mapping) or not isinstance(status, str):
            raise ValueError("order lookup record was malformed")

        mismatch = self._binding_mismatch(expected, details)
        if mismatch is not None:
            return self._contradiction(request_hash, expected, mismatch)
        oid = _positive_int(details.get("oid"))
        original_size = _decimal(details.get("origSz"))
        remaining_size = _decimal(details.get("sz"))
        if remaining_size < 0 or remaining_size > original_size:
            return self._contradiction(request_hash, expected, "HL_REMAINING_SIZE_INVALID")
        venue_filled_size = original_size - remaining_size

        if status in {"open", "triggered"}:
            return self._contradiction(request_hash, expected, "HL_IOC_NONTERMINAL_STATUS")
        if status not in _CANCELLED_STATUSES | _REJECTED_STATUSES | {"filled"}:
            return SettlementRecord(
                SettlementStatus.UNKNOWN,
                evidence={
                    "verifier": self.name,
                    "reason": "HL_STATUS_UNRECOGNIZED",
                    "cloid": expected.cloid,
                    "oid": oid,
                },
                authoritative=False,
            )

        timestamp = details.get("timestamp")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
            return self._contradiction(request_hash, expected, "HL_ORDER_TIMESTAMP_INVALID")
        fills = self.info_client.user_fills_by_time(
            self.account_address, timestamp, aggregate_by_time=True
        )
        if not isinstance(fills, (list, tuple)):
            raise ValueError("fill lookup did not return a sequence")
        if len(fills) >= self.fill_page_limit:
            return SettlementRecord(
                SettlementStatus.UNKNOWN,
                evidence={
                    "verifier": self.name,
                    "reason": "HL_FILL_PAGE_MAY_BE_TRUNCATED",
                    "cloid": expected.cloid,
                    "oid": oid,
                },
                authoritative=False,
            )

        fill_result = self._fills(expected, oid, fills)
        if isinstance(fill_result, str):
            return self._contradiction(request_hash, expected, fill_result)
        observed_size, amount_usd, fill_facts = fill_result
        if observed_size > venue_filled_size:
            return self._contradiction(request_hash, expected, "HL_FILL_TOTAL_EXCEEDS_ORDER")
        if observed_size < venue_filled_size:
            return SettlementRecord(
                SettlementStatus.UNKNOWN,
                evidence={
                    "verifier": self.name,
                    "reason": "HL_FILL_HISTORY_INCOMPLETE",
                    "cloid": expected.cloid,
                    "oid": oid,
                    "venue_filled_size": _wire_decimal(venue_filled_size),
                    "observed_filled_size": _wire_decimal(observed_size),
                },
                authoritative=False,
            )
        if amount_usd > expected.authorized_notional_usd:
            return self._contradiction(request_hash, expected, "HL_FILL_EXCEEDS_AUTHORIZED_NOTIONAL")

        if status == "filled":
            if remaining_size != 0 or observed_size != original_size or amount_usd <= 0:
                return self._contradiction(request_hash, expected, "HL_FILLED_STATUS_INCONSISTENT")
            settlement_status = SettlementStatus.FINALIZED
        else:
            if status in _REJECTED_STATUSES and observed_size != 0:
                return self._contradiction(request_hash, expected, "HL_REJECTION_HAS_FILL")
            settlement_status = SettlementStatus.CANCELLED

        evidence = {
            "verifier": self.name,
            "venue": HYPERLIQUID_TESTNET_VENUE,
            "network": "testnet",
            "account_address": self.account_address,
            "cloid": expected.cloid,
            "oid": oid,
            "venue_status": status,
            "status_timestamp": result.get("statusTimestamp"),
            "coin": expected.coin,
            "side": "B",
            "time_in_force": "Ioc",
            "limit_price": expected.price_wire,
            "order_size": expected.size_wire,
            "filled_size": _wire_decimal(observed_size),
            "fill_count": len(fill_facts),
            "fills_hash": canonical_hash(fill_facts),
        }
        return SettlementRecord(
            settlement_status,
            effect_id=_effect_id(HYPERLIQUID_TESTNET_VENUE, oid),
            amount_usd=amount_usd,
            evidence=evidence,
            authoritative=True,
            verified_request_hash=request_hash,
        )

    @staticmethod
    def _binding_mismatch(expected: HyperliquidIOCOrder, details: Mapping[str, Any]) -> str | None:
        checks = (
            (isinstance(details.get("cloid"), str) and details["cloid"].lower() == expected.cloid, "HL_CLOID_MISMATCH"),
            (details.get("coin") == expected.coin, "HL_COIN_MISMATCH"),
            (details.get("side") == "B", "HL_SIDE_MISMATCH"),
            (details.get("orderType") == "Limit", "HL_ORDER_TYPE_MISMATCH"),
            (details.get("tif") == "Ioc", "HL_TIF_MISMATCH"),
            (details.get("reduceOnly") is False, "HL_REDUCE_ONLY_MISMATCH"),
            (details.get("isTrigger") is False, "HL_TRIGGER_MISMATCH"),
        )
        for ok, reason in checks:
            if not ok:
                return reason
        try:
            if _decimal(details.get("limitPx")) != expected.limit_price:
                return "HL_LIMIT_PRICE_MISMATCH"
            if _decimal(details.get("origSz")) != expected.size:
                return "HL_ORIGINAL_SIZE_MISMATCH"
        except ValueError:
            return "HL_ORDER_DECIMAL_MALFORMED"
        return None

    @staticmethod
    def _fills(
        expected: HyperliquidIOCOrder,
        oid: int,
        fills: Sequence[Mapping[str, Any]],
    ) -> tuple[Decimal, Decimal, list[dict[str, Any]]] | str:
        by_tid: dict[str, tuple[Decimal, Decimal, dict[str, Any]]] = {}
        for fill in fills:
            if not isinstance(fill, Mapping) or fill.get("oid") != oid:
                continue
            if fill.get("coin") != expected.coin:
                return "HL_FILL_COIN_MISMATCH"
            if fill.get("side") != "B":
                return "HL_FILL_SIDE_MISMATCH"
            try:
                size = _positive_decimal(fill.get("sz"))
                price = _positive_decimal(fill.get("px"))
            except ValueError:
                return "HL_FILL_DECIMAL_MALFORMED"
            if price > expected.limit_price:
                return "HL_FILL_PRICE_EXCEEDS_LIMIT"
            tid = fill.get("tid")
            if isinstance(tid, bool) or not isinstance(tid, (int, str)) or not str(tid):
                return "HL_FILL_ID_MALFORMED"
            fact = {
                "tid": str(tid),
                "price": _wire_decimal(price),
                "size": _wire_decimal(size),
            }
            existing = by_tid.get(str(tid))
            if existing is not None and existing[2] != fact:
                return "HL_FILL_ID_CONTRADICTION"
            by_tid[str(tid)] = (size, price, fact)
        observed_size = sum((value[0] for value in by_tid.values()), Decimal("0"))
        amount_usd = sum((value[0] * value[1] for value in by_tid.values()), Decimal("0"))
        try:
            bounded_amount = _quote_amount_ceiling(amount_usd)
        except ValueError:
            return "HL_FILL_AMOUNT_UNBOUNDED"
        facts = [by_tid[key][2] for key in sorted(by_tid)]
        return observed_size, bounded_amount, facts

    def _contradiction(
        self, request_hash: str, expected: HyperliquidIOCOrder, reason: str
    ) -> SettlementRecord:
        return SettlementRecord(
            SettlementStatus.CONTRADICTORY,
            evidence={
                "verifier": self.name,
                "reason": reason,
                "cloid": expected.cloid,
            },
            authoritative=True,
            verified_request_hash=request_hash,
        )


class _HyperliquidTestnetHTTP:
    base_url = HYPERLIQUID_TESTNET_URL

    def __init__(
        self,
        *,
        timeout_seconds: float,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= 10:
            raise ValueError("Hyperliquid HTTP timeout must be in (0, 10] seconds")
        self.timeout_seconds = float(timeout_seconds)
        # POST redirects could forward the signed testnet envelope to another
        # origin. The default opener therefore refuses redirects entirely.
        self._opener = opener or urllib.request.build_opener(_NoRedirectHandler()).open

    def _post(self, path: str, payload: Mapping[str, Any]) -> Any:
        if path not in {"/exchange", "/info"}:
            raise HyperliquidTransportError("HL_HTTP_PATH_REFUSED")
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii"),
            headers={"Content-Type": "application/json", "User-Agent": "faar-runtime/0.4"},
            method="POST",
        )
        response = None
        try:
            response = self._opener(request, timeout=self.timeout_seconds)
            raw = response.read(_MAX_HTTP_RESPONSE_BYTES + 1)
        except (TimeoutError, socket.timeout):
            raise HyperliquidTransportError("HL_HTTP_TIMEOUT") from None
        except urllib.error.HTTPError as exc:
            raise HyperliquidTransportError(f"HL_HTTP_STATUS_{exc.code}") from None
        except urllib.error.URLError:
            raise HyperliquidTransportError("HL_HTTP_UNAVAILABLE") from None
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
        if len(raw) > _MAX_HTTP_RESPONSE_BYTES:
            raise HyperliquidTransportError("HL_HTTP_RESPONSE_TOO_LARGE")
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HyperliquidTransportError("HL_HTTP_RESPONSE_INVALID") from None


class HyperliquidTestnetHTTPTransport(_HyperliquidTestnetHTTP):
    """One-shot testnet order transport. It never retries a POST automatically."""

    def __init__(
        self,
        signer: HyperliquidTestnetActionSigner,
        *,
        vault_address: str | None = None,
        timeout_seconds: float = 2.0,
        opener: Callable[..., Any] | None = None,
    ) -> None:
        super().__init__(timeout_seconds=timeout_seconds, opener=opener)
        if not getattr(signer, "signer_id", None):
            raise ValueError("Hyperliquid signer_id is required")
        if vault_address is not None and not _ADDRESS_RE.fullmatch(vault_address):
            raise ValueError("Hyperliquid vault_address must be a 20-byte hex address")
        self._signer = signer
        self.vault_address = None if vault_address is None else vault_address.lower()

    def submit_ioc_order(
        self, order: HyperliquidIOCOrder, *, nonce: int, expires_after_ms: int
    ) -> Mapping[str, Any]:
        if not isinstance(order, HyperliquidIOCOrder) or not _CLOID_RE.fullmatch(order.cloid):
            raise HyperliquidTransportError("HL_ORDER_MALFORMED")
        if isinstance(nonce, bool) or not isinstance(nonce, int) or nonce < 0:
            raise HyperliquidTransportError("HL_NONCE_INVALID")
        if isinstance(expires_after_ms, bool) or not isinstance(expires_after_ms, int) or expires_after_ms <= nonce:
            raise HyperliquidTransportError("HL_EXPIRY_INVALID")
        action = {
            "type": "order",
            "orders": [{
                "a": order.asset_id,
                "b": True,
                "p": order.price_wire,
                "s": order.size_wire,
                "r": False,
                "t": {"limit": {"tif": "Ioc"}},
                "c": order.cloid,
            }],
            "grouping": "na",
        }
        # Do not let an in-process signer callback broaden the object that is
        # subsequently transported. A real signer is a separate trust boundary,
        # but the Python interface still fails closed if an implementation mutates
        # its input while inspecting it.
        signing_action = json.loads(json.dumps(action, separators=(",", ":")))
        try:
            signature = dict(self._signer.sign_ioc_order_action(
                signing_action,
                nonce=nonce,
                expires_after_ms=expires_after_ms,
                vault_address=self.vault_address,
            ))
        except Exception as exc:
            raise HyperliquidTransportError("HL_SIGNER_UNAVAILABLE:" + type(exc).__name__) from exc
        if signing_action != action:
            raise HyperliquidTransportError("HL_SIGNED_ACTION_MUTATED")
        if (
            not _SIGNATURE_RE.fullmatch(str(signature.get("r", "")))
            or not _SIGNATURE_RE.fullmatch(str(signature.get("s", "")))
            or isinstance(signature.get("v"), bool)
            or signature.get("v") not in {27, 28}
        ):
            raise HyperliquidTransportError("HL_SIGNATURE_MALFORMED")
        response = self._post("/exchange", {
            "action": action,
            "nonce": nonce,
            "signature": {"r": signature["r"], "s": signature["s"], "v": signature["v"]},
            "vaultAddress": self.vault_address,
            "expiresAfter": expires_after_ms,
        })
        if not isinstance(response, Mapping):
            raise HyperliquidTransportError("HL_ORDER_RESPONSE_MALFORMED")
        return response


class HyperliquidTestnetInfoAPI(_HyperliquidTestnetHTTP):
    """Credential-free testnet `/info` client kept separate from submission."""

    def __init__(
        self, *, timeout_seconds: float = 2.0, opener: Callable[..., Any] | None = None
    ) -> None:
        super().__init__(timeout_seconds=timeout_seconds, opener=opener)

    def query_order_by_cloid(self, account_address: str, cloid: str) -> Mapping[str, Any]:
        response = self._post("/info", {"type": "orderStatus", "user": account_address, "oid": cloid})
        if not isinstance(response, Mapping):
            raise HyperliquidTransportError("HL_ORDER_LOOKUP_MALFORMED")
        return response

    def user_fills_by_time(
        self, account_address: str, start_time_ms: int, *, aggregate_by_time: bool
    ) -> Sequence[Mapping[str, Any]]:
        response = self._post("/info", {
            "type": "userFillsByTime",
            "user": account_address,
            "startTime": start_time_ms,
            "aggregateByTime": aggregate_by_time,
        })
        if not isinstance(response, list) or any(not isinstance(item, Mapping) for item in response):
            raise HyperliquidTransportError("HL_FILL_LOOKUP_MALFORMED")
        return response


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401 - stdlib hook
        return None
