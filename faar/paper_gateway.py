"""Paper venue gateway: permit-verifying book with a split submit/query path.

This is not a live-money adapter. Submit and query use different clients and
credentials, but both routes reach the same in-memory venue process and economic
ground truth; this is role separation, not an independently operated verifier.
The venue process consumes the permit, enforces the request's ``limit_price``
bound, and refuses to fill a cancelled order.

Tests drive it in-process or over loopback HTTP. Neither path talks to a funded
venue or holds a production credential.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import http.server
import ipaddress
import json
import math
import threading
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlparse

from .adapters import (
    AmbiguousExecution,
    AdapterSecurityProfile,
    DeterministicFailure,
    REFERENCE_SAFE_PROFILE,
)
from .canonical import canonical_hash, canonical_json, parse_bounded_decimal
from .models import (
    EconomicPrimitive,
    ExecutionPermit,
    ExecutionReceipt,
    ExecutionRequest,
    PermitAlgorithm,
    SettlementRecord,
    SettlementStatus,
    SignedExecutionPermit,
    utcnow,
)
from .permits import ExecutionPermitVerifier
from .settlement import REFERENCE_SETTLEMENT_PROFILE, SettlementSecurityProfile


STABLE_ASSETS = frozenset({"USD", "USDC", "USDT"})
PAPER_QUOTE_ASSET = "USDC"
MAX_WIRE_BODY_BYTES = 64 * 1024
DEFAULT_HTTP_TIMEOUT_SECONDS = 2.0
ORDER_PRIMITIVES = frozenset({
    EconomicPrimitive.BUY,
    EconomicPrimitive.SELL,
})
SUPPORTED_TIME_IN_FORCE = frozenset({"IOC", "GTC"})
_REQUEST_WIRE_FIELDS = frozenset({"principal_id", "intent_id", "primitive", "venue", "payload"})
_PERMIT_WIRE_FIELDS = frozenset({"permit", "signer_id", "algorithm", "signature"})
_PERMIT_BODY_WIRE_FIELDS = frozenset({
    "permit_id",
    "principal_id",
    "intent_id",
    "grant_id",
    "grant_version",
    "grant_hash",
    "request_hash",
    "authority_attestation_hash",
    "risk_attestation_hash",
    "grant_epoch",
    "fence_token",
    "max_amount_usd",
    "issued_at",
    "expires_at",
})


class PaperOrderState(StrEnum):
    PENDING = "PENDING"
    FILLED = "FILLED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"


class VenueRole(StrEnum):
    SUBMIT = "submit"
    QUERY = "query"


@dataclass(frozen=True)
class VenueCredential:
    """Narrow role token presented to the venue. Query cannot submit; submit cannot query."""

    role: VenueRole
    token: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", VenueRole(self.role))
        _validate_role_token(self.token)


def _validate_role_token(token: object) -> str:
    if (
        not isinstance(token, str)
        or not token
        or len(token) > 4096
        or not token.isascii()
        or any(char.isspace() for char in token)
    ):
        raise ValueError("venue credential token must be a bounded non-whitespace ASCII string")
    return token


def _wire_keys(data: object, expected: frozenset[str], code: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping) or set(data) != expected:
        raise DeterministicFailure(code)
    return data


def _wire_string(data: Mapping[str, Any], field: str, code: str) -> str:
    value = data[field]
    if not isinstance(value, str):
        raise DeterministicFailure(code)
    return value


def _wire_int(data: Mapping[str, Any], field: str, code: str) -> int:
    value = data[field]
    if type(value) is not int:
        raise DeterministicFailure(code)
    return value


def _wire_datetime(data: Mapping[str, Any], field: str, code: str) -> datetime:
    raw = _wire_string(data, field, code)
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise DeterministicFailure(code) from exc
    if value.isoformat() != raw:
        raise DeterministicFailure(code)
    return value


def client_order_id(request: ExecutionRequest) -> str:
    """Stable, namespace-safe venue identity derived from the FAAR intent."""

    seed = canonical_json({
        "domain": "faar:paper-gateway:client-order-id:v1",
        "principal_id": request.principal_id,
        "intent_id": request.intent_id,
    })
    return "pco_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]


def request_to_wire(request: ExecutionRequest) -> dict[str, Any]:
    return json.loads(canonical_json(request))


def permit_to_wire(permit: SignedExecutionPermit) -> dict[str, Any]:
    return json.loads(canonical_json(permit))


def request_from_wire(data: object) -> ExecutionRequest:
    code = "MALFORMED_REQUEST"
    try:
        data = _wire_keys(data, _REQUEST_WIRE_FIELDS, code)
        payload = data["payload"]
        if not isinstance(payload, Mapping):
            raise DeterministicFailure(code)
        return ExecutionRequest(
            principal_id=_wire_string(data, "principal_id", code),
            intent_id=_wire_string(data, "intent_id", code),
            primitive=EconomicPrimitive(_wire_string(data, "primitive", code)),
            venue=_wire_string(data, "venue", code),
            payload=dict(payload),
        )
    except DeterministicFailure:
        raise
    except Exception as exc:
        raise DeterministicFailure("MALFORMED_REQUEST") from exc


def permit_from_wire(data: object) -> SignedExecutionPermit:
    code = "MALFORMED_PERMIT"
    try:
        data = _wire_keys(data, _PERMIT_WIRE_FIELDS, code)
        body = data["permit"]
        body = _wire_keys(body, _PERMIT_BODY_WIRE_FIELDS, code)
        raw_amount = body["max_amount_usd"]
        if raw_amount is not None and not isinstance(raw_amount, str):
            raise DeterministicFailure(code)
        max_amount = parse_bounded_decimal(raw_amount) if raw_amount is not None else None
        if raw_amount is not None and max_amount is None:
            raise DeterministicFailure(code)
        return SignedExecutionPermit(
            permit=ExecutionPermit(
                permit_id=_wire_string(body, "permit_id", code),
                principal_id=_wire_string(body, "principal_id", code),
                intent_id=_wire_string(body, "intent_id", code),
                grant_id=_wire_string(body, "grant_id", code),
                grant_version=_wire_int(body, "grant_version", code),
                grant_hash=_wire_string(body, "grant_hash", code),
                request_hash=_wire_string(body, "request_hash", code),
                authority_attestation_hash=_wire_string(body, "authority_attestation_hash", code),
                risk_attestation_hash=_wire_string(body, "risk_attestation_hash", code),
                grant_epoch=_wire_int(body, "grant_epoch", code),
                fence_token=_wire_int(body, "fence_token", code),
                max_amount_usd=max_amount,
                issued_at=_wire_datetime(body, "issued_at", code),
                expires_at=_wire_datetime(body, "expires_at", code),
            ),
            signer_id=_wire_string(data, "signer_id", code),
            algorithm=PermitAlgorithm(_wire_string(data, "algorithm", code)),
            signature=_wire_string(data, "signature", code),
        )
    except DeterministicFailure:
        raise
    except Exception as exc:
        raise DeterministicFailure("MALFORMED_PERMIT") from exc


@dataclass
class _Order:
    key: str
    order_id: str
    principal_id: str
    intent_id: str
    request_hash: str
    primitive: EconomicPrimitive
    state: PaperOrderState
    notional: Decimal | None
    fill: dict[str, str]
    effect_id: str | None = None
    amount_usd: Decimal | None = None
    side: str | None = None
    base_asset: str | None = None
    quote_asset: str | None = None
    limit_price: Decimal | None = None
    time_in_force: str | None = None
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class _OrderPlan:
    notional: Decimal
    limit_price: Decimal
    side: str
    base_asset: str
    quote_asset: str
    time_in_force: str


def _stable_id(*parts: str) -> str:
    return "pg_" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:24]


class PaperVenueBook:
    """In-memory paper book. Ground truth lives here; clients never hold this object."""

    def __init__(
        self,
        prices_usd: Mapping[str, Decimal],
        balances: Mapping[str, Decimal],
        *,
        fill_prices_usd: Mapping[str, Decimal] | None = None,
    ) -> None:
        self.prices_usd = self._validated_table(prices_usd, "paper price", positive=True)
        self.fill_prices_usd = self._validated_table(
            fill_prices_usd if fill_prices_usd is not None else prices_usd,
            "paper fill price",
            positive=True,
        )
        if set(self.fill_prices_usd) != set(self.prices_usd):
            raise ValueError("paper reference and fill price assets must match")
        self.balances = self._validated_table(balances, "paper balance", positive=False)
        self.orders: dict[str, _Order] = {}
        self.orders_by_id: dict[str, str] = {}

    @staticmethod
    def _validated_table(
        values: Mapping[str, Decimal], label: str, *, positive: bool,
    ) -> dict[str, Decimal]:
        result: dict[str, Decimal] = {}
        for asset, raw in values.items():
            if not isinstance(asset, str) or not asset or len(asset) > 128 or asset.strip() != asset:
                raise ValueError(f"{label} asset must be a bounded non-whitespace string")
            value = parse_bounded_decimal(raw)
            if value is None or (value <= 0 if positive else value < 0):
                qualifier = "positive" if positive else "non-negative"
                raise ValueError(f"{label} must be a {qualifier} bounded Decimal")
            result[asset] = value
        return result

    def price(self, asset: str, *, fill: bool = False) -> Decimal:
        if asset in STABLE_ASSETS:
            return Decimal("1")
        table = self.fill_prices_usd if fill else self.prices_usd
        try:
            raw = table[asset]
        except KeyError as exc:
            raise DeterministicFailure(f"NO_PAPER_PRICE:{asset}") from exc
        price = parse_bounded_decimal(raw)
        if price is None or price <= 0:
            raise DeterministicFailure(f"INVALID_PAPER_PRICE:{asset}")
        return price

    def set_quote(self, asset: str, price: Decimal, *, fill_price: Decimal | None = None) -> None:
        if not isinstance(asset, str) or not asset or len(asset) > 128 or asset.strip() != asset:
            raise DeterministicFailure("INVALID_PAPER_ASSET")
        bounded_price = parse_bounded_decimal(price)
        bounded_fill = parse_bounded_decimal(fill_price if fill_price is not None else price)
        if bounded_price is None or bounded_price <= 0 or bounded_fill is None or bounded_fill <= 0:
            raise DeterministicFailure("INVALID_PAPER_PRICE")
        self.prices_usd[asset] = bounded_price
        self.fill_prices_usd[asset] = bounded_fill

    def balance(self, asset: str) -> Decimal:
        raw = self.balances.get(asset, Decimal("0"))
        value = parse_bounded_decimal(raw)
        if value is None or value < 0:
            raise DeterministicFailure(f"INVALID_PAPER_BALANCE:{asset}")
        return value


class PaperVenueService:
    """Venue-side process: consume the permit, then maybe create an effect.

    Submit and query are separate methods guarded by distinct credentials. This
    object is intentionally bound to one principal and one target. In-process
    clients are test seams, not process or credential isolation.
    """

    def __init__(
        self,
        name: str,
        permit_verifier: ExecutionPermitVerifier,
        book: PaperVenueBook,
        *,
        principal_id: str,
        target: str,
        submit_token: str,
        query_token: str,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if not all(isinstance(value, str) and value and len(value) <= 256 for value in (name, principal_id, target)):
            raise ValueError("venue name, principal id, and target must be bounded strings")
        _validate_role_token(submit_token)
        _validate_role_token(query_token)
        if hmac.compare_digest(submit_token, query_token):
            raise ValueError("submit and query credentials must be distinct")
        self.name = name
        self.principal_id = principal_id
        self.target = target
        self.permit_verifier = permit_verifier
        self.book = book
        self.submit_token = submit_token
        self.query_token = query_token
        self.clock = clock
        self._lock = threading.RLock()

    def _require(self, credential: VenueCredential, role: VenueRole) -> None:
        if not isinstance(credential, VenueCredential) or credential.role != role:
            raise DeterministicFailure("CREDENTIAL_DENIED")
        expected = self.submit_token if role is VenueRole.SUBMIT else self.query_token
        if not hmac.compare_digest(credential.token, expected):
            raise DeterministicFailure("CREDENTIAL_DENIED")

    def _key(self, request: ExecutionRequest) -> str:
        return client_order_id(request)

    def _receipt(self, order: _Order) -> ExecutionReceipt:
        evidence = {
            "venue": self.name,
            "client_order_id": order.key,
            "order_id": order.order_id,
            "order_state": order.state.value,
            "effect_id": order.effect_id,
            "request_hash": order.request_hash,
            "fill": order.fill,
            "reasons": list(order.reasons),
        }
        if order.state is PaperOrderState.FILLED:
            status = SettlementStatus.FINALIZED
        elif order.state is PaperOrderState.PENDING:
            # Receipt is telemetry. An open GTC is an admitted order with nothing
            # filled; the verifier is the only path that can promote it.
            status = SettlementStatus.PARTIALLY_FILLED
        elif order.state in {PaperOrderState.CANCELLED, PaperOrderState.REJECTED}:
            status = SettlementStatus.CANCELLED
        else:
            status = SettlementStatus.UNKNOWN
        return ExecutionReceipt(
            effect_id=order.effect_id or order.order_id,
            status=status,
            evidence=evidence,
            amount_usd=order.amount_usd,
        )

    def submit(self, request: ExecutionRequest, permit: SignedExecutionPermit, credential: VenueCredential) -> ExecutionReceipt:
        self._require(credential, VenueRole.SUBMIT)
        with self._lock:
            return self._submit_locked(request, permit)

    def lookup(self, request: ExecutionRequest, credential: VenueCredential) -> SettlementRecord:
        self._require(credential, VenueRole.QUERY)
        with self._lock:
            self._require_request_scope(request)
            return self._lookup_locked(request)

    def match_pending(self) -> list[str]:
        """Fill resting GTC orders that are now marketable. Cancelled orders are skipped."""
        with self._lock:
            return self._match_pending_locked()

    def _match_pending_locked(self) -> list[str]:
        filled: list[str] = []
        for order in list(self.book.orders.values()):
            if order.state is not PaperOrderState.PENDING:
                continue
            if self._marketable(order):
                self._fill(order)
                filled.append(order.key)
        return filled

    def set_quote(self, asset: str, price: Decimal, *, fill_price: Decimal | None = None, match: bool = True) -> list[str]:
        with self._lock:
            self.book.set_quote(asset, price, fill_price=fill_price)
            return self._match_pending_locked() if match else []

    def _submit_locked(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        self._require_request_scope(request)
        if request.primitive not in ORDER_PRIMITIVES | {EconomicPrimitive.CANCEL_ORDER}:
            raise DeterministicFailure(f"UNSUPPORTED_PRIMITIVE:{request.primitive.value}")

        key = self._key(request)
        existing = self.book.orders.get(key)
        if existing is not None:
            if existing.state is PaperOrderState.CANCELLED:
                raise DeterministicFailure("ORDER_ALREADY_CANCELLED")
            if existing.state is PaperOrderState.REJECTED:
                raise DeterministicFailure("ORDER_ALREADY_REJECTED")
            if existing.request_hash != canonical_hash(request):
                raise DeterministicFailure("ORDER_REQUEST_BINDING_MISMATCH")
            return self._receipt(existing)

        if request.primitive == EconomicPrimitive.CANCEL_ORDER:
            return self._cancel_locked(request, permit)
        plan = self._plan(request)

        # Venue-bound consume is the admission linearization point. A permit
        # minted for another venue, or consumed after halt/revoke, creates no order.
        ok, reasons = self.permit_verifier.consume(permit, request, now=self.clock(), venue=self.name)
        if not ok:
            raise DeterministicFailure("PERMIT_REJECTED:" + ",".join(reasons))

        order_id = _stable_id(self.name, key, "order")
        order = _Order(
            key=key,
            order_id=order_id,
            principal_id=request.principal_id,
            intent_id=request.intent_id,
            request_hash=canonical_hash(request),
            primitive=request.primitive,
            state=PaperOrderState.PENDING,
            notional=plan.notional,
            fill={
                "side": plan.side,
                "base_asset": plan.base_asset,
                "quote_asset": plan.quote_asset,
                "limit_price": format(plan.limit_price, "f"),
                "time_in_force": plan.time_in_force,
            },
            effect_id=order_id,
            amount_usd=Decimal("0"),
            side=plan.side,
            base_asset=plan.base_asset,
            quote_asset=plan.quote_asset,
            limit_price=plan.limit_price,
            time_in_force=plan.time_in_force,
        )
        self.book.orders[key] = order
        self.book.orders_by_id[order_id] = key

        if self._marketable(order):
            try:
                self._fill(order)
            except DeterministicFailure as exc:
                # Admitted, then rejected: leave an authoritative CANCELLED
                # record so a consumed permit is never paired with absence.
                self._mark_unfilled_cancel(order, str(exc))
                raise
            return self._receipt(order)

        if order.time_in_force == "GTC":
            return self._receipt(order)

        self._mark_unfilled_cancel(order, "LIMIT_PRICE_EXCEEDED")
        raise DeterministicFailure("LIMIT_PRICE_EXCEEDED")

    def _require_request_scope(self, request: object) -> None:
        if not isinstance(request, ExecutionRequest):
            raise DeterministicFailure("MALFORMED_REQUEST")
        if request.venue != self.name:
            raise DeterministicFailure("PERMIT_VENUE_MISMATCH")
        if request.principal_id != self.principal_id:
            raise DeterministicFailure("PAPER_PRINCIPAL_MISMATCH")
        target = request.payload.get("target")
        if not isinstance(target, str) or target != self.target:
            raise DeterministicFailure("PAPER_TARGET_MISMATCH")

    def _cancel_locked(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        target = request.payload.get("order_id")
        if not isinstance(target, str) or not target:
            raise DeterministicFailure("ORDER_ID_INVALID")
        key = self.book.orders_by_id.get(target)
        if key is None:
            # The request names either the venue order id or exact client order id.
            if target in self.book.orders:
                key = target
        if key is None:
            raise DeterministicFailure("ORDER_NOT_FOUND")
        target_order = self.book.orders[key]
        if target_order.principal_id != request.principal_id:
            raise DeterministicFailure("ORDER_NOT_OWNED")
        # Read-only refusals happen before consume: no admission, no settlement
        # gap. Only a PENDING (or already-CANCELLED) book row is admitted.
        if target_order.state is PaperOrderState.FILLED:
            raise DeterministicFailure("ORDER_ALREADY_FILLED")
        if target_order.state is PaperOrderState.REJECTED:
            raise DeterministicFailure("ORDER_ALREADY_REJECTED")

        ok, reasons = self.permit_verifier.consume(permit, request, now=self.clock(), venue=self.name)
        if not ok:
            raise DeterministicFailure("PERMIT_REJECTED:" + ",".join(reasons))

        target_order = self.book.orders[key]
        if target_order.state is PaperOrderState.FILLED:
            # Lost the race with a fill after the pre-check. Admission without
            # an unwind: leave a CANCELLED record on *this* cancel identity.
            self._record_cancel_intent(request, target_order)
            raise DeterministicFailure("ORDER_ALREADY_FILLED")
        target_order.state = PaperOrderState.CANCELLED
        target_order.reasons = ("CANCELLED",)
        target_order.amount_usd = Decimal("0")
        return self._record_cancel_intent(request, target_order)

    def _record_cancel_intent(self, request: ExecutionRequest, target_order: _Order) -> ExecutionReceipt:
        cancel_id = _stable_id(self.name, self._key(request), "cancel")
        cancel = _Order(
            key=self._key(request),
            order_id=cancel_id,
            principal_id=request.principal_id,
            intent_id=request.intent_id,
            request_hash=canonical_hash(request),
            primitive=EconomicPrimitive.CANCEL_ORDER,
            state=PaperOrderState.FILLED,
            notional=Decimal("0"),
            fill={"cancelled_order_id": target_order.order_id, "cancelled_client_order_id": target_order.key},
            effect_id=cancel_id,
            amount_usd=None,
        )
        self.book.orders[cancel.key] = cancel
        self.book.orders_by_id[cancel_id] = cancel.key
        return self._receipt(cancel)

    def _plan(self, request: ExecutionRequest) -> _OrderPlan:
        p = request.payload
        if request.primitive not in ORDER_PRIMITIVES:
            raise DeterministicFailure(f"UNSUPPORTED_PRIMITIVE:{request.primitive.value}")
        if not isinstance(p.get("order_type"), str) or p["order_type"].lower() != "limit":
            raise DeterministicFailure("PAPER_LIMIT_ORDER_REQUIRED")
        raw_tif = p.get("time_in_force", "IOC")
        if not isinstance(raw_tif, str) or raw_tif.upper() not in SUPPORTED_TIME_IN_FORCE:
            raise DeterministicFailure("PAPER_TIME_IN_FORCE_UNSUPPORTED")
        if "max_slippage_bps" in p:
            # Supporting a second relative bound requires an independent price
            # reference. This gateway enforces exactly the signed absolute limit.
            raise DeterministicFailure("PAPER_ABSOLUTE_LIMIT_ONLY")
        amount_fields = [field for field in ("amount_usd", "notional_usd") if field in p]
        if len(amount_fields) != 1:
            raise DeterministicFailure("PAPER_ONE_NOTIONAL_REQUIRED")
        notional = parse_bounded_decimal(p[amount_fields[0]])
        if notional is None or notional <= 0:
            raise DeterministicFailure("PAPER_NOTIONAL_INVALID")
        limit = parse_bounded_decimal(p.get("limit_price"))
        if limit is None or limit <= 0:
            raise DeterministicFailure("PAPER_LIMIT_PRICE_INVALID")
        base, quote = p.get("base_asset"), p.get("quote_asset")
        if not isinstance(base, str) or not isinstance(quote, str) or not base or not quote or base == quote:
            raise DeterministicFailure("PAPER_MARKET_INVALID")
        if quote != PAPER_QUOTE_ASSET:
            raise DeterministicFailure("PAPER_USDC_QUOTE_REQUIRED")
        # Validate that both reference and executable prices exist before permit
        # consumption. The actual quantities are computed only at fill time.
        self.book.price(base)
        self.book.price(base, fill=True)
        side = "SELL" if request.primitive is EconomicPrimitive.SELL else "BUY"
        return _OrderPlan(notional, limit, side, base, quote, raw_tif.upper())

    def _marketable(self, order: _Order) -> bool:
        if order.limit_price is None or not order.base_asset:
            return False
        fill_price = self.book.price(order.base_asset, fill=True)
        if order.side == "SELL":
            return fill_price >= order.limit_price
        return fill_price <= order.limit_price

    def _mark_unfilled_cancel(self, order: _Order, reason: str) -> None:
        """Admit-then-reject: keep the order identity, fill nothing.

        The runtime treats authoritative CANCELLED with a zero amount as
        ``SETTLEMENT_CANCELLED_UNFILLED``. Authoritative NONE after a consumed
        permit is a ledger contradiction and STOPs.
        """
        order.state = PaperOrderState.CANCELLED
        order.reasons = (reason,)
        order.amount_usd = Decimal("0")
        if order.effect_id is None:
            order.effect_id = order.order_id

    def _fill(self, order: _Order) -> None:
        if order.state is PaperOrderState.CANCELLED:
            raise DeterministicFailure("ORDER_ALREADY_CANCELLED")
        if order.state is PaperOrderState.FILLED:
            return
        if order.state is PaperOrderState.REJECTED:
            raise DeterministicFailure("ORDER_ALREADY_REJECTED")
        if order.primitive != EconomicPrimitive.SWAP and not self._marketable(order):
            raise DeterministicFailure("LIMIT_PRICE_EXCEEDED")

        if order.notional is None or order.base_asset is None or order.quote_asset is None or order.limit_price is None:
            raise DeterministicFailure("PAPER_ORDER_MALFORMED")
        notional = order.notional
        fill_price = self.book.price(order.base_asset, fill=True)
        quote_price = self.book.price(order.quote_asset, fill=True)
        base_quantity = notional / fill_price
        quote_quantity = notional / quote_price
        fill = {
            "side": order.side or "",
            "base_asset": order.base_asset,
            "quote_asset": order.quote_asset,
            "base_quantity": format(base_quantity, "f"),
            "quote_quantity": format(quote_quantity, "f"),
            "notional_usd": format(notional, "f"),
            "limit_price": format(order.limit_price, "f"),
            "fill_price": format(fill_price, "f"),
            "time_in_force": order.time_in_force or "",
        }
        if order.side == "SELL":
            self._transfer(order.base_asset, base_quantity, order.quote_asset, quote_quantity)
        elif order.side == "BUY":
            self._transfer(order.quote_asset, quote_quantity, order.base_asset, base_quantity)
        else:
            raise DeterministicFailure("PAPER_ORDER_SIDE_INVALID")

        # Effect identity is the order identity from admission. A later fill
        # must not mint a second id for the same client_order_id (I-11).
        if order.effect_id is None:
            order.effect_id = order.order_id
        order.fill = fill
        order.amount_usd = notional
        order.state = PaperOrderState.FILLED
        self.book.orders_by_id[order.effect_id] = order.key

    def _transfer(self, debit_asset: str, debit_quantity: Decimal, credit_asset: str, credit_quantity: Decimal) -> None:
        """Apply both balance legs only after the complete fill has validated."""

        if debit_asset == credit_asset:
            raise DeterministicFailure("PAPER_TRANSFER_ASSETS_IDENTICAL")
        if (
            not debit_quantity.is_finite()
            or not credit_quantity.is_finite()
            or debit_quantity <= 0
            or credit_quantity <= 0
        ):
            raise DeterministicFailure("PAPER_FILL_QUANTITY_INVALID")
        debit_balance = self.book.balance(debit_asset)
        credit_balance = self.book.balance(credit_asset)
        if debit_balance < debit_quantity:
            raise DeterministicFailure(f"INSUFFICIENT_BALANCE:{debit_asset}")
        next_debit = debit_balance - debit_quantity
        next_credit = credit_balance + credit_quantity
        if parse_bounded_decimal(next_debit) is None or parse_bounded_decimal(next_credit) is None:
            raise DeterministicFailure("PAPER_BALANCE_OUT_OF_BOUNDS")
        self.book.balances[debit_asset] = next_debit
        self.book.balances[credit_asset] = next_credit

    def _lookup_locked(self, request: ExecutionRequest) -> SettlementRecord:
        request_hash = canonical_hash(request)
        order = self.book.orders.get(self._key(request))
        if order is None:
            return SettlementRecord(
                SettlementStatus.NONE,
                evidence={"venue": self.name, "order_state": "ABSENT"},
                authoritative=True,
                verified_request_hash=request_hash,
            )
        if order.request_hash != request_hash:
            return SettlementRecord(
                SettlementStatus.CONTRADICTORY,
                evidence={
                    "venue": self.name,
                    "reason": "observed-effect-request-binding-mismatch",
                    "observed_request_hash": order.request_hash,
                    "expected_request_hash": request_hash,
                },
                authoritative=True,
                verified_request_hash=request_hash,
            )
        if order.state is PaperOrderState.FILLED:
            return SettlementRecord(
                SettlementStatus.FINALIZED,
                effect_id=order.effect_id,
                amount_usd=order.amount_usd,
                evidence=self._receipt(order).evidence,
                authoritative=True,
                verified_request_hash=request_hash,
            )
        if order.state is PaperOrderState.PENDING:
            # Resting GTC: admitted, nothing filled. Authoritative open-order
            # settlement so the runtime CONFIRMS and never resubmits (I-3, 4.4).
            return SettlementRecord(
                SettlementStatus.PARTIALLY_FILLED,
                effect_id=order.effect_id or order.order_id,
                amount_usd=Decimal("0"),
                evidence={"venue": self.name, "order_state": order.state.value, "order_id": order.order_id},
                authoritative=True,
                verified_request_hash=request_hash,
            )
        # CANCELLED / REJECTED after admission: no economic fill, and the venue
        # guarantees it will never acquire one. CANCELLED (not NONE) so a
        # consumed permit is not a ledger contradiction.
        return SettlementRecord(
            SettlementStatus.CANCELLED,
            effect_id=order.effect_id or order.order_id,
            amount_usd=Decimal("0"),
            evidence={"venue": self.name, "order_state": order.state.value, "reasons": list(order.reasons)},
            authoritative=True,
            verified_request_hash=request_hash,
        )


class SubmitPort(Protocol):
    def submit(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt: ...


class QueryPort(Protocol):
    def lookup(self, request: ExecutionRequest) -> SettlementRecord: ...


class PaperSubmitClient:
    """Submit-only API surface; not a security boundary inside one interpreter."""

    def __init__(self, service: PaperVenueService, credential: VenueCredential) -> None:
        if credential.role is not VenueRole.SUBMIT:
            raise ValueError("submit client requires a submit credential")
        self._service = service
        self._credential = credential

    def submit(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        return self._service.submit(request, permit, self._credential)

    def lookup(self, request: ExecutionRequest) -> SettlementRecord:
        raise DeterministicFailure("SUBMIT_CLIENT_CANNOT_QUERY")


class PaperQueryClient:
    """Query-only API surface; not a security boundary inside one interpreter."""

    def __init__(self, service: PaperVenueService, credential: VenueCredential) -> None:
        if credential.role is not VenueRole.QUERY:
            raise ValueError("query client requires a query credential")
        self._service = service
        self._credential = credential

    def submit(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        raise DeterministicFailure("QUERY_CLIENT_CANNOT_SUBMIT")

    def lookup(self, request: ExecutionRequest) -> SettlementRecord:
        return self._service.lookup(request, self._credential)


@dataclass
class PaperGatewayAdapter:
    """Execution adapter: sanitized request + permit in, untrusted receipt out."""

    name: str
    client: SubmitPort
    security_profile: AdapterSecurityProfile = REFERENCE_SAFE_PROFILE

    def execute(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        return self.client.submit(request, permit)


@dataclass
class PaperGatewayVerifier:
    """Role-split reference verifier: query credential only, shared paper truth."""

    name: str
    client: QueryPort
    security_profile: SettlementSecurityProfile = REFERENCE_SETTLEMENT_PROFILE

    def verify(self, request: ExecutionRequest) -> SettlementRecord:
        return self.client.lookup(request)


def paper_gateway_pair(
    service: PaperVenueService,
) -> tuple[PaperGatewayAdapter, PaperGatewayVerifier]:
    adapter = PaperGatewayAdapter(
        service.name,
        PaperSubmitClient(service, VenueCredential(VenueRole.SUBMIT, service.submit_token)),
    )
    verifier = PaperGatewayVerifier(
        f"{service.name}-settlement",
        PaperQueryClient(service, VenueCredential(VenueRole.QUERY, service.query_token)),
    )
    return adapter, verifier


_LOOPBACK_URL_ERROR = "paper gateway URL must be a numeric loopback HTTP origin with an explicit port"
_HTTP_PATHS = frozenset({"/v1/orders", "/v1/reconcile"})


def _parse_loopback_url(url: object, *, base: bool) -> tuple[str, int, str]:
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise ValueError(_LOOPBACK_URL_ERROR)
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError(_LOOPBACK_URL_ERROR) from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or port is None
        or not 1 <= port <= 65535
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(_LOOPBACK_URL_ERROR)
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError(_LOOPBACK_URL_ERROR) from exc
    if not address.is_loopback:
        raise ValueError(_LOOPBACK_URL_ERROR)
    path = parsed.path or "/"
    if (base and path != "/") or (not base and path not in _HTTP_PATHS):
        raise ValueError(_LOOPBACK_URL_ERROR)
    return str(address), port, path


def _normalize_loopback_origin(url: object) -> str:
    host, port, _ = _parse_loopback_url(url, base=True)
    rendered_host = f"[{host}]" if ":" in host else host
    return f"http://{rendered_host}:{port}"


def _validate_http_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("paper gateway timeout must be a finite number from 0 through 60 seconds")
    timeout = float(value)
    if not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("paper gateway timeout must be a finite number from 0 through 60 seconds")
    return timeout


def _http_json(
    method: str,
    url: str,
    token: str,
    body: Mapping[str, Any] | None = None,
    *,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any]]:
    try:
        host, port, path = _parse_loopback_url(url, base=False)
        bounded_timeout = _validate_http_timeout(timeout)
        _validate_role_token(token)
    except ValueError as exc:
        raise AmbiguousExecution("PAPER_GATEWAY_TRANSPORT_ERROR:URL") from exc
    conn = http.client.HTTPConnection(host, port, timeout=bounded_timeout)
    try:
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        payload = None
        if body is not None:
            payload = canonical_json(body)
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        response = conn.getresponse()
        raw = response.read(MAX_WIRE_BODY_BYTES + 1)
        if len(raw) > MAX_WIRE_BODY_BYTES:
            raise AmbiguousExecution("PAPER_GATEWAY_TRANSPORT_ERROR:BODY")
        if not raw:
            return response.status, {}
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AmbiguousExecution("PAPER_GATEWAY_TRANSPORT_ERROR:JSON") from exc
        if not isinstance(decoded, dict):
            raise AmbiguousExecution("PAPER_GATEWAY_TRANSPORT_ERROR:JSON")
        return response.status, decoded
    except AmbiguousExecution:
        raise
    except DeterministicFailure:
        raise
    except Exception as exc:
        raise AmbiguousExecution(f"PAPER_GATEWAY_TRANSPORT_ERROR:{type(exc).__name__}") from exc
    finally:
        conn.close()


def _raise_venue_error(payload: Mapping[str, Any]) -> None:
    reasons = payload.get("reasons")
    code = payload.get("error")
    if isinstance(code, str) and code:
        raise DeterministicFailure(code)
    if isinstance(reasons, list) and reasons:
        raise DeterministicFailure(",".join(str(r) for r in reasons))
    raise DeterministicFailure("VENUE_REJECTED")


def _receipt_from_wire(data: Mapping[str, Any]) -> ExecutionReceipt:
    code = "PAPER_GATEWAY_TRANSPORT_ERROR:RECEIPT"
    try:
        if set(data) != {"effect_id", "status", "evidence", "amount_usd"}:
            raise ValueError
        effect_id = data["effect_id"]
        status = data["status"]
        evidence = data["evidence"]
        amount = data["amount_usd"]
        if not isinstance(effect_id, str) or not isinstance(status, str) or not isinstance(evidence, Mapping):
            raise ValueError
        if amount is not None and not isinstance(amount, str):
            raise ValueError
        bounded_amount = parse_bounded_decimal(amount) if amount is not None else None
        if amount is not None and bounded_amount is None:
            raise ValueError
        return ExecutionReceipt(
            effect_id=effect_id,
            status=SettlementStatus(status),
            evidence=dict(evidence),
            amount_usd=bounded_amount,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AmbiguousExecution(code) from exc


def _record_from_wire(data: Mapping[str, Any]) -> SettlementRecord:
    code = "PAPER_GATEWAY_TRANSPORT_ERROR:RECORD"
    try:
        if set(data) != {
            "status",
            "effect_id",
            "amount_usd",
            "evidence",
            "authoritative",
            "verified_request_hash",
        }:
            raise ValueError
        status = data["status"]
        effect_id = data["effect_id"]
        amount = data["amount_usd"]
        evidence = data["evidence"]
        authoritative = data["authoritative"]
        verified_hash = data["verified_request_hash"]
        if not isinstance(status, str) or not isinstance(evidence, Mapping):
            raise ValueError
        if effect_id is not None and not isinstance(effect_id, str):
            raise ValueError
        if amount is not None and not isinstance(amount, str):
            raise ValueError
        if type(authoritative) is not bool:
            raise ValueError
        if verified_hash is not None and not isinstance(verified_hash, str):
            raise ValueError
        bounded_amount = parse_bounded_decimal(amount) if amount is not None else None
        if amount is not None and bounded_amount is None:
            raise ValueError
        return SettlementRecord(
            status=SettlementStatus(status),
            effect_id=effect_id,
            amount_usd=bounded_amount,
            evidence=dict(evidence),
            authoritative=authoritative,
            verified_request_hash=verified_hash,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AmbiguousExecution(code) from exc


@dataclass
class PaperHttpSubmitClient:
    base_url: str
    token: str
    timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        self.base_url = _normalize_loopback_origin(self.base_url)
        _validate_role_token(self.token)
        self.timeout_seconds = _validate_http_timeout(self.timeout_seconds)

    def submit(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        status, payload = _http_json(
            "POST",
            f"{self.base_url}/v1/orders",
            self.token,
            {"request": request_to_wire(request), "permit": permit_to_wire(permit)},
            timeout=self.timeout_seconds,
        )
        if status == 200 and payload.get("ok") is True:
            receipt = payload.get("receipt")
            if not isinstance(receipt, Mapping):
                raise AmbiguousExecution("PAPER_GATEWAY_TRANSPORT_ERROR:RECEIPT")
            return _receipt_from_wire(receipt)
        if 400 <= status < 500:
            _raise_venue_error(payload)
        raise AmbiguousExecution(f"PAPER_GATEWAY_TRANSPORT_ERROR:HTTP_{status}")

    def lookup(self, request: ExecutionRequest) -> SettlementRecord:
        raise DeterministicFailure("SUBMIT_CLIENT_CANNOT_QUERY")


@dataclass
class PaperHttpQueryClient:
    base_url: str
    token: str
    timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        self.base_url = _normalize_loopback_origin(self.base_url)
        _validate_role_token(self.token)
        self.timeout_seconds = _validate_http_timeout(self.timeout_seconds)

    def submit(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        raise DeterministicFailure("QUERY_CLIENT_CANNOT_SUBMIT")

    def lookup(self, request: ExecutionRequest) -> SettlementRecord:
        # Reconcile is a distinct path from submit: it never accepts a permit and
        # the query token is refused on POST /v1/orders.
        status, payload = _http_json(
            "POST",
            f"{self.base_url}/v1/reconcile",
            self.token,
            {"request": request_to_wire(request)},
            timeout=self.timeout_seconds,
        )
        if status == 200 and payload.get("ok") is True:
            record = payload.get("record")
            if not isinstance(record, Mapping):
                raise AmbiguousExecution("PAPER_GATEWAY_TRANSPORT_ERROR:RECORD")
            return _record_from_wire(record)
        if status in {401, 403}:
            return SettlementRecord(
                SettlementStatus.UNKNOWN,
                evidence={"venue": "paper-gateway", "error": "CREDENTIAL_DENIED"},
                authoritative=False,
            )
        if 400 <= status < 500:
            return SettlementRecord(
                SettlementStatus.UNKNOWN,
                evidence={"venue": "paper-gateway", "error": payload.get("error", f"HTTP_{status}")},
                authoritative=False,
            )
        raise AmbiguousExecution(f"PAPER_GATEWAY_TRANSPORT_ERROR:HTTP_{status}")


class PaperHttpServer:
    """Loopback HTTP front for ``PaperVenueService``. Bind to 127.0.0.1 only."""

    def __init__(self, service: PaperVenueService, host: str = "127.0.0.1", port: int = 0) -> None:
        if host != "127.0.0.1":
            raise ValueError("paper HTTP server may only bind numeric IPv4 loopback")
        self.service = service
        handler = _make_handler(service)
        self._server = http.server.ThreadingHTTPServer((host, port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="faar-paper-http", daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        rendered_host = f"[{host}]" if ":" in host else host
        return f"http://{rendered_host}:{port}"

    def start(self) -> "PaperHttpServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2)


def _make_handler(service: PaperVenueService):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *args: object) -> None:
            return

        def _credential(self) -> VenueCredential | None:
            header = self.headers.get("Authorization") or ""
            if not header.startswith("Bearer "):
                return None
            token = header[len("Bearer "):].strip()
            try:
                _validate_role_token(token)
            except ValueError:
                return None
            if hmac.compare_digest(token, service.submit_token):
                return VenueCredential(VenueRole.SUBMIT, token)
            if hmac.compare_digest(token, service.query_token):
                return VenueCredential(VenueRole.QUERY, token)
            return VenueCredential(VenueRole.SUBMIT, token)

        def _read_json(self) -> dict[str, Any]:
            length = self.headers.get("Content-Length")
            try:
                size = int(length or "0")
            except ValueError as exc:
                raise DeterministicFailure("MALFORMED_REQUEST") from exc
            if size < 0 or size > MAX_WIRE_BODY_BYTES:
                raise DeterministicFailure("MALFORMED_REQUEST")
            raw = self.rfile.read(size) if size else b""
            if not raw:
                return {}
            try:
                data = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise DeterministicFailure("MALFORMED_REQUEST") from exc
            if not isinstance(data, dict):
                raise DeterministicFailure("MALFORMED_REQUEST")
            return data

        def _send(self, status: int, payload: Mapping[str, Any]) -> None:
            body = canonical_json(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.query or parsed.fragment:
                self._send(404, {"ok": False, "error": "NOT_FOUND"})
                return
            credential = self._credential()
            if credential is None:
                self._send(401, {"ok": False, "error": "CREDENTIAL_DENIED"})
                return
            try:
                data = self._read_json()
                if parsed.path == "/v1/orders":
                    if credential.role is not VenueRole.SUBMIT or credential.token != service.submit_token:
                        self._send(403, {"ok": False, "error": "CREDENTIAL_DENIED"})
                        return
                    request = request_from_wire(data.get("request"))
                    permit = permit_from_wire(data.get("permit"))
                    receipt = service.submit(request, permit, credential)
                    self._send(200, {"ok": True, "receipt": json.loads(canonical_json(receipt))})
                    return
                if parsed.path == "/v1/reconcile":
                    if credential.role is not VenueRole.QUERY or credential.token != service.query_token:
                        self._send(403, {"ok": False, "error": "CREDENTIAL_DENIED"})
                        return
                    request = request_from_wire(data.get("request"))
                    record = service.lookup(request, credential)
                    self._send(200, {"ok": True, "record": json.loads(canonical_json(record))})
                    return
                self._send(404, {"ok": False, "error": "NOT_FOUND"})
            except DeterministicFailure as exc:
                self._send(422, {"ok": False, "error": str(exc), "reasons": [str(exc)]})
            except Exception:
                self._send(500, {"ok": False, "error": "VENUE_INTERNAL"})

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path != "/v1/health" or parsed.query or parsed.fragment:
                self._send(404, {"ok": False, "error": "NOT_FOUND"})
                return
            self._send(200, {"ok": True, "venue": service.name})

    return Handler


def paper_http_pair(
    service: PaperVenueService,
    *,
    timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> tuple[PaperGatewayAdapter, PaperGatewayVerifier, PaperHttpServer]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    server = PaperHttpServer(service).start()
    adapter = PaperGatewayAdapter(
        service.name,
        PaperHttpSubmitClient(server.url, service.submit_token, timeout_seconds),
    )
    verifier = PaperGatewayVerifier(
        f"{service.name}-settlement",
        PaperHttpQueryClient(server.url, service.query_token, timeout_seconds),
    )
    return adapter, verifier, server
