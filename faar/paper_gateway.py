"""Paper venue gateway: permit-verifying book with a split submit/query path.

This is not a live-money adapter. It is the first venue-shaped transport in the
repository whose settlement verifier does not share the submitter's client or
credential. The venue process consumes the permit, enforces the request's
``limit_price`` bound, and refuses to fill a cancelled order.

Tests drive it in-process or over loopback HTTP. Neither path talks to a funded
venue or holds a production credential.
"""

from __future__ import annotations

import hashlib
import http.client
import http.server
import json
import threading
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import parse_qs, urlparse

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
MAX_WIRE_BODY_BYTES = 64 * 1024
DEFAULT_HTTP_TIMEOUT_SECONDS = 2.0
ORDER_PRIMITIVES = frozenset({
    EconomicPrimitive.BUY,
    EconomicPrimitive.SELL,
    EconomicPrimitive.PLACE_ORDER,
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
        if not isinstance(self.token, str) or not self.token:
            raise ValueError("venue credential token is required")


def client_order_id(request: ExecutionRequest) -> str:
    """Stable venue identity derived from the FAAR intent (ADAPTER_CONTRACT A2)."""
    return f"{request.principal_id}:{request.intent_id}"


def request_to_wire(request: ExecutionRequest) -> dict[str, Any]:
    return json.loads(canonical_json(request))


def permit_to_wire(permit: SignedExecutionPermit) -> dict[str, Any]:
    return json.loads(canonical_json(permit))


def request_from_wire(data: object) -> ExecutionRequest:
    if not isinstance(data, Mapping):
        raise DeterministicFailure("MALFORMED_REQUEST")
    try:
        payload = data["payload"]
        if not isinstance(payload, Mapping):
            raise DeterministicFailure("MALFORMED_REQUEST")
        return ExecutionRequest(
            principal_id=str(data["principal_id"]),
            intent_id=str(data["intent_id"]),
            primitive=EconomicPrimitive(str(data["primitive"])),
            venue=str(data["venue"]),
            payload=dict(payload),
        )
    except DeterministicFailure:
        raise
    except Exception as exc:
        raise DeterministicFailure("MALFORMED_REQUEST") from exc


def permit_from_wire(data: object) -> SignedExecutionPermit:
    if not isinstance(data, Mapping):
        raise DeterministicFailure("MALFORMED_PERMIT")
    try:
        body = data["permit"]
        if not isinstance(body, Mapping):
            raise DeterministicFailure("MALFORMED_PERMIT")
        raw_amount = body.get("max_amount_usd")
        max_amount = parse_bounded_decimal(raw_amount) if raw_amount is not None else None
        if raw_amount is not None and max_amount is None:
            raise DeterministicFailure("MALFORMED_PERMIT")
        return SignedExecutionPermit(
            permit=ExecutionPermit(
                permit_id=str(body["permit_id"]),
                principal_id=str(body["principal_id"]),
                intent_id=str(body["intent_id"]),
                grant_id=str(body["grant_id"]),
                grant_version=int(body["grant_version"]),
                grant_hash=str(body["grant_hash"]),
                request_hash=str(body["request_hash"]),
                authority_attestation_hash=str(body["authority_attestation_hash"]),
                risk_attestation_hash=str(body["risk_attestation_hash"]),
                grant_epoch=int(body["grant_epoch"]),
                fence_token=int(body["fence_token"]),
                max_amount_usd=max_amount,
                issued_at=datetime.fromisoformat(str(body["issued_at"])),
                expires_at=datetime.fromisoformat(str(body["expires_at"])),
            ),
            signer_id=str(data["signer_id"]),
            algorithm=PermitAlgorithm(str(data["algorithm"])),
            signature=str(data["signature"]),
        )
    except DeterministicFailure:
        raise
    except Exception as exc:
        raise DeterministicFailure("MALFORMED_PERMIT") from exc


@dataclass
class _Order:
    key: str
    order_id: str
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
    reasons: tuple[str, ...] = ()


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
        self.prices_usd = {k: Decimal(str(v)) for k, v in prices_usd.items()}
        self.fill_prices_usd = {k: Decimal(str(v)) for k, v in (fill_prices_usd or prices_usd).items()}
        self.balances = {k: Decimal(str(v)) for k, v in balances.items()}
        self.orders: dict[str, _Order] = {}
        self.orders_by_id: dict[str, str] = {}

    def price(self, asset: str, *, fill: bool = False) -> Decimal:
        if asset in STABLE_ASSETS:
            return Decimal("1")
        table = self.fill_prices_usd if fill else self.prices_usd
        try:
            price = table[asset]
        except KeyError as exc:
            raise DeterministicFailure(f"NO_PAPER_PRICE:{asset}") from exc
        if price <= 0:
            raise DeterministicFailure(f"INVALID_PAPER_PRICE:{asset}")
        return price

    def set_quote(self, asset: str, price: Decimal, *, fill_price: Decimal | None = None) -> None:
        if price <= 0:
            raise DeterministicFailure("INVALID_PAPER_PRICE")
        self.prices_usd[asset] = price
        self.fill_prices_usd[asset] = fill_price if fill_price is not None else price


class PaperVenueService:
    """Venue-side process: consume the permit, then maybe create an effect.

    Submit and query are separate methods guarded by distinct credentials. A
    client that only holds the query token cannot create an order.
    """

    def __init__(
        self,
        name: str,
        permit_verifier: ExecutionPermitVerifier,
        book: PaperVenueBook,
        *,
        submit_token: str,
        query_token: str,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        if not name or not submit_token or not query_token:
            raise ValueError("venue name and both role tokens are required")
        if submit_token == query_token:
            raise ValueError("submit and query credentials must be distinct")
        self.name = name
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
        if credential.token != expected:
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
        return ExecutionReceipt(
            effect_id=order.effect_id or order.order_id,
            status=SettlementStatus.FINALIZED if order.state is PaperOrderState.FILLED else SettlementStatus.UNKNOWN,
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
            return self._lookup_locked(request)

    def match_pending(self) -> list[str]:
        """Fill resting GTC orders that are now marketable. Cancelled orders are skipped."""
        with self._lock:
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
        return self.match_pending() if match else []

    def _submit_locked(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
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
        if request.primitive == EconomicPrimitive.PAY:
            raise DeterministicFailure("UNSUPPORTED_PRIMITIVE:PAY")

        try:
            notional, fill_plan, limit_price, side = self._plan(request)
        except DeterministicFailure:
            raise

        ok, reasons = self.permit_verifier.consume(permit, request, now=self.clock())
        if not ok:
            raise DeterministicFailure("PERMIT_REJECTED:" + ",".join(reasons))

        order_id = _stable_id(self.name, key, "order")
        order = _Order(
            key=key,
            order_id=order_id,
            request_hash=canonical_hash(request),
            primitive=request.primitive,
            state=PaperOrderState.PENDING,
            notional=notional,
            fill=fill_plan,
            side=side,
            base_asset=fill_plan.get("base_asset") or fill_plan.get("from_asset"),
            quote_asset=fill_plan.get("quote_asset") or fill_plan.get("to_asset"),
            limit_price=limit_price,
        )
        self.book.orders[key] = order
        self.book.orders_by_id[order_id] = key

        tif = str(request.payload.get("time_in_force") or "IOC").upper()
        if request.primitive == EconomicPrimitive.SWAP or self._marketable(order):
            try:
                self._fill(order)
            except DeterministicFailure as exc:
                order.state = PaperOrderState.REJECTED
                order.reasons = (str(exc),)
                raise
            return self._receipt(order)

        if tif == "GTC":
            return self._receipt(order)

        order.state = PaperOrderState.REJECTED
        order.reasons = ("LIMIT_PRICE_EXCEEDED",)
        raise DeterministicFailure("LIMIT_PRICE_EXCEEDED")

    def _cancel_locked(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        ok, reasons = self.permit_verifier.consume(permit, request, now=self.clock())
        if not ok:
            raise DeterministicFailure("PERMIT_REJECTED:" + ",".join(reasons))

        target = str(request.payload["order_id"])
        key = self.book.orders_by_id.get(target)
        if key is None:
            # Allow cancelling by the original client_order_id or by intent_id
            # scoped to this principal.
            if target in self.book.orders and target.startswith(request.principal_id + ":"):
                key = target
            else:
                candidate = f"{request.principal_id}:{target}"
                if candidate in self.book.orders:
                    key = candidate
        if key is None:
            raise DeterministicFailure("ORDER_NOT_FOUND")
        target_order = self.book.orders[key]
        if target_order.state is PaperOrderState.FILLED:
            raise DeterministicFailure("ORDER_ALREADY_FILLED")
        if target_order.state is PaperOrderState.REJECTED:
            raise DeterministicFailure("ORDER_ALREADY_REJECTED")
        target_order.state = PaperOrderState.CANCELLED
        target_order.reasons = ("CANCELLED",)

        cancel_id = _stable_id(self.name, self._key(request), "cancel")
        cancel = _Order(
            key=self._key(request),
            order_id=cancel_id,
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

    def _plan(self, request: ExecutionRequest) -> tuple[Decimal, dict[str, str], Decimal | None, str | None]:
        p = request.payload
        notional = parse_bounded_decimal(p.get("amount_usd", p.get("notional_usd")))
        if notional is None or notional <= 0:
            raise DeterministicFailure("AMOUNT_INVALID")
        if request.primitive == EconomicPrimitive.SWAP:
            src, dst = str(p["from_asset"]), str(p["to_asset"])
            qty_src = notional / self.book.price(src)
            qty_dst = notional / self.book.price(dst)
            fill = {
                "from_asset": src, "to_asset": dst,
                "from_quantity": format(qty_src, "f"), "to_quantity": format(qty_dst, "f"),
                "notional_usd": format(notional, "f"),
            }
            return notional, fill, None, None

        if request.primitive not in ORDER_PRIMITIVES:
            raise DeterministicFailure(f"UNSUPPORTED_PRIMITIVE:{request.primitive.value}")
        limit = parse_bounded_decimal(p.get("limit_price"))
        if limit is None or limit <= 0:
            raise DeterministicFailure("LIMIT_PRICE_REQUIRED")
        base, quote = str(p["base_asset"]), str(p["quote_asset"])
        side = "SELL" if request.primitive is EconomicPrimitive.SELL else "BUY"
        qty_quote = notional / self.book.price(quote, fill=True)
        qty_base = notional / self.book.price(base, fill=True)
        fill = {
            "side": side, "base_asset": base, "quote_asset": quote,
            "base_quantity": format(qty_base, "f"), "quote_quantity": format(qty_quote, "f"),
            "notional_usd": format(notional, "f"), "limit_price": format(limit, "f"),
            "fill_price": format(self.book.price(base, fill=True), "f"),
        }
        return notional, fill, limit, side

    def _marketable(self, order: _Order) -> bool:
        if order.primitive == EconomicPrimitive.SWAP:
            return True
        if order.limit_price is None or not order.base_asset:
            return False
        fill_price = self.book.price(order.base_asset, fill=True)
        if order.side == "SELL":
            return fill_price >= order.limit_price
        return fill_price <= order.limit_price

    def _fill(self, order: _Order) -> None:
        if order.state is PaperOrderState.CANCELLED:
            raise DeterministicFailure("ORDER_ALREADY_CANCELLED")
        if order.state is PaperOrderState.FILLED:
            return
        if order.state is PaperOrderState.REJECTED:
            raise DeterministicFailure("ORDER_ALREADY_REJECTED")
        if order.primitive != EconomicPrimitive.SWAP and not self._marketable(order):
            raise DeterministicFailure("LIMIT_PRICE_EXCEEDED")

        notional = order.notional or Decimal("0")
        if order.primitive == EconomicPrimitive.SWAP:
            src, dst = order.fill["from_asset"], order.fill["to_asset"]
            self._debit(src, notional / self.book.price(src))
            self._credit(dst, notional / self.book.price(dst))
        elif order.side == "SELL":
            assert order.base_asset and order.quote_asset
            self._debit(order.base_asset, notional / self.book.price(order.base_asset, fill=True))
            self._credit(order.quote_asset, notional / self.book.price(order.quote_asset, fill=True))
        else:
            assert order.base_asset and order.quote_asset
            self._debit(order.quote_asset, notional / self.book.price(order.quote_asset, fill=True))
            self._credit(order.base_asset, notional / self.book.price(order.base_asset, fill=True))

        order.effect_id = _stable_id(self.name, order.key, canonical_json(order.fill))
        order.amount_usd = None if order.primitive == EconomicPrimitive.CANCEL_ORDER else notional
        order.state = PaperOrderState.FILLED
        self.book.orders_by_id[order.effect_id] = order.key

    def _debit(self, asset: str, quantity: Decimal) -> None:
        current = self.book.balances.get(asset, Decimal("0"))
        if current < quantity:
            raise DeterministicFailure(f"INSUFFICIENT_BALANCE:{asset}")
        self.book.balances[asset] = current - quantity

    def _credit(self, asset: str, quantity: Decimal) -> None:
        self.book.balances[asset] = self.book.balances.get(asset, Decimal("0")) + quantity

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
            # A resting order may still fill. Absence of a fill is not proof of
            # non-execution (ADAPTER_CONTRACT B3).
            return SettlementRecord(
                SettlementStatus.UNKNOWN,
                evidence={"venue": self.name, "order_state": order.state.value, "order_id": order.order_id},
                authoritative=False,
                verified_request_hash=request_hash,
            )
        # CANCELLED on the *cancel* intent is FILLED above. CANCELLED here is the
        # original order after a later cancel: no economic fill, and the venue
        # guarantees it will never acquire one.
        return SettlementRecord(
            SettlementStatus.NONE,
            evidence={"venue": self.name, "order_state": order.state.value, "reasons": list(order.reasons)},
            authoritative=True,
            verified_request_hash=request_hash,
        )


class SubmitPort(Protocol):
    def submit(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt: ...


class QueryPort(Protocol):
    def lookup(self, request: ExecutionRequest) -> SettlementRecord: ...


class PaperSubmitClient:
    """Submit-only handle. Holding this object is not enough to reconcile."""

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
    """Query-only handle. Holding this object is not enough to create an effect."""

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
    """Independent settlement verifier: query credential only, no submit path."""

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


def _http_json(
    method: str,
    url: str,
    token: str,
    body: Mapping[str, Any] | None = None,
    *,
    timeout: float = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> tuple[int, dict[str, Any]]:
    parsed = urlparse(url)
    if parsed.hostname is None or parsed.port is None:
        raise AmbiguousExecution("PAPER_GATEWAY_TRANSPORT_ERROR:URL")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
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
    amount = data.get("amount_usd")
    return ExecutionReceipt(
        effect_id=str(data.get("effect_id") or ""),
        status=SettlementStatus(str(data.get("status") or SettlementStatus.UNKNOWN.value)),
        evidence=dict(data.get("evidence") or {}),
        amount_usd=parse_bounded_decimal(amount) if amount is not None else None,
    )


def _record_from_wire(data: Mapping[str, Any]) -> SettlementRecord:
    amount = data.get("amount_usd")
    return SettlementRecord(
        status=SettlementStatus(str(data.get("status") or SettlementStatus.UNKNOWN.value)),
        effect_id=data.get("effect_id") if isinstance(data.get("effect_id"), str) else None,
        amount_usd=parse_bounded_decimal(amount) if amount is not None else None,
        evidence=dict(data.get("evidence") or {}),
        authoritative=bool(data.get("authoritative")),
        verified_request_hash=data.get("verified_request_hash") if isinstance(data.get("verified_request_hash"), str) else None,
    )


@dataclass
class PaperHttpSubmitClient:
    base_url: str
    token: str
    timeout_seconds: float = DEFAULT_HTTP_TIMEOUT_SECONDS

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
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("paper HTTP server may only bind loopback")
        self.service = service
        handler = _make_handler(service)
        self._server = http.server.ThreadingHTTPServer((host, port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="faar-paper-http", daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

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
            if token == service.submit_token:
                return VenueCredential(VenueRole.SUBMIT, token)
            if token == service.query_token:
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
            if parsed.path != "/v1/health":
                self._send(404, {"ok": False, "error": "NOT_FOUND"})
                return
            qs = parse_qs(parsed.query)
            _ = qs
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
