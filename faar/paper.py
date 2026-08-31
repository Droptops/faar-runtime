from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from threading import RLock
from typing import Callable

from .adapters import AdapterSecurityProfile, DeterministicFailure, REFERENCE_SAFE_PROFILE
from .canonical import canonical_hash, canonical_json
from .models import EconomicPrimitive, ExecutionReceipt, ExecutionRequest, SettlementRecord, SettlementStatus, SignedExecutionPermit, utcnow
from .permits import ExecutionPermitVerifier


@dataclass
class PaperTradingVenue:
    """In-process paper venue for end-to-end FAAR integration testing.

    The venue is idempotent on `intent_id`. Prices are caller-provisioned static
    reference prices; this is deliberately not a market-data system.
    """

    name: str
    prices_usd: dict[str, Decimal]
    permit_verifier: ExecutionPermitVerifier
    clock: Callable[[], datetime] = utcnow
    balances: dict[str, Decimal] = field(default_factory=dict)
    security_profile: AdapterSecurityProfile = REFERENCE_SAFE_PROFILE

    def __post_init__(self) -> None:
        self._lock = RLock()
        self._effects: dict[str, ExecutionReceipt] = {}
        self.balances = {k: Decimal(str(v)) for k, v in self.balances.items()}
        self.prices_usd = {k: Decimal(str(v)) for k, v in self.prices_usd.items()}

    def _price(self, asset: str) -> Decimal:
        if asset in {"USD", "USDC", "USDT"}:
            return Decimal("1")
        try:
            price = self.prices_usd[asset]
        except KeyError as exc:
            raise DeterministicFailure(f"no paper price for asset {asset}") from exc
        if price <= 0:
            raise DeterministicFailure(f"invalid paper price for asset {asset}")
        return price

    def _debit(self, asset: str, quantity: Decimal) -> None:
        current = self.balances.get(asset, Decimal("0"))
        if current < quantity:
            raise DeterministicFailure(f"insufficient paper balance for {asset}")
        self.balances[asset] = current - quantity

    def _credit(self, asset: str, quantity: Decimal) -> None:
        self.balances[asset] = self.balances.get(asset, Decimal("0")) + quantity

    @staticmethod
    def _key(intent: ExecutionRequest) -> str:
        return f"{intent.principal_id}\x1f{intent.intent_id}"

    def execute(self, intent: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        with self._lock:
            key = self._key(intent)
            existing = self._effects.get(key)
            if existing:
                return existing

            ok, reasons = self.permit_verifier.consume(permit, intent, now=self.clock())
            if not ok:
                raise DeterministicFailure("permit rejected:" + ",".join(reasons))

            p = intent.payload
            notional = Decimal(str(p.get("amount_usd", p.get("notional_usd", "0"))))
            if notional <= 0 and intent.primitive != EconomicPrimitive.CANCEL_ORDER:
                raise DeterministicFailure("paper notional must be positive")

            fill: dict[str, str] = {"notional_usd": format(notional, "f")}
            if intent.primitive in {EconomicPrimitive.BUY, EconomicPrimitive.PLACE_ORDER}:
                base = str(p["base_asset"]); quote = str(p["quote_asset"])
                qty_quote = notional / self._price(quote)
                qty_base = notional / self._price(base)
                self._debit(quote, qty_quote); self._credit(base, qty_base)
                fill.update({"side": "BUY", "base_asset": base, "quote_asset": quote, "base_quantity": format(qty_base, "f")})
            elif intent.primitive == EconomicPrimitive.SELL:
                base = str(p["base_asset"]); quote = str(p["quote_asset"])
                qty_base = notional / self._price(base)
                qty_quote = notional / self._price(quote)
                self._debit(base, qty_base); self._credit(quote, qty_quote)
                fill.update({"side": "SELL", "base_asset": base, "quote_asset": quote, "base_quantity": format(qty_base, "f")})
            elif intent.primitive == EconomicPrimitive.SWAP:
                src = str(p["from_asset"]); dst = str(p["to_asset"])
                qty_src = notional / self._price(src)
                qty_dst = notional / self._price(dst)
                self._debit(src, qty_src); self._credit(dst, qty_dst)
                fill.update({"from_asset": src, "to_asset": dst, "from_quantity": format(qty_src, "f"), "to_quantity": format(qty_dst, "f")})
            elif intent.primitive == EconomicPrimitive.CANCEL_ORDER:
                fill.update({"cancelled_order_id": str(p["order_id"])})
            else:
                raise DeterministicFailure(f"primitive {intent.primitive.value} unsupported by paper trading venue")

            effect_id = "paper_" + hashlib.sha256((intent.principal_id + "\x1f" + intent.intent_id + canonical_json(fill)).encode()).hexdigest()[:24]
            evidence = {
                "venue": self.name, "principal_id": intent.principal_id, "intent_id": intent.intent_id,
                "effect_id": effect_id, "request_hash": canonical_hash(intent), "fill": fill,
            }
            receipt = ExecutionReceipt(
                effect_id=effect_id, status=SettlementStatus.FINALIZED, evidence=evidence,
                amount_usd=None if intent.primitive == EconomicPrimitive.CANCEL_ORDER else notional,
            )
            self._effects[key] = receipt
            return receipt

    def lookup_effect(self, intent: ExecutionRequest) -> ExecutionReceipt | None:
        with self._lock:
            return self._effects.get(self._key(intent))

    def reconcile(self, intent: ExecutionRequest) -> SettlementRecord:
        with self._lock:
            receipt = self._effects.get(self._key(intent))
            request_hash = canonical_hash(intent)
            if receipt is None:
                return SettlementRecord(
                    SettlementStatus.NONE, evidence={"venue": self.name}, authoritative=True,
                    verified_request_hash=request_hash,
                )
            return SettlementRecord(
                SettlementStatus.FINALIZED, effect_id=receipt.effect_id, amount_usd=receipt.amount_usd,
                evidence=receipt.evidence, authoritative=True, verified_request_hash=request_hash,
            )

    def successful_effect_count(self, intent_id: str, *, principal_id: str = "principal:test") -> int:
        return 1 if f"{principal_id}\x1f{intent_id}" in self._effects else 0
