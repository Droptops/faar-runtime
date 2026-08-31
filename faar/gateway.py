"""Single choke point for v0.5 mock-financial side effects.

The gateway verifies and consumes a signed permit, then executes. It is
constructed from serialized verifier descriptors, not signer objects.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Callable

from .adapters import AmbiguousExecution, DeterministicFailure
from .canonical import canonical_hash
from .descriptors import VerifierDescriptor, VerifierPurpose, permit_verifier_from_descriptor
from .ledger import EffectReceipt, SQLiteAuthorityLedger, receipt_hash
from .models import ExecutionRequest, SettlementStatus, SignedExecutionPermit, utcnow
from .permits import ExecutionPermitVerifier
from .treasury import MockTreasuryAdapter


class GatewayDenial(RuntimeError):
    def __init__(self, reasons: tuple[str, ...]):
        super().__init__(",".join(reasons))
        self.reasons = reasons


@dataclass(frozen=True)
class GatewayLimits:
    daily_budget_usd: Decimal
    max_clock_skew_seconds: int = 2


class ExecutionGateway:
    """Idempotent permit-consuming treasury gateway."""

    def __init__(
        self,
        ledger: SQLiteAuthorityLedger,
        descriptors: tuple[VerifierDescriptor, ...],
        adapter: MockTreasuryAdapter,
        *,
        limits: GatewayLimits,
        clock: Callable[[], datetime] = utcnow,
        allow_test_time_override: bool = False,
    ) -> None:
        permit_descriptors = [d for d in descriptors if d.purpose is VerifierPurpose.PERMIT]
        if len(permit_descriptors) != 1:
            raise ValueError("GATEWAY_REQUIRES_ONE_PERMIT_DESCRIPTOR")
        backend = permit_verifier_from_descriptor(permit_descriptors[0])
        self.ledger = ledger
        self.adapter = adapter
        self.limits = limits
        self.clock = clock
        self.allow_test_time_override = allow_test_time_override
        self.verifier = ExecutionPermitVerifier(backend, ledger.store)

    def _now(self, override: datetime | None) -> datetime:
        if override is not None and self.allow_test_time_override:
            return override
        return self.clock()

    def submit(
        self,
        request: ExecutionRequest,
        permit: SignedExecutionPermit,
        *,
        now: datetime | None = None,
    ) -> EffectReceipt:
        decision_time = self._now(now)
        existing = self.ledger.get_receipt(request.intent_id)
        if existing is not None:
            if existing.request_hash != canonical_hash(request):
                raise GatewayDenial(("GATEWAY_IDEMPOTENT_PAYLOAD_MISMATCH",))
            return existing

        observed = self.adapter.lookup_effect(request)
        if observed is not None:
            return self._commit_receipt(request, permit, observed, decision_time)

        reasons = list(self._preconditions(request, permit, decision_time))
        ok, verify_reasons = self.verifier.verify(permit, request, now=decision_time)
        if not ok:
            reasons.extend(verify_reasons)
        if reasons:
            raise GatewayDenial(tuple(dict.fromkeys(reasons)))

        ok, consume_reasons = self.verifier.consume(permit, request, now=decision_time)
        if not ok:
            if "PERMIT_ALREADY_CONSUMED" in consume_reasons:
                execution = self.adapter.lookup_effect(request)
                if execution is None:
                    raise GatewayDenial(("GATEWAY_PERMIT_CONSUMED_WITHOUT_EFFECT",) + tuple(consume_reasons))
                return self._commit_receipt(request, permit, execution, decision_time)
            raise GatewayDenial(tuple(consume_reasons))

        try:
            execution = self.adapter.execute(request, permit)
        except DeterministicFailure as exc:
            raise GatewayDenial(("GATEWAY_EXECUTION_DENIED", str(exc))) from exc
        except AmbiguousExecution:
            execution = self.adapter.lookup_effect(request)
            if execution is None:
                raise GatewayDenial(("GATEWAY_EXECUTION_AMBIGUOUS",))

        return self._commit_receipt(request, permit, execution, decision_time)

    def _commit_receipt(self, request, permit, execution, decision_time) -> EffectReceipt:
        existing = self.ledger.get_receipt(request.intent_id)
        if existing is not None:
            return existing
        account = self.ledger.get_account(request.principal_id)
        beneficiary = str(request.payload.get("target") or "")
        amount = _amount(request)
        body = {
            "intent_id": request.intent_id,
            "principal_id": request.principal_id,
            "effect_id": execution.effect_id,
            "permit_hash": canonical_hash(permit),
            "request_hash": canonical_hash(request),
            "amount_usd": format(amount, "f"),
            "source_account": account,
            "beneficiary": beneficiary,
            "status": SettlementStatus.FINALIZED.value,
        }
        recorded = EffectReceipt(
            intent_id=request.intent_id,
            principal_id=request.principal_id,
            effect_id=execution.effect_id,
            permit_hash=canonical_hash(permit),
            request_hash=canonical_hash(request),
            amount_usd=amount,
            source_account=account or "",
            beneficiary=beneficiary,
            status=SettlementStatus.FINALIZED,
            recorded_at=decision_time,
            receipt_hash=receipt_hash(body),
            prev_receipt_hash=self.ledger.last_receipt_hash(),
        )
        committed = self.ledger.commit_receipt(recorded)
        if committed.receipt_hash == recorded.receipt_hash:
            day_key = decision_time.date().isoformat()
            self.ledger.add_daily_spend(account, day_key, amount)
        return committed

    def _preconditions(
        self, request: ExecutionRequest, permit: SignedExecutionPermit, now: datetime
    ) -> tuple[str, ...]:
        reasons: list[str] = []
        if request.venue != "mock-treasury":
            reasons.append("GATEWAY_VENUE_MISMATCH")
        if request.primitive.value != "PAY":
            reasons.append("GATEWAY_PRIMITIVE_NOT_PAY")
        account = self.ledger.get_account(request.principal_id)
        if not account:
            reasons.append("GATEWAY_ACCOUNT_NOT_BOUND")
        beneficiary = str(request.payload.get("target") or "")
        if not beneficiary:
            reasons.append("GATEWAY_BENEFICIARY_REQUIRED")
        elif account and not self.ledger.beneficiary_allowed(account, beneficiary):
            reasons.append("GATEWAY_BENEFICIARY_NOT_ALLOWED")
        amount = None
        try:
            amount = _amount(request)
        except GatewayDenial as exc:
            reasons.extend(exc.reasons)
        if amount is not None and account:
            day_key = now.date().isoformat()
            spent = self.ledger.daily_spent(account, day_key)
            if spent + amount > self.limits.daily_budget_usd:
                reasons.append("GATEWAY_DAILY_BUDGET_EXCEEDED")
            try:
                available = self.ledger.get_balance(account)
            except KeyError:
                reasons.append("GATEWAY_ACCOUNT_UNKNOWN")
            else:
                if available < amount:
                    reasons.append("GATEWAY_INSUFFICIENT_FUNDS")
        if now > permit.permit.expires_at:
            reasons.append("GATEWAY_PERMIT_EXPIRED")
        return tuple(reasons)


def _amount(request: ExecutionRequest) -> Decimal:
    raw = request.payload.get("amount_usd")
    try:
        value = Decimal(str(raw))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise GatewayDenial(("GATEWAY_AMOUNT_INVALID",)) from exc
    if not value.is_finite() or value <= 0:
        raise GatewayDenial(("GATEWAY_AMOUNT_INVALID",))
    return value
