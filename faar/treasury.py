"""Fake-money treasury adapter. PAY only, exactly-once by intent_id.

Not a live payments network. Not a brokerage. The adapter receives only
ExecutionRequest + signed permit; it does not mint permits.
"""
from __future__ import annotations

import hashlib
from decimal import Decimal, InvalidOperation
from threading import RLock
from typing import Callable

from .adapters import AmbiguousExecution, DeterministicFailure, REFERENCE_SAFE_PROFILE
from .canonical import canonical_hash
from .ledger import LedgerConflict, SQLiteAuthorityLedger
from .models import ExecutionReceipt, ExecutionRequest, SettlementStatus, SignedExecutionPermit, utcnow


class MockTreasuryAdapter:
    """In-ledger fake payments venue.

    `mode` supports the same crash/timeout names as MockVenue so the gateway can
    exercise effect-before-receipt and timeout-before-effect faults.
    """

    name = "mock-treasury"
    security_profile = REFERENCE_SAFE_PROFILE

    def __init__(self, ledger: SQLiteAuthorityLedger, *, clock: Callable = utcnow, mode: str = "SUCCESS") -> None:
        self.ledger = ledger
        self.clock = clock
        self.mode = mode
        self._lock = RLock()
        self._effects: dict[str, ExecutionReceipt] = {}
        self._calls: dict[str, int] = {}

    def _key(self, request: ExecutionRequest) -> str:
        return f"{request.principal_id}\x1f{request.intent_id}"

    def execute(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        with self._lock:
            key = self._key(request)
            self._calls[key] = self._calls.get(key, 0) + 1
            if key in self._effects:
                return self._effects[key]
            if request.venue != self.name:
                raise DeterministicFailure("TREASURY_VENUE_MISMATCH")
            if request.primitive.value != "PAY":
                raise DeterministicFailure("TREASURY_PRIMITIVE_NOT_PAY")
            if self.mode == "TIMEOUT_BEFORE_EFFECT":
                raise AmbiguousExecution("timeout before treasury effect")
            amount = _amount(request)
            beneficiary = str(request.payload.get("target") or "")
            source = self.ledger.get_account(request.principal_id)
            if source is None:
                raise DeterministicFailure("TREASURY_ACCOUNT_NOT_BOUND")
            try:
                self.ledger.transfer(source_account=source, beneficiary=beneficiary, amount=amount)
            except LedgerConflict as exc:
                raise DeterministicFailure(str(exc) or "TREASURY_TRANSFER_DENIED") from exc
            receipt = self._receipt(request, amount)
            self._effects[key] = receipt
            if self.mode == "TIMEOUT_AFTER_EFFECT":
                raise AmbiguousExecution("timeout after treasury effect")
            return receipt

    def lookup_effect(self, request: ExecutionRequest) -> ExecutionReceipt | None:
        with self._lock:
            return self._effects.get(self._key(request))

    def execute_call_count(self, intent_id: str, *, principal_id: str) -> int:
        return self._calls.get(f"{principal_id}\x1f{intent_id}", 0)

    def _receipt(self, request: ExecutionRequest, amount: Decimal) -> ExecutionReceipt:
        seed = request.principal_id + "\x1f" + request.intent_id + str(request.payload.get("target"))
        effect_id = "pay_" + hashlib.sha256(seed.encode()).hexdigest()[:24]
        return ExecutionReceipt(
            effect_id=effect_id,
            status=SettlementStatus.FINALIZED,
            evidence={
                "venue": self.name,
                "principal_id": request.principal_id,
                "intent_id": request.intent_id,
                "effect_id": effect_id,
                "request_hash": canonical_hash(request),
                "beneficiary": request.payload.get("target"),
            },
            amount_usd=amount,
        )


def _amount(request: ExecutionRequest) -> Decimal:
    raw = request.payload.get("amount_usd")
    try:
        value = Decimal(str(raw))
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise DeterministicFailure("TREASURY_AMOUNT_INVALID") from exc
    if not value.is_finite() or value <= 0:
        raise DeterministicFailure("TREASURY_AMOUNT_INVALID")
    return value
