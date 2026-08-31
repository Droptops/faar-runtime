from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from decimal import Decimal, InvalidOperation
from typing import Protocol

from .canonical import canonical_json
from .models import ExecutionReceipt, ExecutionRequest, SettlementRecord, SettlementStatus


class ExecutionError(RuntimeError):
    pass


class AmbiguousExecution(ExecutionError):
    """The caller cannot know whether an economic effect occurred."""


class DeterministicFailure(ExecutionError):
    """The adapter knows no economic effect occurred."""


@dataclass(frozen=True)
class AdapterSecurityProfile:
    """Properties FAAR requires before an adapter may enter the execution path.

    These are declarations, not proofs. A live adapter still needs review and
    failure injection, but the runtime refuses adapters that do not even claim the
    minimum semantics required by the recovery state machine.
    """

    stable_intent_identity: bool
    idempotent_submission: bool
    authoritative_reconciliation: bool
    stable_effect_identity: bool

    @property
    def exactly_once_compatible(self) -> bool:
        return all((
            self.stable_intent_identity,
            self.idempotent_submission,
            self.authoritative_reconciliation,
            self.stable_effect_identity,
        ))


REFERENCE_SAFE_PROFILE = AdapterSecurityProfile(True, True, True, True)


class MockMode(StrEnum):
    SUCCESS = "SUCCESS"
    TIMEOUT_BEFORE_EFFECT = "TIMEOUT_BEFORE_EFFECT"
    TIMEOUT_AFTER_EFFECT = "TIMEOUT_AFTER_EFFECT"
    AMBIGUOUS = "AMBIGUOUS"


class ExecutionAdapter(Protocol):
    name: str
    security_profile: AdapterSecurityProfile

    def execute(self, request: ExecutionRequest) -> ExecutionReceipt: ...
    def reconcile(self, request: ExecutionRequest) -> SettlementRecord: ...


@dataclass
class MockVenue:
    """Deterministic idempotent fake venue keyed by FAAR intent_id.

    It models the essential property required of a live adapter: resubmitting the
    same logical intent cannot create a second economic effect. Live venues can
    implement this with client order IDs, idempotency keys, or a lower-level
    capability contract; otherwise the adapter must not be considered safe.
    """

    name: str = "mock-venue"
    mode: MockMode = MockMode.SUCCESS
    security_profile: AdapterSecurityProfile = REFERENCE_SAFE_PROFILE

    def __post_init__(self) -> None:
        self._lock = RLock()
        self._effects: dict[str, ExecutionReceipt] = {}
        self._execute_calls: dict[str, int] = {}

    def _receipt(self, request: ExecutionRequest) -> ExecutionReceipt:
        effect_id = "fx_" + hashlib.sha256((request.intent_id + canonical_json(request.payload)).encode()).hexdigest()[:24]
        amount = None
        raw_amount = request.payload.get("amount_usd", request.payload.get("notional_usd"))
        if raw_amount is not None:
            try:
                amount = Decimal(str(raw_amount))
            except (InvalidOperation, ValueError, TypeError):
                amount = None
        return ExecutionReceipt(
            effect_id=effect_id,
            status=SettlementStatus.FINALIZED,
            evidence={"venue": self.name, "intent_id": request.intent_id, "effect_id": effect_id},
            amount_usd=amount,
        )

    def execute(self, request: ExecutionRequest) -> ExecutionReceipt:
        with self._lock:
            self._execute_calls[request.intent_id] = self._execute_calls.get(request.intent_id, 0) + 1
            if request.intent_id in self._effects:
                return self._effects[request.intent_id]
            if self.mode == MockMode.TIMEOUT_BEFORE_EFFECT:
                raise AmbiguousExecution("timeout before venue effect; caller must reconcile before retry")
            if self.mode == MockMode.AMBIGUOUS:
                raise AmbiguousExecution("venue remains ambiguous")
            receipt = self._receipt(request)
            self._effects[request.intent_id] = receipt
            if self.mode == MockMode.TIMEOUT_AFTER_EFFECT:
                raise AmbiguousExecution("timeout after venue effect; caller must reconcile")
            return receipt

    def reconcile(self, request: ExecutionRequest) -> SettlementRecord:
        with self._lock:
            receipt = self._effects.get(request.intent_id)
            if receipt:
                return SettlementRecord(
                    status=receipt.status,
                    effect_id=receipt.effect_id,
                    amount_usd=receipt.amount_usd,
                    evidence=receipt.evidence,
                    authoritative=True,
                )
            if self.mode == MockMode.AMBIGUOUS:
                return SettlementRecord(SettlementStatus.UNKNOWN, evidence={"venue": self.name}, authoritative=False)
            return SettlementRecord(SettlementStatus.NONE, evidence={"venue": self.name}, authoritative=True)

    def successful_effect_count(self, intent_id: str) -> int:
        return 1 if intent_id in self._effects else 0

    def execute_call_count(self, intent_id: str) -> int:
        return self._execute_calls.get(intent_id, 0)

    def set_mode(self, mode: MockMode) -> None:
        self.mode = mode
