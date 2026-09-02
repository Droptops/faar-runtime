from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Callable, Protocol

from .canonical import canonical_hash, canonical_json, parse_bounded_decimal
from .models import ExecutionReceipt, ExecutionRequest, SettlementRecord, SettlementStatus, SignedExecutionPermit, utcnow
from .permits import ExecutionPermitVerifier


class ExecutionError(RuntimeError):
    pass


class AmbiguousExecution(ExecutionError):
    """The caller cannot know whether an economic effect occurred."""


class DeterministicFailure(ExecutionError):
    """The adapter knows no economic effect occurred."""


@dataclass(frozen=True)
class AdapterSecurityProfile:
    """Minimum semantics required for an execution transport.

    `permit_enforced` is the v0.3 TCB boundary: the transport must not hold a generic
    credential that can broaden the request. The economic venue/capability gateway
    must independently verify FAAR's signed execution permit.
    """

    stable_intent_identity: bool
    idempotent_submission: bool
    stable_effect_identity: bool
    permit_enforced: bool
    single_use_permit_consumption: bool

    @property
    def exactly_once_compatible(self) -> bool:
        return all((
            self.stable_intent_identity,
            self.idempotent_submission,
            self.stable_effect_identity,
            self.permit_enforced,
            self.single_use_permit_consumption,
        ))


REFERENCE_SAFE_PROFILE = AdapterSecurityProfile(True, True, True, True, True)


class MockMode(StrEnum):
    SUCCESS = "SUCCESS"
    TIMEOUT_BEFORE_EFFECT = "TIMEOUT_BEFORE_EFFECT"
    TIMEOUT_AFTER_EFFECT = "TIMEOUT_AFTER_EFFECT"
    AMBIGUOUS = "AMBIGUOUS"


class ExecutionAdapter(Protocol):
    name: str
    security_profile: AdapterSecurityProfile

    def execute(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt: ...


@dataclass
class MockVenue:
    """Permit-enforcing idempotent fake venue keyed by principal + intent_id.

    The transport does not possess a generic financial credential. An economic
    effect is created only after the venue verifies a narrowly scoped permit against
    the current grant epoch. This is the reference analogue of an on-chain
    capability contract, restricted subaccount, or isolated policy signer.
    """

    permit_verifier: ExecutionPermitVerifier
    name: str = "mock-venue"
    mode: MockMode = MockMode.SUCCESS
    security_profile: AdapterSecurityProfile = REFERENCE_SAFE_PROFILE
    clock: Callable = utcnow

    def __post_init__(self) -> None:
        self._lock = RLock()
        self._effects: dict[str, ExecutionReceipt] = {}
        self._execute_calls: dict[str, int] = {}

    @staticmethod
    def _key(request: ExecutionRequest) -> str:
        return f"{request.principal_id}\x1f{request.intent_id}"

    def _receipt(self, request: ExecutionRequest) -> ExecutionReceipt:
        seed = request.principal_id + "\x1f" + request.intent_id + canonical_json(request.payload)
        effect_id = "fx_" + hashlib.sha256(seed.encode()).hexdigest()[:24]
        amount = parse_bounded_decimal(request.payload.get("amount_usd", request.payload.get("notional_usd")))
        return ExecutionReceipt(
            effect_id=effect_id,
            status=SettlementStatus.FINALIZED,
            evidence={
                "venue": self.name,
                "principal_id": request.principal_id,
                "intent_id": request.intent_id,
                "effect_id": effect_id,
                "request_hash": canonical_hash(request),
            },
            amount_usd=amount,
        )

    def execute(self, request: ExecutionRequest, permit: SignedExecutionPermit) -> ExecutionReceipt:
        with self._lock:
            key = self._key(request)
            self._execute_calls[key] = self._execute_calls.get(key, 0) + 1
            if key in self._effects:
                return self._effects[key]

            ok, reasons = self.permit_verifier.consume(permit, request, now=self.clock())
            if not ok:
                raise DeterministicFailure("permit rejected:" + ",".join(reasons))

            if self.mode == MockMode.TIMEOUT_BEFORE_EFFECT:
                raise AmbiguousExecution("timeout before venue effect; caller must reconcile before retry")
            if self.mode == MockMode.AMBIGUOUS:
                raise AmbiguousExecution("venue remains ambiguous")
            receipt = self._receipt(request)
            self._effects[key] = receipt
            if self.mode == MockMode.TIMEOUT_AFTER_EFFECT:
                raise AmbiguousExecution("timeout after venue effect; caller must reconcile")
            return receipt

    def lookup_effect(self, request: ExecutionRequest) -> ExecutionReceipt | None:
        with self._lock:
            return self._effects.get(self._key(request))

    def successful_effect_count(self, intent_id: str, *, principal_id: str = "principal:test") -> int:
        return 1 if f"{principal_id}\x1f{intent_id}" in self._effects else 0

    def execute_call_count(self, intent_id: str, *, principal_id: str = "principal:test") -> int:
        return self._execute_calls.get(f"{principal_id}\x1f{intent_id}", 0)

    def set_mode(self, mode: MockMode) -> None:
        self.mode = mode
