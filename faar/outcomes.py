from __future__ import annotations

from datetime import timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from .attestation import AttestationVerifier
from .canonical import canonical_hash
from .models import (
    IntentState,
    Attestation,
    AttestationKind,
    ExecutionRequest,
    Intent,
    OutcomeCriterion,
    OutcomeResult,
    OutcomeVerdict,
    SettlementRecord,
    SettlementStatus,
    TaskContract,
)


def _path_get(root: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = root
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _as_number(value: Any) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (int, float, str, Decimal)):
        return None
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None
    return number if number.is_finite() else None


def _cmp(actual: Any, expected: Any, op: str) -> bool:
    """Compare a settlement value against a contract criterion.

    Equality is numeric whenever both sides are numbers (so a JSON-string "50"
    matches the runtime-normalised Decimal amount and differing scales agree),
    never conflates booleans with numbers, and otherwise requires the same type.
    Ordered comparisons are numeric only.
    """
    if op == "eq":
        if isinstance(actual, bool) or isinstance(expected, bool):
            return isinstance(actual, bool) and isinstance(expected, bool) and actual == expected
        left, right = _as_number(actual), _as_number(expected)
        if left is not None and right is not None:
            return left == right
        return type(actual) is type(expected) and actual == expected
    left, right = _as_number(actual), _as_number(expected)
    if left is None or right is None:
        return False
    if op == "gte":
        return left >= right
    if op == "lte":
        return left <= right
    return False


def verify_task_outcome(
    contract: TaskContract,
    settlement: SettlementRecord,
    *,
    expected_request_hash: str | None = None,
) -> OutcomeResult:
    """Evaluate "done" independently from "money moved".

    A FINALIZED economic effect is necessary for this reference verifier, but it is
    not sufficient. The task's immutable success criteria must also be satisfied by
    settlement evidence. This prevents an agent from declaring success just because
    it emitted an action or got an API acknowledgement.

    `expected_request_hash` binds the settlement record to the execution request the
    contract is about. Without it this function only proves that *some* effect met
    the criteria; control-plane callers must use `verify_attested_task_outcome`,
    which derives the binding from the intent.
    """

    if settlement.status != SettlementStatus.FINALIZED:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("ECONOMIC_EFFECT_NOT_FINALIZED",))
    if not settlement.authoritative:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("SETTLEMENT_NOT_AUTHORITATIVE",))
    if not settlement.effect_id:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("FINALIZED_EFFECT_ID_REQUIRED",))
    if expected_request_hash is not None and settlement.verified_request_hash != expected_request_hash:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("TASK_SETTLEMENT_INTENT_MISMATCH",))

    # Criteria may address normalized settlement fields or adapter-specific
    # evidence. Standard fields overwrite same-named evidence keys so a venue
    # cannot redefine what `effect_id`, `amount_usd`, or `status` means.
    root: dict[str, Any] = dict(settlement.evidence)
    root.update({
        "effect_id": settlement.effect_id,
        "amount_usd": settlement.amount_usd,
        "status": settlement.status.value,
    })

    evaluated: dict[str, Any] = {}
    failures: list[str] = []
    for idx, criterion in enumerate(contract.criteria):
        found, actual = _path_get(root, criterion.path)
        evaluated[criterion.path] = actual if found else None
        if criterion.op == "present":
            ok = found and actual not in (None, "")
        else:
            ok = found and _cmp(actual, criterion.value, criterion.op)
        if not ok:
            failures.append(f"OUTCOME_CRITERION_FAILED:{idx}:{criterion.path}:{criterion.op}")

    if failures:
        try:
            return OutcomeResult(OutcomeVerdict.NOT_MET, tuple(failures), evaluated)
        except ValueError:
            # The addressed subtrees overlap past the canonical budget; the failures
            # stand on their own, the evaluation record is omitted.
            return OutcomeResult(OutcomeVerdict.NOT_MET, tuple(failures) + ("OUTCOME_EVALUATION_UNBOUNDED",))
    try:
        return OutcomeResult(OutcomeVerdict.MET, (), evaluated)
    except ValueError:
        # MET must carry its evidence; an evaluation that cannot be recorded is not done.
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("OUTCOME_EVALUATION_UNBOUNDED",))


def verify_attested_task_outcome(
    contract: TaskContract,
    settlement: SettlementRecord,
    *,
    attestation: Attestation,
    intent: Intent,
    trust: AttestationVerifier,
    now,
    max_clock_skew_seconds: int = 5,
    runtime_state: IntentState | None = None,
    runtime_effect_id: str | None = None,
) -> OutcomeResult:
    """Definition of done for an attested task contract.

    Pass the runtime's stored state and effect id (`runtime_state`,
    `runtime_effect_id`) whenever they are available: a settlement record the
    runtime refused to finalize (effect id owned by another intent, amount above
    the authorized envelope) must not be declared done by a control plane that
    only looked at the record itself.
    """
    if contract.intent_id != intent.intent_id:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("TASK_INTENT_ID_MISMATCH",))
    if runtime_state is not None and runtime_state != IntentState.FINALIZED:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("TASK_INTENT_NOT_FINALIZED",))
    if runtime_state is not None and runtime_effect_id != settlement.effect_id:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("TASK_EFFECT_ID_MISMATCH",))
    # Issuance tolerates the same small clock skew as the attestation layer;
    # expiry stays exact.
    if now + timedelta(seconds=max(max_clock_skew_seconds, 0)) < contract.issued_at:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("TASK_CONTRACT_FROM_FUTURE",))
    if now > contract.expires_at:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("TASK_CONTRACT_EXPIRED",))
    ok, reasons = trust.verify(
        attestation,
        kind=AttestationKind.TASK,
        subject=contract,
        intent=intent,
        now=now,
    )
    if not ok:
        return OutcomeResult(
            OutcomeVerdict.UNKNOWN,
            tuple("TASK_" + reason for reason in reasons),
        )
    # The settlement must be the settlement of *this* intent's execution request.
    # Authoritative records always carry verified_request_hash, so the binding is
    # always checkable; a FINALIZED record from any other intent yields UNKNOWN.
    expected = canonical_hash(ExecutionRequest.from_intent(intent))
    return verify_task_outcome(contract, settlement, expected_request_hash=expected)
