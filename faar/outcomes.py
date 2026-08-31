from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Mapping

from .attestation import AttestationVerifier
from .models import Attestation, AttestationKind, Intent, OutcomeCriterion, OutcomeResult, OutcomeVerdict, SettlementRecord, SettlementStatus, TaskContract


def _path_get(root: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = root
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _cmp(actual: Any, expected: Any, op: str) -> bool:
    if op == "eq":
        return actual == expected
    try:
        left = Decimal(str(actual))
        right = Decimal(str(expected))
    except (InvalidOperation, ValueError, TypeError):
        return False
    if not left.is_finite() or not right.is_finite():
        return False
    if op == "gte":
        return left >= right
    if op == "lte":
        return left <= right
    return False


def verify_task_outcome(contract: TaskContract, settlement: SettlementRecord) -> OutcomeResult:
    """Evaluate "done" independently from "money moved".

    A FINALIZED economic effect is necessary for this reference verifier, but it is
    not sufficient. The task's immutable success criteria must also be satisfied by
    settlement evidence. This prevents an agent from declaring success just because
    it emitted an action or got an API acknowledgement.
    """

    if settlement.status != SettlementStatus.FINALIZED:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("ECONOMIC_EFFECT_NOT_FINALIZED",))
    if not settlement.authoritative:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("SETTLEMENT_NOT_AUTHORITATIVE",))
    if not settlement.effect_id:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("FINALIZED_EFFECT_ID_REQUIRED",))

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
        return OutcomeResult(OutcomeVerdict.NOT_MET, tuple(failures), evaluated)
    return OutcomeResult(OutcomeVerdict.MET, (), evaluated)


def verify_attested_task_outcome(
    contract: TaskContract,
    settlement: SettlementRecord,
    *,
    attestation: Attestation,
    intent: Intent,
    trust: AttestationVerifier,
    now,
) -> OutcomeResult:
    if contract.intent_id != intent.intent_id:
        return OutcomeResult(OutcomeVerdict.UNKNOWN, ("TASK_INTENT_ID_MISMATCH",))
    if now < contract.issued_at:
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
    return verify_task_outcome(contract, settlement)
