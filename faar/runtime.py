from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from datetime import datetime
from typing import Callable, Mapping

from .adapters import AmbiguousExecution, DeterministicFailure, ExecutionAdapter
from .attestation import AttestationVerifier
from .canonical import canonical_hash
from .gates import evaluate_authority, evaluate_capability, evaluate_risk
from .models import (
    Attestation,
    AttestationKind,
    AuthorityDecision,
    CapabilityGrant,
    Decision,
    ExecutionRequest,
    Intent,
    IntentState,
    MONETARY_PRIMITIVES,
    RiskSnapshot,
    SettlementRecord,
    SettlementStatus,
    Verdict,
    utcnow,
)
from .store import EffectConflict, GrantConflict, SQLiteIntentStore, TERMINAL_STATES, UnknownGrant


@dataclass(frozen=True)
class RuntimeResult:
    intent_id: str
    state: IntentState
    decisions: tuple[Decision, ...] = ()
    effect_id: str | None = None
    reason_codes: tuple[str, ...] = ()
    replayed: bool = False
    submission_count: int = 0


class FAARRuntime:
    def __init__(
        self,
        store: SQLiteIntentStore,
        adapters: Mapping[str, ExecutionAdapter],
        trust: AttestationVerifier,
        *,
        clock: Callable[[], datetime] = utcnow,
        allow_test_time_override: bool = False,
    ) -> None:
        self.store = store
        self.adapters = dict(adapters)
        for name, adapter in self.adapters.items():
            profile = getattr(adapter, "security_profile", None)
            if profile is None or not profile.exactly_once_compatible:
                raise ValueError(
                    f"adapter {name!r} is not exactly-once compatible: "
                    "stable intent identity, idempotent submission, authoritative reconciliation, "
                    "and stable effect identity are required"
                )
        self.trust = trust
        self.clock = clock
        self.allow_test_time_override = allow_test_time_override

    def _decision_time(self, override: datetime | None) -> datetime:
        # Callers must not be able to move the security clock backwards to evade
        # expiry, staleness, daily-budget, or velocity limits. Deterministic tests
        # may opt in explicitly; production/runtime callers get the trusted clock.
        if override is not None and self.allow_test_time_override:
            return override
        return self.clock()

    def process(
        self,
        intent: Intent,
        authority: AuthorityDecision,
        grant: CapabilityGrant,
        risk: RiskSnapshot,
        *,
        authority_attestation: Attestation,
        risk_attestation: Attestation,
        now: datetime | None = None,
    ) -> RuntimeResult:
        now_override = now if self.allow_test_time_override else None
        decision_now = self._decision_time(now)
        intent_hash = canonical_hash(intent)
        existing = self.store.register(intent, intent_hash)

        # The complete grant envelope is provisioned by a separate principal.
        # Matching only grant_id/version is insufficient because a compromised
        # coordinator could otherwise substitute broader contents under the same ID.
        try:
            self.store.verify_grant(grant, canonical_hash(grant))
        except UnknownGrant:
            return self._stop_if_possible(existing, ("GRANT_NOT_PROVISIONED",))
        except GrantConflict:
            return self._stop_if_possible(existing, ("GRANT_ENVELOPE_MISMATCH",))

        if existing.state in TERMINAL_STATES:
            return self._stored_result(existing, replayed=True)

        runtime_grant_status = self.store.get_grant_status(grant.grant_id, grant.version)
        if runtime_grant_status != "ACTIVE":
            reason = f"GRANT_RUNTIME_{runtime_grant_status}"
            if existing.state == IntentState.PROPOSED:
                self.store.transition(intent.intent_id, IntentState.PROPOSED, IntentState.STOPPED, reason_codes=(reason,))
                self.store.release_usage(intent.intent_id)
                return self._current_result(intent.intent_id, reason_codes=(reason,))
            if existing.state == IntentState.AUTHORIZED:
                self.store.transition(intent.intent_id, IntentState.AUTHORIZED, IntentState.STOPPED, reason_codes=(reason,))
                self.store.release_usage(intent.intent_id)
                return self._current_result(intent.intent_id, reason_codes=(reason,))
            return self.reconcile(
                intent,
                grant=grant,
                authority=authority,
                risk=risk,
                authority_attestation=authority_attestation,
                risk_attestation=risk_attestation,
                now=now_override,
                _allow_resubmit=False,
                _block_reason=reason,
            )

        # Interrupted authorization should not blindly resume on stale caller state.
        if existing.state == IntentState.AUTHORIZED:
            decisions, trust_reasons = self._evaluate_fresh(
                intent, authority, grant, risk, authority_attestation, risk_attestation, decision_now
            )
            if trust_reasons or self._dominant(decisions).verdict != Verdict.ALLOW:
                reasons = trust_reasons + tuple(r for d in decisions for r in d.reason_codes)
                self.store.transition(intent.intent_id, IntentState.AUTHORIZED, IntentState.STOPPED, reason_codes=reasons)
                self.store.release_usage(intent.intent_id)
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons)
            if not self.store.transition(intent.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED):
                return self.reconcile(
                    intent,
                    grant=grant,
                    authority=authority,
                    risk=risk,
                    authority_attestation=authority_attestation,
                    risk_attestation=risk_attestation,
                    now=now_override,
                )
            return self._submit(intent, grant, decisions, now=now_override, reauth=(authority, risk, authority_attestation, risk_attestation))

        # Any interrupted execution state must reconcile before another submission.
        if existing.state in {
            IntentState.RESERVED,
            IntentState.SUBMITTED,
            IntentState.UNKNOWN,
            IntentState.RECONCILING,
            IntentState.CONFIRMED,
        }:
            return self.reconcile(
                intent,
                grant=grant,
                authority=authority,
                risk=risk,
                authority_attestation=authority_attestation,
                risk_attestation=risk_attestation,
                now=now_override,
            )

        decisions, trust_reasons = self._evaluate_fresh(
            intent, authority, grant, risk, authority_attestation, risk_attestation, decision_now
        )
        if trust_reasons:
            self.store.transition(intent.intent_id, IntentState.PROPOSED, IntentState.STOPPED, reason_codes=trust_reasons)
            self.store.release_usage(intent.intent_id)
            self.store.add_evidence(intent.intent_id, "attestation_rejected", {"reason_codes": list(trust_reasons)})
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=trust_reasons)

        dominant = self._dominant(decisions)
        if dominant.verdict != Verdict.ALLOW:
            target_state = {
                Verdict.DENY: IntentState.DENIED,
                Verdict.DEFER: IntentState.DEFERRED,
                Verdict.STOP: IntentState.STOPPED,
            }[dominant.verdict]
            reasons = tuple(r for d in decisions for r in d.reason_codes)
            self.store.transition(intent.intent_id, IntentState.PROPOSED, target_state, reason_codes=reasons)
            # A prior crash may have occurred after atomic usage reservation but
            # before PROPOSED -> AUTHORIZED. Terminalizing PROPOSED is proof that
            # no adapter submission began, so any orphan HELD reservation is safe
            # to release.
            self.store.release_usage(intent.intent_id)
            self.store.add_evidence(intent.intent_id, "authorization_decision", {
                "verdict": dominant.verdict.value,
                "reason_codes": list(reasons),
                "layers": [{"layer": d.layer, "verdict": d.verdict.value, "reason_codes": list(d.reason_codes)} for d in decisions],
            })
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons)

        if intent.venue not in self.adapters:
            reasons = ("ADAPTER_NOT_CONFIGURED",)
            self.store.transition(intent.intent_id, IntentState.PROPOSED, IntentState.STOPPED, reason_codes=reasons)
            self.store.release_usage(intent.intent_id)
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons)

        usage_ok, usage_reasons = self.store.reserve_usage(intent, grant, risk, decision_now)
        if not usage_ok:
            self.store.transition(intent.intent_id, IntentState.PROPOSED, IntentState.DEFERRED, reason_codes=usage_reasons)
            self.store.add_evidence(intent.intent_id, "usage_reservation_denied", {"reason_codes": list(usage_reasons)})
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=usage_reasons)

        if not self.store.transition(intent.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED):
            return self.reconcile(
                intent,
                grant=grant,
                authority=authority,
                risk=risk,
                authority_attestation=authority_attestation,
                risk_attestation=risk_attestation,
                now=now_override,
            )
        if not self.store.transition(intent.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED):
            return self.reconcile(
                intent,
                grant=grant,
                authority=authority,
                risk=risk,
                authority_attestation=authority_attestation,
                risk_attestation=risk_attestation,
                now=now_override,
            )

        self.store.add_evidence(intent.intent_id, "authorized", {
            "intent_hash": intent_hash,
            "grant_id": grant.grant_id,
            "grant_version": grant.version,
            "venue": intent.venue,
            "authority_attestation_hash": canonical_hash(authority_attestation),
            "risk_attestation_hash": canonical_hash(risk_attestation),
        })
        return self._submit(intent, grant, decisions, now=now_override, reauth=(authority, risk, authority_attestation, risk_attestation))

    def _evaluate_fresh(
        self,
        intent: Intent,
        authority: AuthorityDecision,
        grant: CapabilityGrant,
        risk: RiskSnapshot,
        authority_attestation: Attestation,
        risk_attestation: Attestation,
        now: datetime,
    ) -> tuple[tuple[Decision, ...], tuple[str, ...]]:
        trust_reasons: list[str] = []
        ok, reasons = self.trust.verify(
            authority_attestation,
            kind=AttestationKind.AUTHORITY,
            subject=authority,
            intent=intent,
            now=now,
        )
        if not ok:
            trust_reasons.extend("AUTHORITY_" + r for r in reasons)
        ok, reasons = self.trust.verify(
            risk_attestation,
            kind=AttestationKind.RISK,
            subject=risk,
            intent=intent,
            now=now,
        )
        if not ok:
            trust_reasons.extend("RISK_" + r for r in reasons)

        decisions = (
            evaluate_authority(authority),
            evaluate_capability(intent, grant, now),
            evaluate_risk(intent, grant, risk, now),
        )
        return decisions, tuple(trust_reasons)

    def _submit(
        self,
        intent: Intent,
        grant: CapabilityGrant,
        decisions: tuple[Decision, ...] = (),
        *,
        now: datetime | None,
        reauth: tuple[AuthorityDecision, RiskSnapshot, Attestation, Attestation] | None = None,
    ) -> RuntimeResult:
        if intent.venue not in self.adapters:
            return self._stop_execution_state(intent.intent_id, ("ADAPTER_NOT_CONFIGURED",), decisions, release_usage=True)

        adapter = self.adapters[intent.venue]

        # Revocation fence: set_grant_status holds this same per-grant guard. An
        # execution already inside the guard linearizes before revocation; after a
        # successful revoke call returns, no later adapter submission can begin.
        with self.store.execution_guard(grant.grant_id, grant.version):
            # In normal operation `now` is None and the trusted clock is re-read
            # *inside* the submission fence. Tests/demos may inject a fixed time.
            submit_now = now if now is not None else self.clock()

            # Revalidate the exact signed authority/risk state at the last possible
            # moment before external execution. Waiting for the grant fence must not
            # preserve an attestation or risk snapshot that has since expired.
            if reauth is not None:
                fresh_decisions, trust_reasons = self._evaluate_fresh(
                    intent, reauth[0], grant, reauth[1], reauth[2], reauth[3], submit_now
                )
                if trust_reasons or self._dominant(fresh_decisions).verdict != Verdict.ALLOW:
                    reasons = ("SUBMIT_REAUTHORIZATION_FAILED",) + trust_reasons + tuple(
                        r for d in fresh_decisions for r in d.reason_codes
                    )
                    return self._stop_execution_state(
                        intent.intent_id, reasons, fresh_decisions, release_usage=True
                    )
                decisions = fresh_decisions

            status = self.store.get_grant_status(grant.grant_id, grant.version)
            if status != "ACTIVE":
                return self._stop_execution_state(
                    intent.intent_id,
                    (f"GRANT_RUNTIME_{status}",),
                    decisions,
                    release_usage=True,
                )
            if submit_now > intent.expires_at:
                return self._stop_execution_state(intent.intent_id, ("INTENT_EXPIRED_BEFORE_SUBMIT",), decisions, release_usage=True)
            if grant.valid_until is not None and submit_now > grant.valid_until:
                return self._stop_execution_state(intent.intent_id, ("GRANT_EXPIRED_BEFORE_SUBMIT",), decisions, release_usage=True)

            started, limit_reached, attempt = self.store.begin_submission(
                intent.intent_id,
                [IntentState.RESERVED, IntentState.RECONCILING],
                max_attempts=grant.limits.max_submission_attempts,
            )
            if limit_reached:
                return self._stop_execution_state(
                    intent.intent_id,
                    ("MAX_SUBMISSION_ATTEMPTS_REACHED",),
                    decisions,
                    release_usage=True,
                )
            if not started:
                return self.reconcile(
                    intent,
                    grant=grant,
                    authority=reauth[0] if reauth else None,
                    risk=reauth[1] if reauth else None,
                    authority_attestation=reauth[2] if reauth else None,
                    risk_attestation=reauth[3] if reauth else None,
                    now=now,
                    _allow_resubmit=reauth is not None,
                )

            self.store.add_evidence(intent.intent_id, "submission_started", {
                "venue": intent.venue,
                "attempt": attempt,
            })
            try:
                receipt = adapter.execute(ExecutionRequest.from_intent(intent))
            except AmbiguousExecution as exc:
                self.store.transition(intent.intent_id, IntentState.SUBMITTED, IntentState.UNKNOWN, reason_codes=("EXECUTION_AMBIGUOUS",))
                self.store.add_evidence(intent.intent_id, "execution_ambiguous", {"message": str(exc), "attempt": attempt})
                return self.reconcile(
                    intent,
                    grant=grant,
                    authority=reauth[0] if reauth else None,
                    risk=reauth[1] if reauth else None,
                    authority_attestation=reauth[2] if reauth else None,
                    risk_attestation=reauth[3] if reauth else None,
                    now=now,
                    decisions=decisions,
                    _allow_resubmit=reauth is not None,
                )
            except DeterministicFailure as exc:
                reasons = ("EXECUTION_DETERMINISTIC_FAILURE",)
                self.store.transition(intent.intent_id, IntentState.SUBMITTED, IntentState.FAILED_SAFE, reason_codes=reasons)
                self.store.release_usage(intent.intent_id)
                self.store.add_evidence(intent.intent_id, "execution_failed_safe", {"message": str(exc), "attempt": attempt})
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons)
            except Exception as exc:  # adapter crash is economically ambiguous
                reasons = ("ADAPTER_EXECUTION_EXCEPTION",)
                self.store.transition(intent.intent_id, IntentState.SUBMITTED, IntentState.UNKNOWN, reason_codes=reasons)
                self.store.add_evidence(intent.intent_id, "adapter_execution_exception", {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "attempt": attempt,
                })
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons)

        integrity_reason = self._effect_integrity_reason(self.store.get(intent.intent_id).effect_id, receipt.status, receipt.effect_id)
        if integrity_reason:
            return self._stop_execution_state(intent.intent_id, (integrity_reason,), decisions, release_usage=False)
        amount_reason = self._effect_amount_integrity_reason(intent, receipt.status, receipt.amount_usd)
        if amount_reason:
            return self._stop_execution_state(intent.intent_id, (amount_reason,), decisions, release_usage=False)

        if receipt.status not in {SettlementStatus.CONFIRMED, SettlementStatus.FINALIZED}:
            self.store.transition(intent.intent_id, IntentState.SUBMITTED, IntentState.UNKNOWN, reason_codes=("EXECUTION_NOT_SETTLED",))
            return self.reconcile(
                intent,
                grant=grant,
                authority=reauth[0] if reauth else None,
                risk=reauth[1] if reauth else None,
                authority_attestation=reauth[2] if reauth else None,
                risk_attestation=reauth[3] if reauth else None,
                now=now,
                decisions=decisions,
                _allow_resubmit=reauth is not None,
            )

        if receipt.status == SettlementStatus.CONFIRMED:
            try:
                self.store.transition(intent.intent_id, IntentState.SUBMITTED, IntentState.CONFIRMED, effect_id=receipt.effect_id)
            except EffectConflict:
                return self._stop_execution_state(
                    intent.intent_id, ("EFFECT_ID_ALREADY_CLAIMED",), decisions, release_usage=False
                )
            evidence = dict(receipt.evidence)
            evidence["amount_usd"] = format(receipt.amount_usd, "f") if receipt.amount_usd is not None else None
            self.store.add_evidence(intent.intent_id, "execution_confirmed", evidence)
            return self._current_result(intent.intent_id, decisions=decisions, effect_id=receipt.effect_id)

        try:
            self.store.transition(intent.intent_id, IntentState.SUBMITTED, IntentState.CONFIRMED, effect_id=receipt.effect_id)
            self.store.transition(intent.intent_id, IntentState.CONFIRMED, IntentState.FINALIZED, effect_id=receipt.effect_id)
        except EffectConflict:
            return self._stop_execution_state(
                intent.intent_id, ("EFFECT_ID_ALREADY_CLAIMED",), decisions, release_usage=False
            )
        self.store.commit_usage(intent.intent_id)
        evidence = dict(receipt.evidence)
        evidence["amount_usd"] = format(receipt.amount_usd, "f") if receipt.amount_usd is not None else None
        self.store.add_evidence(intent.intent_id, "execution_finalized", evidence)
        return self._current_result(intent.intent_id, decisions=decisions, effect_id=receipt.effect_id)

    def reconcile(
        self,
        intent: Intent,
        *,
        grant: CapabilityGrant,
        authority: AuthorityDecision | None = None,
        risk: RiskSnapshot | None = None,
        authority_attestation: Attestation | None = None,
        risk_attestation: Attestation | None = None,
        now: datetime | None = None,
        decisions: tuple[Decision, ...] = (),
        _allow_resubmit: bool = True,
        _block_reason: str | None = None,
    ) -> RuntimeResult:
        now_override = now if self.allow_test_time_override else None
        decision_now = self._decision_time(now)
        stored = self.store.get(intent.intent_id)
        previous_effect_id = stored.effect_id
        if stored.state in TERMINAL_STATES:
            return self._stored_result(stored, decisions=decisions, replayed=True)
        if intent.venue not in self.adapters:
            return self._stop_execution_state(intent.intent_id, ("ADAPTER_NOT_CONFIGURED",), decisions, release_usage=False)

        # Move to RECONCILING from every non-terminal execution state where legal.
        if stored.state == IntentState.CONFIRMED:
            self.store.transition(intent.intent_id, IntentState.CONFIRMED, IntentState.RECONCILING)
        elif stored.state in {IntentState.RESERVED, IntentState.SUBMITTED, IntentState.UNKNOWN}:
            self.store.transition(intent.intent_id, stored.state, IntentState.RECONCILING)
        elif stored.state != IntentState.RECONCILING:
            return self._stored_result(stored, decisions=decisions, replayed=True)

        adapter = self.adapters[intent.venue]
        try:
            settlement = adapter.reconcile(ExecutionRequest.from_intent(intent))
        except Exception as exc:
            reasons = ("RECONCILIATION_EXCEPTION",)
            self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.UNKNOWN, reason_codes=reasons)
            self.store.add_evidence(intent.intent_id, "reconciliation_exception", {
                "type": type(exc).__name__,
                "message": str(exc),
            })
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

        self.store.add_evidence(intent.intent_id, "reconciliation", {
            "status": settlement.status.value,
            "effect_id": settlement.effect_id,
            "amount_usd": format(settlement.amount_usd, "f") if settlement.amount_usd is not None else None,
            "authoritative": settlement.authoritative,
            "evidence": dict(settlement.evidence),
        })

        integrity_reason = self._effect_integrity_reason(previous_effect_id, settlement.status, settlement.effect_id)
        if integrity_reason:
            return self._stop_execution_state(
                intent.intent_id,
                (integrity_reason,),
                decisions,
                effect_id=previous_effect_id,
                release_usage=False,
                replayed=True,
            )

        if settlement.status in {SettlementStatus.CONFIRMED, SettlementStatus.FINALIZED} and not settlement.authoritative:
            reasons = ("SETTLEMENT_POSITIVE_NOT_AUTHORITATIVE",)
            self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.UNKNOWN, reason_codes=reasons)
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

        amount_reason = self._effect_amount_integrity_reason(intent, settlement.status, settlement.amount_usd)
        if amount_reason:
            return self._stop_execution_state(
                intent.intent_id, (amount_reason,), decisions, effect_id=previous_effect_id,
                release_usage=False, replayed=True,
            )

        if settlement.status == SettlementStatus.FINALIZED:
            try:
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.FINALIZED, effect_id=settlement.effect_id)
            except EffectConflict:
                return self._stop_execution_state(
                    intent.intent_id, ("EFFECT_ID_ALREADY_CLAIMED",), decisions, release_usage=False, replayed=True
                )
            self.store.commit_usage(intent.intent_id)
            return self._current_result(intent.intent_id, decisions=decisions, effect_id=settlement.effect_id, replayed=True)
        if settlement.status == SettlementStatus.CONFIRMED:
            try:
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.CONFIRMED, effect_id=settlement.effect_id)
            except EffectConflict:
                return self._stop_execution_state(
                    intent.intent_id, ("EFFECT_ID_ALREADY_CLAIMED",), decisions, release_usage=False, replayed=True
                )
            return self._current_result(intent.intent_id, decisions=decisions, effect_id=settlement.effect_id, replayed=True)
        if settlement.status in {SettlementStatus.UNKNOWN, SettlementStatus.CONTRADICTORY}:
            state = IntentState.STOPPED if settlement.status == SettlementStatus.CONTRADICTORY else IntentState.UNKNOWN
            reason = "SETTLEMENT_CONTRADICTORY" if settlement.status == SettlementStatus.CONTRADICTORY else "SETTLEMENT_UNKNOWN"
            reasons = (reason,) + ((_block_reason,) if _block_reason else ())
            self.store.transition(intent.intent_id, IntentState.RECONCILING, state, reason_codes=reasons)
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

        if settlement.status == SettlementStatus.NONE:
            if not settlement.authoritative:
                reasons = ("SETTLEMENT_NONE_NOT_AUTHORITATIVE",)
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.UNKNOWN, reason_codes=reasons)
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

            # Authoritative NONE is the only state in which releasing the held budget
            # or considering a retry is safe.
            if not _allow_resubmit:
                reason = _block_reason or "RESUBMISSION_BLOCKED"
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.STOPPED, reason_codes=(reason,))
                self.store.release_usage(intent.intent_id)
                self.store.add_evidence(intent.intent_id, "resubmission_blocked", {"reason": reason})
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=(reason,), replayed=True)

            if decision_now > intent.expires_at:
                reasons = ("INTENT_EXPIRED_BEFORE_RESUBMIT",)
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.STOPPED, reason_codes=reasons)
                self.store.release_usage(intent.intent_id)
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)
            if grant.valid_until is not None and decision_now > grant.valid_until:
                reasons = ("GRANT_EXPIRED_BEFORE_RESUBMIT",)
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.STOPPED, reason_codes=reasons)
                self.store.release_usage(intent.intent_id)
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)
            if self.store.get_grant_status(grant.grant_id, grant.version) != "ACTIVE":
                reasons = ("GRANT_NOT_ACTIVE_BEFORE_RESUBMIT",)
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.STOPPED, reason_codes=reasons)
                self.store.release_usage(intent.intent_id)
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

            if any(v is None for v in (authority, risk, authority_attestation, risk_attestation)):
                reasons = ("FRESH_AUTHORIZATION_REQUIRED_FOR_RESUBMIT",)
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.STOPPED, reason_codes=reasons)
                self.store.release_usage(intent.intent_id)
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

            fresh_decisions, trust_reasons = self._evaluate_fresh(
                intent,
                authority,  # type: ignore[arg-type]
                grant,
                risk,  # type: ignore[arg-type]
                authority_attestation,  # type: ignore[arg-type]
                risk_attestation,  # type: ignore[arg-type]
                decision_now,
            )
            dominant = self._dominant(fresh_decisions)
            if trust_reasons or dominant.verdict != Verdict.ALLOW:
                reasons = ("RESUBMIT_NOT_AUTHORIZED",) + trust_reasons + tuple(
                    r for d in fresh_decisions for r in d.reason_codes
                )
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.STOPPED, reason_codes=reasons)
                self.store.release_usage(intent.intent_id)
                self.store.add_evidence(intent.intent_id, "resubmit_authorization_failed", {"reason_codes": list(reasons)})
                return self._current_result(intent.intent_id, decisions=fresh_decisions, reason_codes=reasons, replayed=True)

            return self._submit(
                intent,
                grant,
                fresh_decisions,
                now=now_override,
                reauth=(authority, risk, authority_attestation, risk_attestation),  # type: ignore[arg-type]
            )

        return self._stop_execution_state(
            intent.intent_id,
            ("UNHANDLED_SETTLEMENT_STATE",),
            decisions,
            release_usage=False,
            replayed=True,
        )

    @staticmethod
    def _effect_amount_integrity_reason(
        intent: Intent,
        status: SettlementStatus,
        actual_amount: Decimal | None,
    ) -> str | None:
        if status not in {SettlementStatus.CONFIRMED, SettlementStatus.FINALIZED}:
            return None
        if intent.primitive not in MONETARY_PRIMITIVES:
            return None
        raw = intent.payload.get("amount_usd", intent.payload.get("notional_usd"))
        try:
            intended = Decimal(str(raw))
        except (InvalidOperation, ValueError, TypeError):
            return "AUTHORIZED_EFFECT_AMOUNT_INVALID"
        if not intended.is_finite() or intended <= 0:
            return "AUTHORIZED_EFFECT_AMOUNT_INVALID"
        if actual_amount is None:
            return "SETTLED_AMOUNT_REQUIRED"
        if not actual_amount.is_finite() or actual_amount <= 0:
            return "SETTLED_AMOUNT_INVALID"
        if intent.primitive.value == "PAY":
            if actual_amount != intended:
                return "PAYMENT_AMOUNT_MISMATCH"
        elif actual_amount > intended:
            return "SETTLED_AMOUNT_EXCEEDS_AUTHORIZED"
        return None

    @staticmethod
    def _effect_integrity_reason(
        previous_effect_id: str | None,
        status: SettlementStatus,
        effect_id: str | None,
    ) -> str | None:
        if status in {SettlementStatus.CONFIRMED, SettlementStatus.FINALIZED} and not effect_id:
            return "SETTLED_EFFECT_ID_REQUIRED"
        if previous_effect_id is not None:
            if status == SettlementStatus.NONE:
                return "SETTLEMENT_LOST_PREVIOUS_EFFECT"
            if effect_id is not None and effect_id != previous_effect_id:
                return "SETTLEMENT_EFFECT_ID_MISMATCH"
        return None

    def _stop_if_possible(self, stored, reasons: tuple[str, ...]) -> RuntimeResult:
        if stored.state == IntentState.PROPOSED:
            self.store.transition(stored.intent_id, IntentState.PROPOSED, IntentState.STOPPED, reason_codes=reasons)
            self.store.release_usage(stored.intent_id)
            return self._current_result(stored.intent_id, reason_codes=reasons)
        return self._stored_result(stored, replayed=True)

    def _stop_execution_state(
        self,
        intent_id: str,
        reasons: tuple[str, ...],
        decisions: tuple[Decision, ...] = (),
        *,
        effect_id: str | None = None,
        release_usage: bool,
        replayed: bool = False,
    ) -> RuntimeResult:
        stored = self.store.get(intent_id)
        if stored.state not in TERMINAL_STATES and IntentState.STOPPED in self._allowed_from(stored.state):
            self.store.transition(intent_id, stored.state, IntentState.STOPPED, reason_codes=reasons, effect_id=effect_id)
        if release_usage:
            self.store.release_usage(intent_id)
        self.store.add_evidence(intent_id, "execution_stopped", {"reason_codes": list(reasons)})
        return self._current_result(intent_id, decisions=decisions, effect_id=effect_id, reason_codes=reasons, replayed=replayed)

    @staticmethod
    def _allowed_from(state: IntentState) -> set[IntentState]:
        # Local copy of the only transition queried by runtime helpers; avoids
        # exporting the store's whole transition table as public API.
        if state in {
            IntentState.PROPOSED,
            IntentState.AUTHORIZED,
            IntentState.RESERVED,
            IntentState.SUBMITTED,
            IntentState.UNKNOWN,
            IntentState.RECONCILING,
            IntentState.CONFIRMED,
        }:
            return {IntentState.STOPPED}
        return set()

    def _current_result(
        self,
        intent_id: str,
        *,
        decisions: tuple[Decision, ...] = (),
        effect_id: str | None = None,
        reason_codes: tuple[str, ...] = (),
        replayed: bool = False,
    ) -> RuntimeResult:
        stored = self.store.get(intent_id)
        return RuntimeResult(
            intent_id=intent_id,
            state=stored.state,
            decisions=decisions,
            effect_id=effect_id if effect_id is not None else stored.effect_id,
            reason_codes=reason_codes if reason_codes else stored.reason_codes,
            replayed=replayed,
            submission_count=stored.submission_count,
        )

    @staticmethod
    def _stored_result(stored, *, decisions: tuple[Decision, ...] = (), replayed: bool = False) -> RuntimeResult:
        return RuntimeResult(
            intent_id=stored.intent_id,
            state=stored.state,
            decisions=decisions,
            effect_id=stored.effect_id,
            reason_codes=stored.reason_codes,
            replayed=replayed,
            submission_count=stored.submission_count,
        )

    @staticmethod
    def _dominant(decisions: tuple[Decision, ...]) -> Decision:
        rank = {Verdict.ALLOW: 0, Verdict.DEFER: 1, Verdict.DENY: 2, Verdict.STOP: 3}
        return max(decisions, key=lambda d: rank[d.verdict])
