from __future__ import annotations

import threading
from dataclasses import dataclass
from decimal import Decimal
from datetime import datetime, timedelta
from typing import Callable, Mapping

from .adapters import AdapterDeadlineExceeded, AmbiguousExecution, DeterministicFailure, ExecutionAdapter
from .attestation import AttestationVerifier, has_signing_api
from .permits import ConstrainedPermitAuthority, PermitIssuanceError
from .settlement import SettlementVerifier
from .canonical import canonical_hash, parse_bounded_decimal
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
from .store import EffectConflict, GrantConflict, IntentBusy, SQLiteIntentStore, TERMINAL_STATES, UnknownGrant, UnknownIntent


# Adapter and verifier output is a trust boundary. An effect identity must be a
# bounded string before it can enter the evidence chain or the intents table;
# anything else is recorded as malformed rather than crashing the state machine.
MAX_EFFECT_ID_CHARS = 512

# Reason codes that durably block resubmission of an intent. They are persisted on
# the intent row so the block survives across process() calls and worker restarts.
_DETERMINISTIC_FAILURE_BLOCK = "EXECUTION_DETERMINISTIC_FAILURE"
_RESUBMIT_BLOCKING_REASONS = frozenset({
    _DETERMINISTIC_FAILURE_BLOCK,
    "EXECUTION_DETERMINISTIC_FAILURE_UNVERIFIED",
})


def _valid_effect_id(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_EFFECT_ID_CHARS


def _untrusted_repr(value: object) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else f"{type(value).__name__}:{value!r}"
    return text[:MAX_EFFECT_ID_CHARS]


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
        permit_authority: ConstrainedPermitAuthority,
        settlement_verifiers: Mapping[str, SettlementVerifier],
        *,
        clock: Callable[[], datetime] = utcnow,
        allow_test_time_override: bool = False,
        adapter_deadline_seconds: float | None = None,
    ) -> None:
        self.store = store
        self.adapters = dict(adapters)
        if adapter_deadline_seconds is not None and not adapter_deadline_seconds > 0:
            raise ValueError("adapter_deadline_seconds must be positive or None")
        # Bounded adapter calls: a hung venue call must not hold the per-grant
        # revocation fence indefinitely. Past the deadline the call is treated as an
        # in-flight ambiguity bounded by the permit's expiry.
        self.adapter_deadline_seconds = adapter_deadline_seconds
        for name, adapter in self.adapters.items():
            profile = getattr(adapter, "security_profile", None)
            if profile is None or not profile.exactly_once_compatible:
                raise ValueError(
                    f"adapter {name!r} is not exactly-once compatible: "
                    "stable intent identity, idempotent submission, stable effect identity, "
                    "permit enforcement, and single-use permit consumption are required"
                )
        if has_signing_api(trust):
            raise ValueError("FAAR runtime must receive a verify-only attestation trust store")
        self.trust = trust
        self.permit_authority = permit_authority
        self.settlement_verifiers = dict(settlement_verifiers)
        if set(self.settlement_verifiers) != set(self.adapters):
            raise ValueError("every execution adapter must have exactly one configured settlement verifier")
        for name, verifier in self.settlement_verifiers.items():
            if verifier is self.adapters[name]:
                raise ValueError(f"settlement verifier {name!r} must be a distinct component from the submitter")
            profile = getattr(verifier, "security_profile", None)
            if profile is None or not profile.trusted:
                raise ValueError(f"settlement verifier {name!r} does not satisfy the trusted verification profile")
        self.clock = clock
        self.allow_test_time_override = allow_test_time_override

    def _execute_adapter(self, adapter: ExecutionAdapter, request: ExecutionRequest, permit) -> object:
        """Call the adapter, bounded by `adapter_deadline_seconds` when configured.

        A Python thread cannot be cancelled, so a call that overruns is left to
        finish on its own; the runtime stops waiting and records the attempt as
        ambiguous until the permit the venue holds can no longer be consumed.
        """
        if self.adapter_deadline_seconds is None:
            return adapter.execute(request, permit)
        outcome: dict[str, object] = {}
        done = threading.Event()

        def run() -> None:
            try:
                outcome["receipt"] = adapter.execute(request, permit)
            except BaseException as exc:  # propagated to the caller below
                outcome["error"] = exc
            finally:
                done.set()

        worker = threading.Thread(target=run, name=f"faar-adapter-{request.intent_id}", daemon=True)
        worker.start()
        if not done.wait(self.adapter_deadline_seconds):
            raise AdapterDeadlineExceeded(
                f"adapter call exceeded {self.adapter_deadline_seconds}s; request may still be in flight"
            )
        if "error" in outcome:
            raise outcome["error"]  # type: ignore[misc]
        return outcome["receipt"]

    @staticmethod
    def _ambiguity_window_closes_at(stored, grant: CapabilityGrant) -> datetime | None:
        """Instant after which absence of an effect may be trusted again.

        The venue judges permit expiry by its own clock, so the runtime waits the
        grant's clock-skew allowance past the permit expiry before it will accept
        an authoritative NONE for an attempt that may still be in flight.
        """
        if not stored.ambiguity_until:
            return None
        return datetime.fromisoformat(stored.ambiguity_until) + timedelta(seconds=grant.limits.max_clock_skew_seconds)

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
        # Bind the canonical payload before waiting on the lease. A competing caller
        # cannot hide a changed payload behind an already-running intent id.
        stored = self.store.register(intent, canonical_hash(intent))
        if stored.state in TERMINAL_STATES:
            self._release_orphaned_hold(stored)
            return self._stored_result(stored, replayed=True)
        try:
            with self.store.intent_guard(intent.intent_id):
                return self._process_unlocked(
                    intent, authority, grant, risk,
                    authority_attestation=authority_attestation,
                    risk_attestation=risk_attestation, now=now,
                )
        except IntentBusy:
            current = self.store.get(intent.intent_id)
            return RuntimeResult(
                intent_id=intent.intent_id, state=current.state, effect_id=current.effect_id,
                reason_codes=("INTENT_BUSY",), replayed=True,
                submission_count=current.submission_count,
            )

    def _release_orphaned_hold(self, stored) -> None:
        """Release a HELD reservation left behind by a terminal, never-submitted intent.

        `submission_count` is incremented atomically with the SUBMITTED transition, so
        a terminal intent with a zero count provably never reached an adapter and its
        reservation cannot back an external effect. Anything else keeps its budget
        held; ambiguity is never resolved in favour of availability.
        """
        if stored.state in TERMINAL_STATES and stored.state != IntentState.FINALIZED and stored.submission_count == 0:
            self.store.release_usage(stored.intent_id)

    def _process_unlocked(
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

        runtime_grant_status = self.store.get_grant_status(grant.principal_id, grant.grant_id, grant.version)
        if runtime_grant_status != "ACTIVE":
            reason = f"GRANT_RUNTIME_{runtime_grant_status}"
            if existing.state in {IntentState.PROPOSED, IntentState.AUTHORIZED}:
                # No submission can have begun from these states, so the HELD
                # reservation is released in the same transaction as the stop.
                self.store.transition(intent.intent_id, existing.state, IntentState.STOPPED, reason_codes=(reason,), release_usage=True)
                self.store.add_evidence(intent.intent_id, "grant_runtime_inactive", {
                    "runtime_status": runtime_grant_status, "from_state": existing.state.value,
                })
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
                self.store.transition(intent.intent_id, IntentState.AUTHORIZED, IntentState.STOPPED, reason_codes=reasons, release_usage=True)
                self.store.add_evidence(intent.intent_id, "authorization_decision", {
                    "verdict": Verdict.STOP.value, "recovered_from": IntentState.AUTHORIZED.value,
                    "reason_codes": list(reasons),
                    "layers": [{"layer": d.layer, "verdict": d.verdict.value, "reason_codes": list(d.reason_codes)} for d in decisions],
                })
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
            # A recovered authorization must leave the same audit record as a fresh
            # one; otherwise the chain starts at submission with no trace of which
            # attested authority and risk state licensed the submission.
            self._record_authorized(intent, intent_hash, grant, authority_attestation, risk_attestation, recovered=True)
            return self._submit(intent, grant, decisions, now=now_override, reauth=(authority, risk, authority_attestation, risk_attestation))

        # Any interrupted execution state must reconcile before another submission.
        if existing.state in {
            IntentState.RESERVED,
            IntentState.SUBMITTED,
            IntentState.UNKNOWN,
            IntentState.RECONCILING,
            IntentState.CONFIRMED,
        }:
            # A durable resubmission block (deterministic adapter failure) persists on
            # the intent row and must survive across calls; a later authoritative
            # NONE may release the held budget but must not resubmit.
            blocked = any(r in _RESUBMIT_BLOCKING_REASONS for r in existing.reason_codes)
            return self.reconcile(
                intent,
                grant=grant,
                authority=authority,
                risk=risk,
                authority_attestation=authority_attestation,
                risk_attestation=risk_attestation,
                now=now_override,
                _allow_resubmit=not blocked,
                _block_reason=_DETERMINISTIC_FAILURE_BLOCK if blocked else None,
            )

        decisions, trust_reasons = self._evaluate_fresh(
            intent, authority, grant, risk, authority_attestation, risk_attestation, decision_now
        )
        if trust_reasons:
            self.store.transition(intent.intent_id, IntentState.PROPOSED, IntentState.STOPPED, reason_codes=trust_reasons, release_usage=True)
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
            # A prior crash may have occurred after atomic usage reservation but
            # before PROPOSED -> AUTHORIZED. Terminalizing PROPOSED is proof that
            # no adapter submission began, so any orphan HELD reservation is safe
            # to release, atomically with the terminal transition.
            self.store.transition(intent.intent_id, IntentState.PROPOSED, target_state, reason_codes=reasons, release_usage=True)
            self.store.add_evidence(intent.intent_id, "authorization_decision", {
                "verdict": dominant.verdict.value,
                "reason_codes": list(reasons),
                "layers": [{"layer": d.layer, "verdict": d.verdict.value, "reason_codes": list(d.reason_codes)} for d in decisions],
            })
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons)

        if intent.venue not in self.adapters:
            reasons = ("ADAPTER_NOT_CONFIGURED",)
            self.store.transition(intent.intent_id, IntentState.PROPOSED, IntentState.STOPPED, reason_codes=reasons, release_usage=True)
            self.store.add_evidence(intent.intent_id, "execution_stopped", {"reason_codes": list(reasons)})
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

        self._record_authorized(intent, intent_hash, grant, authority_attestation, risk_attestation)
        return self._submit(intent, grant, decisions, now=now_override, reauth=(authority, risk, authority_attestation, risk_attestation))

    def _record_authorized(
        self,
        intent: Intent,
        intent_hash: str,
        grant: CapabilityGrant,
        authority_attestation: Attestation,
        risk_attestation: Attestation,
        *,
        recovered: bool = False,
    ) -> None:
        self.store.add_evidence(intent.intent_id, "authorized", {
            "intent_hash": intent_hash,
            "grant_id": grant.grant_id,
            "grant_version": grant.version,
            "venue": intent.venue,
            "authority_attestation_hash": canonical_hash(authority_attestation),
            "risk_attestation_hash": canonical_hash(risk_attestation),
            "recovered": recovered,
        })

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
        reauth_kwargs = dict(
            authority=reauth[0] if reauth else None,
            risk=reauth[1] if reauth else None,
            authority_attestation=reauth[2] if reauth else None,
            risk_attestation=reauth[3] if reauth else None,
        )

        # Revocation fence: set_grant_status holds this same per-grant guard. An
        # execution already inside the guard linearizes before revocation; after a
        # successful revoke call returns, no later adapter submission can begin.
        #
        # The fence covers exactly the window from the final pre-submission checks
        # through the adapter call. Settlement verification and any retry run after
        # the guard is released so a slow or hung verifier cannot delay pause/revoke;
        # a retry re-enters this method and re-acquires the fence, re-checking grant
        # status and permit epoch before any new submission.
        outcome = "receipt"
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

            status = self.store.get_grant_status(grant.principal_id, grant.grant_id, grant.version)
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
                outcome = "not_started"
            else:
                request = ExecutionRequest.from_intent(intent)
                try:
                    permit = self.permit_authority.issue(
                        request,
                        intent=intent,
                        authority=reauth[0] if reauth else None,  # type: ignore[arg-type]
                        grant=grant,
                        risk=reauth[1] if reauth else None,  # type: ignore[arg-type]
                        authority_attestation=reauth[2] if reauth else None,  # type: ignore[arg-type]
                        risk_attestation=reauth[3] if reauth else None,  # type: ignore[arg-type]
                        now=submit_now,
                    )
                except PermitIssuanceError as exc:
                    reasons = ("EXECUTION_PERMIT_REJECTED",) + exc.reasons
                    self.store.transition(intent.intent_id, IntentState.SUBMITTED, IntentState.FAILED_SAFE, reason_codes=reasons, release_usage=True)
                    self.store.add_evidence(intent.intent_id, "execution_permit_rejected", {"reason_codes": list(exc.reasons), "attempt": attempt})
                    return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons)
                except Exception as exc:
                    # Permit issuance happens before the adapter sees anything, so an
                    # unexpected signer/store failure is fail-safe rather than economically
                    # ambiguous. No external execution capability was transported.
                    reasons = ("EXECUTION_PERMIT_EXCEPTION",)
                    self.store.transition(intent.intent_id, IntentState.SUBMITTED, IntentState.FAILED_SAFE, reason_codes=reasons, release_usage=True)
                    self.store.add_evidence(intent.intent_id, "execution_permit_exception", {
                        "type": type(exc).__name__, "message": str(exc), "attempt": attempt,
                    })
                    return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons)

                self.store.add_evidence(intent.intent_id, "submission_started", {
                    "venue": intent.venue,
                    "attempt": attempt,
                    "permit_id": permit.permit.permit_id,
                    "permit_hash": canonical_hash(permit),
                    "grant_epoch": permit.permit.grant_epoch,
                    "fence_token": permit.permit.fence_token,
                })
                # While the signed permit is live the venue may still act on an
                # attempt whose outcome the runtime never observed. Absence of an
                # effect is therefore not authoritative until the permit has expired.
                ambiguity_until = permit.permit.expires_at
                try:
                    receipt = self._execute_adapter(adapter, request, permit)
                except AmbiguousExecution as exc:
                    outcome = "ambiguous"
                    reason = "EXECUTION_DEADLINE_EXCEEDED" if isinstance(exc, AdapterDeadlineExceeded) else "EXECUTION_AMBIGUOUS"
                    self.store.transition(
                        intent.intent_id, IntentState.SUBMITTED, IntentState.UNKNOWN,
                        reason_codes=(reason,), ambiguity_until=ambiguity_until,
                    )
                    self.store.add_evidence(intent.intent_id, "execution_ambiguous", {
                        "message": str(exc), "attempt": attempt, "reason": reason,
                        "ambiguity_until": ambiguity_until.isoformat(),
                    })
                except DeterministicFailure as exc:
                    # A submitter is not allowed to prove non-execution. Even a
                    # deterministic-looking rejection is independently reconciled before
                    # held budget is released. The verifier may still find an effect.
                    # The block on resubmission is persisted in the reason codes so it
                    # survives across calls and worker restarts.
                    outcome = "deterministic"
                    self.store.transition(
                        intent.intent_id, IntentState.SUBMITTED, IntentState.UNKNOWN,
                        reason_codes=("EXECUTION_DETERMINISTIC_FAILURE_UNVERIFIED",),
                    )
                    self.store.add_evidence(intent.intent_id, "adapter_rejection_untrusted", {
                        "message": str(exc), "attempt": attempt,
                    })
                except Exception as exc:
                    # Adapter crashes are economically ambiguous. The independent
                    # verifier, never the submitter, decides whether an effect exists.
                    outcome = "exception"
                    self.store.transition(
                        intent.intent_id, IntentState.SUBMITTED, IntentState.UNKNOWN,
                        reason_codes=("ADAPTER_EXECUTION_EXCEPTION",), ambiguity_until=ambiguity_until,
                    )
                    self.store.add_evidence(intent.intent_id, "adapter_execution_exception", {
                        "type": type(exc).__name__, "message": str(exc), "attempt": attempt,
                        "ambiguity_until": ambiguity_until.isoformat(),
                    })
                else:
                    # A submitter receipt is telemetry, not settlement authority. Never
                    # persist its effect id or amount as economic truth. Only the
                    # configured independent settlement verifier may advance
                    # CONFIRMED/FINALIZED. Receipt fields are bounded/stringified here
                    # because adapter output is a trust boundary and must not be able to
                    # crash evidence recording.
                    self.store.add_evidence(intent.intent_id, "adapter_receipt_untrusted", {
                        "reported_status": receipt.status.value,
                        "reported_effect_id": _untrusted_repr(receipt.effect_id),
                        "reported_effect_id_well_formed": _valid_effect_id(receipt.effect_id),
                        "reported_amount_usd": format(receipt.amount_usd, "f") if receipt.amount_usd is not None else None,
                        "evidence": dict(receipt.evidence),
                    })
                    self.store.transition(
                        intent.intent_id, IntentState.SUBMITTED, IntentState.UNKNOWN,
                        reason_codes=("AWAITING_INDEPENDENT_SETTLEMENT",),
                    )

        if outcome == "deterministic":
            return self.reconcile(
                intent, grant=grant, **reauth_kwargs, now=now, decisions=decisions,
                _allow_resubmit=False, _block_reason=_DETERMINISTIC_FAILURE_BLOCK,
            )
        return self.reconcile(
            intent, grant=grant, **reauth_kwargs, now=now, decisions=decisions,
            _allow_resubmit=reauth is not None,
        )

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
        try:
            with self.store.intent_guard(intent.intent_id):
                return self._reconcile_unlocked(
                    intent, grant=grant, authority=authority, risk=risk,
                    authority_attestation=authority_attestation, risk_attestation=risk_attestation,
                    now=now, decisions=decisions, _allow_resubmit=_allow_resubmit,
                    _block_reason=_block_reason,
                )
        except IntentBusy:
            current = self.store.get(intent.intent_id)
            return RuntimeResult(
                intent_id=intent.intent_id, state=current.state, decisions=decisions,
                effect_id=current.effect_id, reason_codes=("INTENT_BUSY",), replayed=True,
                submission_count=current.submission_count,
            )

    def _reconcile_unlocked(
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
        # An unregistered intent has no durable state to reconcile; the store raises
        # the typed UnknownIntent (a KeyError subclass) rather than mutating anything.
        stored = self.store.get(intent.intent_id)
        previous_effect_id = stored.effect_id
        if stored.state in TERMINAL_STATES:
            return self._stored_result(stored, decisions=decisions, replayed=True)

        # The presented grant must be the provisioned envelope before any state
        # mutation. A caller presenting the wrong grant is not evidence about the
        # in-flight intent, so the result is machine-readable and non-mutating.
        try:
            self.store.verify_grant(grant, canonical_hash(grant))
        except UnknownGrant:
            return self._stored_result(stored, decisions=decisions, replayed=True, reason_codes=("GRANT_NOT_PROVISIONED",))
        except GrantConflict:
            return self._stored_result(stored, decisions=decisions, replayed=True, reason_codes=("GRANT_ENVELOPE_MISMATCH",))

        if intent.venue not in self.adapters:
            # PROPOSED/AUTHORIZED/RESERVED prove that begin_submission never ran, so
            # the HELD reservation is safe to release; every later state may have an
            # external effect and keeps its budget held.
            never_submitted = stored.state in {IntentState.PROPOSED, IntentState.AUTHORIZED, IntentState.RESERVED}
            return self._stop_execution_state(
                intent.intent_id, ("ADAPTER_NOT_CONFIGURED",), decisions, release_usage=never_submitted,
            )

        # Move to RECONCILING from every non-terminal execution state where legal.
        if stored.state == IntentState.CONFIRMED:
            self.store.transition(intent.intent_id, IntentState.CONFIRMED, IntentState.RECONCILING)
        elif stored.state in {IntentState.RESERVED, IntentState.SUBMITTED, IntentState.UNKNOWN}:
            self.store.transition(intent.intent_id, stored.state, IntentState.RECONCILING)
        elif stored.state != IntentState.RECONCILING:
            return self._stored_result(stored, decisions=decisions, replayed=True)

        verifier = self.settlement_verifiers[intent.venue]
        request = ExecutionRequest.from_intent(intent)
        request_hash = canonical_hash(request)
        try:
            settlement = verifier.verify(request)
        except Exception as exc:
            reasons = self._with_block("RECONCILIATION_EXCEPTION", _block_reason)
            self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.UNKNOWN, reason_codes=reasons)
            self.store.add_evidence(intent.intent_id, "reconciliation_exception", {
                "type": type(exc).__name__,
                "message": str(exc),
            })
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

        # Verifier output is a trust boundary: the effect identity is validated before
        # it can enter the evidence chain or the intents table.
        effect_id_well_formed = settlement.effect_id is None or _valid_effect_id(settlement.effect_id)
        self.store.add_evidence(intent.intent_id, "reconciliation", {
            "status": settlement.status.value,
            "effect_id": _untrusted_repr(settlement.effect_id),
            "effect_id_well_formed": effect_id_well_formed,
            "amount_usd": format(settlement.amount_usd, "f") if settlement.amount_usd is not None else None,
            "authoritative": settlement.authoritative,
            "verified_request_hash": settlement.verified_request_hash,
            "evidence": dict(settlement.evidence),
        })

        # A non-authoritative observation carries no economic weight in either
        # direction (I-8, I-9, I-23): a weak "not found" is not loss of a previous
        # effect and a weak positive cannot confirm, change, or invalidate one. Only
        # a contradiction is acted on regardless of authority, because STOP is the
        # conservative direction. Continuity/amount integrity is therefore judged
        # against authoritative records only.
        if not settlement.authoritative and settlement.status in {
            SettlementStatus.CONFIRMED, SettlementStatus.FINALIZED, SettlementStatus.NONE,
        }:
            reason = (
                "SETTLEMENT_NONE_NOT_AUTHORITATIVE"
                if settlement.status == SettlementStatus.NONE
                else "SETTLEMENT_POSITIVE_NOT_AUTHORITATIVE"
            )
            reasons = self._with_block(reason, _block_reason)
            self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.UNKNOWN, reason_codes=reasons)
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

        if settlement.authoritative and settlement.verified_request_hash != request_hash:
            return self._stop_execution_state(
                intent.intent_id, ("SETTLEMENT_REQUEST_BINDING_MISMATCH",), decisions,
                effect_id=previous_effect_id, release_usage=False, replayed=True,
            )

        if settlement.authoritative and not effect_id_well_formed:
            return self._stop_execution_state(
                intent.intent_id, ("SETTLED_EFFECT_ID_INVALID",), decisions,
                effect_id=previous_effect_id, release_usage=False, replayed=True,
            )

        integrity_reason = (
            self._effect_integrity_reason(previous_effect_id, settlement.status, settlement.effect_id)
            if settlement.authoritative else None
        )
        if integrity_reason:
            return self._stop_execution_state(
                intent.intent_id,
                (integrity_reason,),
                decisions,
                effect_id=previous_effect_id,
                release_usage=False,
                replayed=True,
            )

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
            reasons = self._with_block(reason, _block_reason)
            self.store.transition(intent.intent_id, IntentState.RECONCILING, state, reason_codes=reasons)
            if state == IntentState.STOPPED:
                self.store.add_evidence(intent.intent_id, "execution_stopped", {"reason_codes": list(reasons)})
            return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

        if settlement.status == SettlementStatus.NONE:
            # Authoritative NONE is the only state in which releasing the held budget
            # or considering a retry is safe, and only once no in-flight attempt can
            # still be acted on by the venue (I-9): before the permit window closes a
            # venue that has not yet processed the request will truthfully report
            # "no effect" and a retry would create a duplicate.
            window_closes_at = self._ambiguity_window_closes_at(stored, grant)
            if window_closes_at is not None and decision_now < window_closes_at:
                reasons = self._with_block("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", _block_reason)
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.UNKNOWN, reason_codes=reasons)
                self.store.add_evidence(intent.intent_id, "ambiguity_window_open", {
                    "closes_at": window_closes_at.isoformat(), "observed_at": decision_now.isoformat(),
                })
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=reasons, replayed=True)

            if not _allow_resubmit:
                reason = _block_reason or "RESUBMISSION_BLOCKED"
                target = (
                    IntentState.FAILED_SAFE
                    if reason == _DETERMINISTIC_FAILURE_BLOCK
                    else IntentState.STOPPED
                )
                self.store.transition(intent.intent_id, IntentState.RECONCILING, target, reason_codes=(reason,), release_usage=True)
                self.store.add_evidence(intent.intent_id, "resubmission_blocked", {
                    "reason": reason, "authoritative_none": True, "terminal_state": target.value,
                })
                return self._current_result(intent.intent_id, decisions=decisions, reason_codes=(reason,), replayed=True)

            for blocked, reason in (
                (decision_now > intent.expires_at, "INTENT_EXPIRED_BEFORE_RESUBMIT"),
                (grant.valid_until is not None and decision_now > grant.valid_until, "GRANT_EXPIRED_BEFORE_RESUBMIT"),
                (self.store.get_grant_status(grant.principal_id, grant.grant_id, grant.version) != "ACTIVE", "GRANT_NOT_ACTIVE_BEFORE_RESUBMIT"),
                (any(v is None for v in (authority, risk, authority_attestation, risk_attestation)), "FRESH_AUTHORIZATION_REQUIRED_FOR_RESUBMIT"),
            ):
                if blocked:
                    reasons = (reason,)
                    self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.STOPPED, reason_codes=reasons, release_usage=True)
                    self.store.add_evidence(intent.intent_id, "resubmission_blocked", {
                        "reason": reason, "authoritative_none": True, "terminal_state": IntentState.STOPPED.value,
                    })
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
                self.store.transition(intent.intent_id, IntentState.RECONCILING, IntentState.STOPPED, reason_codes=reasons, release_usage=True)
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
    def _with_block(reason: str, block: str | None) -> tuple[str, ...]:
        """Carry a durable resubmission block through every non-terminal transition."""
        if block and block != reason:
            return (reason, block)
        return (reason,)

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
        intended = parse_bounded_decimal(intent.payload.get("amount_usd", intent.payload.get("notional_usd")))
        if intended is None or intended <= 0:
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
            self.store.transition(stored.intent_id, IntentState.PROPOSED, IntentState.STOPPED, reason_codes=reasons, release_usage=True)
            self.store.add_evidence(stored.intent_id, "grant_rejected", {"reason_codes": list(reasons)})
            return self._current_result(stored.intent_id, reason_codes=reasons)
        return self._stored_result(stored, replayed=True, reason_codes=reasons)

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
        transitioned = False
        if stored.state not in TERMINAL_STATES and IntentState.STOPPED in self._allowed_from(stored.state):
            transitioned = self.store.transition(
                intent_id, stored.state, IntentState.STOPPED,
                reason_codes=reasons, effect_id=effect_id, release_usage=release_usage,
            )
        if release_usage and not transitioned:
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
    def _stored_result(
        stored,
        *,
        decisions: tuple[Decision, ...] = (),
        replayed: bool = False,
        reason_codes: tuple[str, ...] | None = None,
    ) -> RuntimeResult:
        return RuntimeResult(
            intent_id=stored.intent_id,
            state=stored.state,
            decisions=decisions,
            effect_id=stored.effect_id,
            reason_codes=stored.reason_codes if reason_codes is None else reason_codes,
            replayed=replayed,
            submission_count=stored.submission_count,
        )

    @staticmethod
    def _dominant(decisions: tuple[Decision, ...]) -> Decision:
        rank = {Verdict.ALLOW: 0, Verdict.DEFER: 1, Verdict.DENY: 2, Verdict.STOP: 3}
        return max(decisions, key=lambda d: rank[d.verdict])
