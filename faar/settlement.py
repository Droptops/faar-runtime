from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Protocol, Sequence

from .adapters import MockMode, MockVenue
from .canonical import canonical_hash
from .models import ExecutionRequest, SettlementRecord, SettlementStatus


@dataclass(frozen=True)
class SettlementSecurityProfile:
    authoritative: bool
    independent_from_submitter: bool
    stable_effect_identity: bool
    amount_evidence: bool

    @property
    def trusted(self) -> bool:
        return all((
            self.authoritative,
            self.independent_from_submitter,
            self.stable_effect_identity,
            self.amount_evidence,
        ))


REFERENCE_SETTLEMENT_PROFILE = SettlementSecurityProfile(True, True, True, True)


class SettlementVerifier(Protocol):
    name: str
    security_profile: SettlementSecurityProfile

    def verify(self, request: ExecutionRequest) -> SettlementRecord: ...


@dataclass
class MockSettlementVerifier:
    """Independent read path over the mock venue ledger.

    It shares economic ground truth with the venue but is a separate component from
    the submitter. A real deployment should use an independently authenticated venue
    API, chain verifier, clearing record, or multiple-source quorum.
    """

    venue: MockVenue
    name: str = "mock-settlement-verifier"
    security_profile: SettlementSecurityProfile = REFERENCE_SETTLEMENT_PROFILE

    def verify(self, request: ExecutionRequest) -> SettlementRecord:
        request_hash = canonical_hash(request)
        receipt = self.venue.lookup_effect(request)
        if receipt:
            observed_request_hash = receipt.evidence.get("request_hash")
            if observed_request_hash != request_hash:
                return SettlementRecord(
                    SettlementStatus.CONTRADICTORY,
                    evidence={
                        "verifier": self.name,
                        "reason": "observed-effect-request-binding-mismatch",
                        "observed_request_hash": observed_request_hash,
                        "expected_request_hash": request_hash,
                    },
                    authoritative=True,
                    verified_request_hash=request_hash,
                )
            return SettlementRecord(
                status=receipt.status,
                effect_id=receipt.effect_id,
                amount_usd=receipt.amount_usd,
                evidence=receipt.evidence,
                authoritative=True,
                verified_request_hash=request_hash,
            )
        if getattr(self.venue, "mode", MockMode.SUCCESS) == MockMode.AMBIGUOUS:
            return SettlementRecord(SettlementStatus.UNKNOWN, evidence={"verifier": self.name}, authoritative=False)
        return SettlementRecord(
            SettlementStatus.NONE, evidence={"verifier": self.name}, authoritative=True,
            verified_request_hash=request_hash,
        )


@dataclass
class QuorumSettlementVerifier:
    """Require independent sources to agree on a positive/negative settlement fact."""

    sources: Sequence[SettlementVerifier]
    quorum: int
    name: str = "settlement-quorum"
    security_profile: SettlementSecurityProfile = REFERENCE_SETTLEMENT_PROFILE

    def __post_init__(self) -> None:
        if self.quorum < 2:
            raise ValueError("settlement quorum must be at least 2")
        if len(self.sources) < self.quorum:
            raise ValueError("not enough settlement sources for quorum")
        if any(not s.security_profile.trusted for s in self.sources):
            raise ValueError("all quorum sources must satisfy the trusted settlement profile")
        if len({id(s) for s in self.sources}) != len(self.sources):
            raise ValueError("the same settlement verifier object cannot be counted twice")
        names = [s.name for s in self.sources]
        if len(set(names)) != len(names):
            raise ValueError("settlement quorum sources must have unique identities")

    @staticmethod
    def _fact(record: SettlementRecord) -> tuple[str, str | None, str | None]:
        # Vote on the numeric value, not its textual scale: Decimal("50") and
        # Decimal("50.00") from two honest sources are one fact, not a contradiction.
        amount = None if record.amount_usd is None else format(record.amount_usd.normalize(), "f")
        return record.status.value, record.effect_id, amount

    def verify(self, request: ExecutionRequest) -> SettlementRecord:
        expected_hash = canonical_hash(request)
        # One unreachable minority source must not wedge an intent whose effect a
        # quorum of healthy sources can attest. A raising source contributes a
        # non-authoritative UNKNOWN, exactly like a source that answers "I don't
        # know"; it can never contribute to a positive or negative quorum.
        observations: list[tuple[str, SettlementRecord]] = []
        errors: dict[str, str] = {}
        for source in self.sources:
            try:
                observations.append((source.name, source.verify(request)))
            except Exception as exc:
                errors[source.name] = type(exc).__name__
                observations.append((source.name, SettlementRecord(
                    SettlementStatus.UNKNOWN, evidence={"verifier": source.name, "error": type(exc).__name__},
                    authoritative=False,
                )))
        records = [record for _, record in observations]
        counts: dict[tuple[str, str | None, str | None], int] = {}
        binding_mismatches = 0
        for record in records:
            if not record.authoritative:
                continue
            if record.verified_request_hash != expected_hash:
                binding_mismatches += 1
                continue
            fact = self._fact(record)
            counts[fact] = counts.get(fact, 0) + 1
        if not counts:
            if binding_mismatches:
                return SettlementRecord(
                    SettlementStatus.CONTRADICTORY,
                    evidence={"quorum": "request-binding-mismatch", "mismatches": binding_mismatches, "errors": errors},
                    authoritative=True,
                    verified_request_hash=expected_hash,
                )
            return SettlementRecord(
                SettlementStatus.UNKNOWN, evidence={"quorum": "no-authoritative-facts", "errors": errors}, authoritative=False,
            )
        # Reaching quorum is necessary but not sufficient. If two DISTINCT
        # authoritative facts each reach quorum (e.g. a 2-2 split with quorum=2),
        # settlement is genuinely contested and must fail closed, not be resolved
        # by whichever fact `max` happens to visit first.
        quorum_facts = [fact for fact, count in counts.items() if count >= self.quorum]
        if len(quorum_facts) > 1:
            return SettlementRecord(
                SettlementStatus.CONTRADICTORY,
                evidence={
                    "quorum": "multiple-facts-reached-quorum",
                    "required": self.quorum,
                    "facts": [self._fact(r) for r in records],
                    "binding_mismatches": binding_mismatches,
                },
                authoritative=True,
                verified_request_hash=expected_hash,
            )
        fact, count = max(counts.items(), key=lambda kv: kv[1])
        if count < self.quorum:
            return SettlementRecord(
                SettlementStatus.CONTRADICTORY,
                evidence={
                    "quorum": count, "required": self.quorum,
                    "facts": [self._fact(r) for r in records],
                    "binding_mismatches": binding_mismatches,
                },
                authoritative=True,
                verified_request_hash=expected_hash,
            )
        status = SettlementStatus(fact[0])
        amount = Decimal(fact[2]) if fact[2] is not None else None
        # Carry the agreeing sources' evidence forward so definition-of-done
        # criteria that address venue evidence (fill quantities, assets) remain
        # evaluable behind a quorum. Identical evidence is merged at the top level;
        # per-source evidence is always available under `source_evidence`. The
        # runtime-owned standard fields (effect_id, amount_usd, status) still
        # override same-named evidence keys at outcome evaluation.
        agreeing = [
            (name, record) for name, record in observations
            if record.authoritative and record.verified_request_hash == expected_hash and self._fact(record) == fact
        ]
        evidence: dict = {}
        if agreeing and len({canonical_hash(record.evidence) for _, record in agreeing}) == 1:
            evidence.update(dict(agreeing[0][1].evidence))
        evidence.update({
            "quorum": count,
            "required": self.quorum,
            "sources": [s.name for s in self.sources],
            "source_evidence": {name: dict(record.evidence) for name, record in agreeing},
            "errors": errors,
        })
        return SettlementRecord(
            status=status,
            effect_id=fact[1],
            amount_usd=amount,
            evidence=evidence,
            authoritative=True,
            verified_request_hash=expected_hash,
        )
