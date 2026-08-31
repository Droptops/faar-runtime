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
        amount = None if record.amount_usd is None else format(record.amount_usd, "f")
        return record.status.value, record.effect_id, amount

    def verify(self, request: ExecutionRequest) -> SettlementRecord:
        expected_hash = canonical_hash(request)
        records = [source.verify(request) for source in self.sources]
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
                    evidence={"quorum": "request-binding-mismatch", "mismatches": binding_mismatches},
                    authoritative=True,
                    verified_request_hash=expected_hash,
                )
            return SettlementRecord(SettlementStatus.UNKNOWN, evidence={"quorum": "no-authoritative-facts"}, authoritative=False)
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
        return SettlementRecord(
            status=status,
            effect_id=fact[1],
            amount_usd=amount,
            evidence={"quorum": count, "required": self.quorum, "sources": [s.name for s in self.sources]},
            authoritative=True,
            verified_request_hash=expected_hash,
        )
