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

# Effect-id characters carried into aggregate (quorum) evidence per member.
_FACT_ID_CHARS = 512


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
    def _fact_view(fact: tuple[str, str | None, str | None]) -> list:
        """A fact as written into aggregate evidence: effect ids are truncated so a
        member cannot inflate the aggregate record past the evidence bounds."""
        status, effect_id, amount = fact
        return [status, None if effect_id is None else effect_id[:_FACT_ID_CHARS], amount]

    def _record(self, status: SettlementStatus, *, evidence: dict, compact: dict, **fields) -> SettlementRecord:
        """Build the aggregate record; if the merged evidence exceeds the record
        bounds (every member inside the bound, the sum outside it), fall back to
        the compact form so an honest quorum can never fail its own constructor."""
        try:
            return SettlementRecord(status, evidence=evidence, **fields)
        except ValueError:
            return SettlementRecord(status, evidence={**compact, "evidence_truncated": True}, **fields)

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
        counts: dict[tuple[str, str | None, str | None], int] = {}
        facts: list[tuple[str, str | None, str | None]] = []
        binding_mismatches = 0
        for source in self.sources:
            name = str(source.name)
            try:
                record = source.verify(request)
                # Everything derived from a source's answer happens inside the
                # per-source guard: a member that returns garbage instead of raising
                # must not wedge the quorum either (I-8: zero weight in either direction).
                if not isinstance(record, SettlementRecord):
                    raise TypeError(f"source returned {type(record).__name__}")
                fact = self._fact(record)
            except Exception as exc:
                errors[name] = type(exc).__name__
                record = SettlementRecord(
                    SettlementStatus.UNKNOWN, evidence={"verifier": name, "error": type(exc).__name__},
                    authoritative=False,
                )
                fact = self._fact(record)
            observations.append((name, record))
            facts.append(fact)
            if not record.authoritative:
                continue
            if record.verified_request_hash != expected_hash:
                binding_mismatches += 1
                continue
            counts[fact] = counts.get(fact, 0) + 1
        records = [record for _, record in observations]
        # Finality lag is not a contest. Independent sources cross the finality
        # threshold at different times; CONFIRMED and FINALIZED for the same effect
        # id and amount agree on *what* settled and differ only on *how final* it
        # is. Reached finality is not vetoed by a lagging member; otherwise the
        # weaker status carries the combined votes and the runtime reconciles again.
        agree_statuses: set[str] = set()
        if not binding_mismatches and len(counts) == 2:
            keys = list(counts)
            if {k[0] for k in keys} == {"CONFIRMED", "FINALIZED"} and len({(k[1], k[2]) for k in keys}) == 1:
                final = next(k for k in keys if k[0] == "FINALIZED")
                confirmed = next(k for k in keys if k[0] == "CONFIRMED")
                if counts[final] >= self.quorum:
                    counts = {final: counts[final]}
                else:
                    agree_statuses = {"CONFIRMED", "FINALIZED"}
                    counts = {confirmed: counts[final] + counts[confirmed]}
        fact_views = [self._fact_view(f) for f in facts]
        if binding_mismatches or len(counts) > 1:
            # Two distinct authoritative facts (a 2-2 split is the canonical case), or
            # an authoritative record bound to another request, is a contested
            # settlement: fail closed whether or not any fact reached quorum.
            kind = "request-binding-mismatch" if binding_mismatches and len(counts) <= 1 else "contested"
            return self._record(
                SettlementStatus.CONTRADICTORY,
                evidence={"quorum": kind, "required": self.quorum, "facts": fact_views, "binding_mismatches": binding_mismatches, "errors": errors},
                compact={"quorum": kind, "required": self.quorum, "binding_mismatches": binding_mismatches, "errors": errors},
                authoritative=True,
                verified_request_hash=expected_hash,
            )
        if not counts:
            return self._record(
                SettlementStatus.UNKNOWN,
                evidence={"quorum": "no-authoritative-facts", "errors": errors},
                compact={"quorum": "no-authoritative-facts"},
                authoritative=False,
            )
        ((fact, count),) = counts.items()
        if count < self.quorum:
            # One uncontested fact short of quorum (the other sources were unreachable
            # or non-authoritative) is insufficient evidence, not a contradiction. A
            # weak UNKNOWN keeps the intent retriable; CONTRADICTORY would terminally
            # STOP an intent whose effect exists on a single transient source error.
            return self._record(
                SettlementStatus.UNKNOWN,
                evidence={
                    "quorum": "quorum-not-reached", "votes": count, "required": self.quorum,
                    "fact": self._fact_view(fact), "facts": fact_views, "errors": errors,
                },
                compact={"quorum": "quorum-not-reached", "votes": count, "required": self.quorum, "fact": self._fact_view(fact)},
                authoritative=False,
            )
        status = SettlementStatus(fact[0])
        amount = Decimal(fact[2]) if fact[2] is not None else None
        # Carry the agreeing sources' evidence forward so definition-of-done
        # criteria that address venue evidence (fill quantities, assets) remain
        # evaluable behind a quorum. Identical evidence is merged at the top level;
        # per-source evidence is always available under `source_evidence`. The
        # runtime-owned standard fields (effect_id, amount_usd, status) still
        # override same-named evidence keys at outcome evaluation.
        agree_statuses = agree_statuses or {fact[0]}
        agreeing = [
            (name, record) for name, record in observations
            if record.authoritative and record.verified_request_hash == expected_hash
            and self._fact(record)[1:] == fact[1:] and self._fact(record)[0] in agree_statuses
        ]
        evidence: dict = {}
        if agreeing and len({canonical_hash(record.evidence) for _, record in agreeing}) == 1:
            evidence.update(dict(agreeing[0][1].evidence))
        summary = {
            "quorum": count,
            "required": self.quorum,
            "sources": [s.name for s in self.sources],
            "errors": errors,
        }
        evidence.update({**summary, "source_evidence": {name: dict(record.evidence) for name, record in agreeing}})
        # Members inside the evidence bound can still sum past it; the compact form
        # keeps every member's evidence hash so the aggregate stays auditable.
        compact = {**summary, "source_evidence_hashes": {name: canonical_hash(record.evidence) for name, record in agreeing}}
        return self._record(
            status,
            evidence=evidence,
            compact=compact,
            effect_id=fact[1],
            amount_usd=amount,
            authoritative=True,
            verified_request_hash=expected_hash,
        )
