from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from typing import Any, Mapping

from .canonical import canonical_json, parse_bounded_decimal


def _aware(value: datetime) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None


MAX_CANONICAL_DEPTH = 24
MAX_CANONICAL_CONTAINER_ITEMS = 256
MAX_CANONICAL_STRING_CHARS = 8192
MAX_CANONICAL_INT_BITS = 256

# Identifier bounds mirror schemas/*.schema.json. Identifiers are replicated into
# primary keys, permits, evidence rows and adapter idempotency keys, so they are
# bounded here as well as at the JSON boundary. A durable economic intent id also
# has a minimum length so trivially enumerable ids cannot be squatted.
MAX_IDENTIFIER_CHARS = 128
MIN_INTENT_ID_CHARS = 16
MAX_SAFE_INT = 2**63 - 1
SUPPORTED_INTENT_SCHEMA_VERSIONS = frozenset({"0.3"})


def _require_identifier(name: str, value: object, *, minimum: int = 1) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    if not (minimum <= len(value) <= MAX_IDENTIFIER_CHARS):
        raise ValueError(f"{name} must be between {minimum} and {MAX_IDENTIFIER_CHARS} characters")


def _require_mapping(name: str, value: object) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be a JSON object")


# Total nodes one untrusted document may expand to. Per-container and depth
# bounds alone still let a DAG (one child referenced from every key) materialise
# millions of nodes when copied; the shared budget makes the copy linear in what
# the caller may legitimately send.
MAX_CANONICAL_TOTAL_NODES = 10_000
# Total UTF-8 bytes of string content (keys and values) one frozen structure may
# carry. Node and string-length bounds alone admitted ~160 MB documents that were
# canonicalised a dozen times and stored verbatim before any gate ran.
MAX_CANONICAL_TOTAL_BYTES = 65_536
# Upper bound on the canonical JSON size of an evidence payload accepted from a
# settlement source or adapter and copied into the evidence chain.
MAX_EVIDENCE_BYTES = 65_536


def _deep_freeze(value: Any, _depth: int = 0, _budget: list[int] | None = None) -> Any:
    """Copy untrusted nested data into a bounded immutable JSON-like structure.

    Frozen dataclasses are only shallowly immutable. The explicit depth/container/
    scalar bounds and the total node budget also stop model, adapter, or verifier
    data from turning evidence handling and canonical hashing into a trivial
    memory/recursion denial of service.
    """
    if _budget is None:
        _budget = [MAX_CANONICAL_TOTAL_NODES, MAX_CANONICAL_TOTAL_BYTES]
    _budget[0] -= 1
    if _budget[0] < 0:
        raise ValueError("canonical data exceeds maximum total node count")
    if _depth > MAX_CANONICAL_DEPTH:
        raise ValueError("canonical data exceeds maximum nesting depth")
    if isinstance(value, Mapping):
        if len(value) > MAX_CANONICAL_CONTAINER_ITEMS:
            raise ValueError("canonical mapping exceeds maximum item count")
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("mapping keys must be strings")
            if len(key) > MAX_CANONICAL_STRING_CHARS:
                raise ValueError("canonical mapping key is too long")
            _budget[1] -= len(key.encode("utf-8"))
            if _budget[1] < 0:
                raise ValueError("canonical data exceeds maximum total size")
            out[key] = _deep_freeze(item, _depth + 1, _budget)
        return MappingProxyType(out)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_CANONICAL_CONTAINER_ITEMS:
            raise ValueError("canonical sequence exceeds maximum item count")
        return tuple(_deep_freeze(v, _depth + 1, _budget) for v in value)
    if isinstance(value, (set, frozenset)):
        if len(value) > MAX_CANONICAL_CONTAINER_ITEMS:
            raise ValueError("canonical set exceeds maximum item count")
        return frozenset(_deep_freeze(v, _depth + 1, _budget) for v in value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("non-finite Decimals are not allowed in canonical data")
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("non-finite floats are not allowed in canonical data")
        return value
    if isinstance(value, str):
        if len(value) > MAX_CANONICAL_STRING_CHARS:
            raise ValueError("canonical string is too long")
        _budget[1] -= len(value.encode("utf-8"))
        if _budget[1] < 0:
            raise ValueError("canonical data exceeds maximum total size")
        return value
    if isinstance(value, datetime):
        if not _aware(value):
            raise ValueError("naive datetimes are not allowed in canonical data")
        return value
    if isinstance(value, bool) or value is None or isinstance(value, StrEnum):
        return value
    if isinstance(value, int):
        if value.bit_length() > MAX_CANONICAL_INT_BITS:
            raise ValueError("canonical integer exceeds maximum bit length")
        return value
    raise ValueError(f"unsupported canonical value type: {type(value).__name__}")


# Upper bound for every time-valued limit (one leap year) and, separately, for a
# clock-skew allowance: a skew of hours would disable the future-dated checks and
# make every permit window unclosable, so it is capped at one hour.
MAX_LIMIT_SECONDS = 366 * 86_400
MAX_CLOCK_SKEW_SECONDS = 3_600


def _require_int(name: str, value: int, *, minimum: int | None = None, maximum: int = MAX_SAFE_INT) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    if value > maximum:
        raise ValueError(f"{name} must be <= {maximum}")


def _require_bool(name: str, value: bool) -> None:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")


def _finite_nonnegative_decimal(name: str, value: Decimal | None) -> None:
    if value is None:
        return
    if not value.is_finite():
        raise ValueError(f"{name} must be finite")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


class AuthorityPosture(StrEnum):
    ADVISE = "ADVISE"
    EXECUTE = "EXECUTE"
    DEFER = "DEFER"
    STOP = "STOP"


class AuthorityPrimitive(StrEnum):
    EXECUTE_ACTION = "EXECUTE_ACTION"
    GIVE_FACT = "GIVE_FACT"
    GIVE_RECOMMENDATION = "GIVE_RECOMMENDATION"
    ASK_CLARIFYING_QUESTION = "ASK_CLARIFYING_QUESTION"
    STATE_BLOCKER = "STATE_BLOCKER"
    RECOMMEND_NEAREST_SAFE_ALTERNATIVE = "RECOMMEND_NEAREST_SAFE_ALTERNATIVE"
    COMPARE_OPTIONS = "COMPARE_OPTIONS"
    MAKE_PLAN = "MAKE_PLAN"
    REFUSE_AND_REDIRECT = "REFUSE_AND_REDIRECT"
    SUMMARIZE = "SUMMARIZE"


class EconomicPrimitive(StrEnum):
    PAY = "PAY"
    SWAP = "SWAP"
    BUY = "BUY"
    SELL = "SELL"
    PLACE_ORDER = "PLACE_ORDER"
    CANCEL_ORDER = "CANCEL_ORDER"


MONETARY_PRIMITIVES = frozenset({
    EconomicPrimitive.PAY,
    EconomicPrimitive.SWAP,
    EconomicPrimitive.BUY,
    EconomicPrimitive.SELL,
    EconomicPrimitive.PLACE_ORDER,
})
TARGET_BOUND_PRIMITIVES = frozenset({EconomicPrimitive.PAY, EconomicPrimitive.SWAP})


class GrantStatus(StrEnum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    REVOKED = "REVOKED"


class Verdict(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DEFER = "DEFER"
    STOP = "STOP"


class IntentState(StrEnum):
    PROPOSED = "PROPOSED"
    DENIED = "DENIED"
    DEFERRED = "DEFERRED"
    STOPPED = "STOPPED"
    AUTHORIZED = "AUTHORIZED"
    RESERVED = "RESERVED"
    SUBMITTED = "SUBMITTED"
    UNKNOWN = "UNKNOWN"
    RECONCILING = "RECONCILING"
    CONFIRMED = "CONFIRMED"
    FINALIZED = "FINALIZED"
    FAILED_SAFE = "FAILED_SAFE"


class SettlementStatus(StrEnum):
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"
    CONFIRMED = "CONFIRMED"
    # An order that exists at the venue, has filled for `amount_usd` so far and can
    # still fill further. Non-terminal: the runtime reconciles again later and never
    # submits a second attempt for the remainder.
    PARTIALLY_FILLED = "PARTIALLY_FILLED"
    FINALIZED = "FINALIZED"
    # Terminal at the venue: no further fill is possible. `amount_usd` is the amount
    # filled before cancellation (0/None for an unfilled order).
    CANCELLED = "CANCELLED"
    CONTRADICTORY = "CONTRADICTORY"


class AttestationKind(StrEnum):
    AUTHORITY = "AUTHORITY"
    RISK = "RISK"
    TASK = "TASK"


class AttestationAlgorithm(StrEnum):
    HMAC_SHA256 = "HMAC_SHA256"
    ED25519 = "ED25519"


class PermitAlgorithm(StrEnum):
    HMAC_SHA256 = "HMAC_SHA256"
    ED25519 = "ED25519"


class OutcomeVerdict(StrEnum):
    MET = "MET"
    NOT_MET = "NOT_MET"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class AuthorityDecision:
    posture: AuthorityPosture
    primitive: AuthorityPrimitive
    reason_codes: tuple[str, ...] = ()
    source: str = "external"


@dataclass(frozen=True)
class CapabilityLimits:
    max_order_usd: Decimal | None = None
    max_position_usd: Decimal | None = None
    max_daily_turnover_usd: Decimal | None = None
    max_daily_loss_usd: Decimal | None = None
    max_slippage_bps: int | None = None
    max_price_impact_bps: int | None = None
    max_market_data_age_seconds: int | None = None
    max_risk_snapshot_age_seconds: int | None = None
    max_intent_ttl_seconds: int | None = None
    max_clock_skew_seconds: int = 5
    max_actions_per_window: int | None = None
    action_window_seconds: int | None = None
    max_submission_attempts: int = 2

    def __post_init__(self) -> None:
        for name in (
            "max_order_usd",
            "max_position_usd",
            "max_daily_turnover_usd",
            "max_daily_loss_usd",
        ):
            value = getattr(self, name)
            if value is not None and not isinstance(value, Decimal):
                raise ValueError(f"{name} must be Decimal or None")
            _finite_nonnegative_decimal(name, value)
        for name in ("max_slippage_bps", "max_price_impact_bps", "max_actions_per_window"):
            value = getattr(self, name)
            if value is not None:
                _require_int(name, value, minimum=0)
        # Time-valued limits are bounded so the gates can always form a timedelta
        # from them; an absurd value must fail at the document boundary, not raise
        # OverflowError out of process() after the intent is registered.
        for name in ("max_market_data_age_seconds", "max_risk_snapshot_age_seconds", "max_intent_ttl_seconds"):
            value = getattr(self, name)
            if value is not None:
                _require_int(name, value, minimum=0, maximum=MAX_LIMIT_SECONDS)
        _require_int("max_clock_skew_seconds", self.max_clock_skew_seconds, minimum=0, maximum=MAX_CLOCK_SKEW_SECONDS)
        if self.action_window_seconds is not None:
            _require_int("action_window_seconds", self.action_window_seconds, minimum=1, maximum=MAX_LIMIT_SECONDS)
        if self.max_actions_per_window is not None and self.action_window_seconds is None:
            raise ValueError("action_window_seconds is required when max_actions_per_window is set")
        _require_int("max_submission_attempts", self.max_submission_attempts, minimum=1)


@dataclass(frozen=True)
class CapabilityGrant:
    principal_id: str
    grant_id: str
    version: int
    actor_id: str
    status: GrantStatus
    allowed_primitives: frozenset[EconomicPrimitive]
    allowed_venues: frozenset[str]
    allowed_assets: frozenset[str] = frozenset()
    allowed_targets: frozenset[str] = frozenset()
    denied_targets: frozenset[str] = frozenset()
    valid_until: datetime | None = None
    limits: CapabilityLimits = field(default_factory=CapabilityLimits)

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", GrantStatus(self.status))
        object.__setattr__(self, "allowed_primitives", frozenset(EconomicPrimitive(v) for v in self.allowed_primitives))
        object.__setattr__(self, "allowed_venues", frozenset(str(v) for v in self.allowed_venues))
        object.__setattr__(self, "allowed_assets", frozenset(str(v) for v in self.allowed_assets))
        object.__setattr__(self, "allowed_targets", frozenset(str(v) for v in self.allowed_targets))
        object.__setattr__(self, "denied_targets", frozenset(str(v) for v in self.denied_targets))
        for name in ("principal_id", "grant_id", "actor_id"):
            _require_identifier(name, getattr(self, name))
        _require_int("grant version", self.version, minimum=1)
        if not self.allowed_primitives:
            raise ValueError("allowed_primitives cannot be empty")
        if not self.allowed_venues:
            raise ValueError("allowed_venues cannot be empty")

        # A financial capability must be bounded by construction. A missing limit
        # is not interpreted as "infinite" for money-moving primitives. Every
        # monetary grant gets a per-action ceiling, an aggregate daily ceiling,
        # explicit asset scope, and every grant gets a velocity ceiling. PAY/SWAP
        # additionally require a target allowlist because their execution payload
        # contains a direct counterparty/router target.
        monetary = self.allowed_primitives.intersection(MONETARY_PRIMITIVES)
        if monetary:
            if self.limits.max_order_usd is None or self.limits.max_order_usd <= 0:
                raise ValueError("monetary grants require max_order_usd > 0")
            if self.limits.max_daily_turnover_usd is None or self.limits.max_daily_turnover_usd <= 0:
                raise ValueError("monetary grants require max_daily_turnover_usd > 0")
            if not self.allowed_assets:
                raise ValueError("monetary grants require a non-empty allowed_assets scope")
        if self.allowed_primitives.intersection(TARGET_BOUND_PRIMITIVES) and not self.allowed_targets:
            raise ValueError("PAY/SWAP grants require a non-empty allowed_targets scope")
        if self.limits.max_actions_per_window is None or self.limits.action_window_seconds is None:
            raise ValueError("all grants require max_actions_per_window and action_window_seconds")
        if self.limits.max_actions_per_window <= 0:
            raise ValueError("max_actions_per_window must be > 0")

        if self.valid_until is not None and not _aware(self.valid_until):
            raise ValueError("grant valid_until must be timezone-aware")
        overlap = self.allowed_targets.intersection(self.denied_targets)
        if overlap:
            raise ValueError(f"targets cannot be both allowed and denied: {sorted(overlap)}")


@dataclass(frozen=True)
class Intent:
    principal_id: str
    intent_id: str
    actor_id: str
    grant_id: str
    grant_version: int
    primitive: EconomicPrimitive
    venue: str
    created_at: datetime
    expires_at: datetime
    payload: Mapping[str, Any]
    metadata: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = "0.3"

    def __post_init__(self) -> None:
        object.__setattr__(self, "primitive", EconomicPrimitive(self.primitive))
        # A payload that is not a JSON object must fail at construction: the gates
        # index it by key and a list/str/None would surface as an exception inside
        # the runtime instead of a verdict.
        _require_mapping("intent payload", self.payload)
        _require_mapping("intent metadata", self.metadata)
        object.__setattr__(self, "payload", _deep_freeze(self.payload))
        object.__setattr__(self, "metadata", _deep_freeze(self.metadata))
        for name in ("principal_id", "actor_id", "grant_id", "venue"):
            _require_identifier(name, getattr(self, name))
        _require_identifier("intent_id", self.intent_id, minimum=MIN_INTENT_ID_CHARS)
        if self.schema_version not in SUPPORTED_INTENT_SCHEMA_VERSIONS:
            raise ValueError(f"unsupported intent schema_version {self.schema_version!r}")
        _require_int("grant_version", self.grant_version, minimum=1)
        if not _aware(self.created_at) or not _aware(self.expires_at):
            raise ValueError("intent timestamps must be timezone-aware")
        if self.expires_at <= self.created_at:
            raise ValueError("intent expires_at must be after created_at")


@dataclass(frozen=True)
class ExecutionRequest:
    """Minimal post-authorization object exposed to an execution adapter.

    Deliberately excludes model metadata, authority/risk objects, and grant contents.
    The adapter gets only the canonical economic primitive that survived FAAR's gates.
    """

    principal_id: str
    intent_id: str
    primitive: EconomicPrimitive
    venue: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "primitive", EconomicPrimitive(self.primitive))
        _require_mapping("execution request payload", self.payload)
        object.__setattr__(self, "payload", _deep_freeze(self.payload))
        _require_identifier("principal_id", self.principal_id)
        _require_identifier("intent_id", self.intent_id, minimum=MIN_INTENT_ID_CHARS)
        _require_identifier("venue", self.venue)

    @classmethod
    def from_intent(cls, intent: Intent) -> "ExecutionRequest":
        return cls(
            principal_id=intent.principal_id,
            intent_id=intent.intent_id,
            primitive=intent.primitive,
            venue=intent.venue,
            payload=intent.payload,
        )


@dataclass(frozen=True)
class ExecutionPermit:
    """Signer-issued, narrowly scoped authority for one sanitized execution request.

    A permit is not a generic wallet credential. It binds one principal, intent,
    request hash, immutable grant envelope, runtime grant epoch, amount ceiling,
    and short expiry. A venue/gateway that accepts permits can reject any request
    outside this exact envelope without trusting the calling agent process.
    """

    permit_id: str
    principal_id: str
    intent_id: str
    grant_id: str
    grant_version: int
    grant_hash: str
    request_hash: str
    authority_attestation_hash: str
    risk_attestation_hash: str
    grant_epoch: int
    fence_token: int
    max_amount_usd: Decimal | None
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for name in ("permit_id", "principal_id", "grant_id"):
            _require_identifier(name, getattr(self, name))
        _require_identifier("intent_id", self.intent_id, minimum=MIN_INTENT_ID_CHARS)
        for name in ("grant_hash", "request_hash", "authority_attestation_hash", "risk_attestation_hash"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError(f"permit {name} is required")
        _require_int("grant_version", self.grant_version, minimum=1)
        _require_int("grant_epoch", self.grant_epoch, minimum=1)
        _require_int("fence_token", self.fence_token, minimum=1)
        if self.max_amount_usd is not None:
            bounded = parse_bounded_decimal(self.max_amount_usd) if isinstance(self.max_amount_usd, Decimal) else None
            if bounded is None or bounded <= 0:
                raise ValueError("permit max_amount_usd must be a positive, canonically bounded Decimal or None")
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("permit timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("permit expires_at must be after issued_at")


@dataclass(frozen=True)
class SignedExecutionPermit:
    permit: ExecutionPermit
    signer_id: str
    algorithm: PermitAlgorithm
    signature: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "algorithm", PermitAlgorithm(self.algorithm))
        if not isinstance(self.permit, ExecutionPermit):
            raise ValueError("signed permit body must be an ExecutionPermit")
        _require_identifier("signer_id", self.signer_id)
        if not isinstance(self.signature, str) or not self.signature:
            raise ValueError("signed permit signature is required")


@dataclass(frozen=True)
class RiskSnapshot:
    observed_at: datetime
    state_version: int = 1
    scope: str = "portfolio"
    position_after_usd: Decimal | None = None
    daily_turnover_after_usd: Decimal | None = None
    daily_loss_usd: Decimal | None = None
    market_data_age_seconds: int | None = None
    requested_slippage_bps: int | None = None
    price_impact_bps: int | None = None
    actions_in_window: int = 0
    circuit_breaker_active: bool = False
    data_complete: bool = True
    source_count: int = 1
    sources_agree: bool = True

    def __post_init__(self) -> None:
        if not _aware(self.observed_at):
            raise ValueError("risk observed_at must be timezone-aware")
        _require_int("risk state_version", self.state_version, minimum=1)
        if not self.scope:
            raise ValueError("risk scope is required")
        for name in ("position_after_usd", "daily_turnover_after_usd", "daily_loss_usd"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, Decimal):
                raise ValueError(f"{name} must be Decimal or None")
        for name in ("market_data_age_seconds", "requested_slippage_bps", "price_impact_bps"):
            value = getattr(self, name)
            if value is not None:
                _require_int(name, value)
        _require_int("actions_in_window", self.actions_in_window, minimum=0)
        _require_int("source_count", self.source_count, minimum=0)
        for name in ("circuit_breaker_active", "data_complete", "sources_agree"):
            _require_bool(name, getattr(self, name))


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason_codes: tuple[str, ...]
    layer: str

    @property
    def allowed(self) -> bool:
        return self.verdict == Verdict.ALLOW


@dataclass(frozen=True)
class KeyValidity:
    """Lifecycle window of a verification key (attestation or permit signer).

    An artifact is accepted only if it was issued inside the key's window and the
    key is not revoked at verification time. Overlapping windows across two key
    ids give a rotation period without ever accepting an unknown signer; an
    artifact issued within the window stays verifiable for its own lifetime after
    `not_after` so rotation never invalidates authority already granted.
    """

    not_before: datetime | None = None
    not_after: datetime | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        _require_bool("revoked", self.revoked)
        for name in ("not_before", "not_after"):
            value = getattr(self, name)
            if value is not None and not _aware(value):
                raise ValueError(f"{name} must be a timezone-aware datetime or None")
        if self.not_before is not None and self.not_after is not None and self.not_after <= self.not_before:
            raise ValueError("not_after must be after not_before")

    def rejection(self, issued_at: datetime) -> str | None:
        if self.revoked:
            return "KEY_REVOKED"
        if self.not_before is not None and issued_at < self.not_before:
            return "KEY_NOT_YET_VALID"
        if self.not_after is not None and issued_at > self.not_after:
            return "KEY_EXPIRED"
        return None


@dataclass(frozen=True)
class Attestation:
    kind: AttestationKind
    key_id: str
    algorithm: AttestationAlgorithm
    subject_hash: str
    intent_hash: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "algorithm", AttestationAlgorithm(self.algorithm))
        object.__setattr__(self, "kind", AttestationKind(self.kind))
        _require_identifier("key_id", self.key_id)
        for name in ("subject_hash", "intent_hash", "signature"):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ValueError("attestation fields cannot be empty")
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("attestation timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("attestation expires_at must be after issued_at")


def _bounded_amount(name: str, value: object) -> Decimal | None:
    """A settlement or receipt amount: a finite Decimal inside the canonical bounds,
    stored as a plain canonical Decimal (a subclass with overridden formatting is
    not carried into evidence)."""
    if value is None:
        return None
    if not isinstance(value, Decimal) or not value.is_finite():
        raise ValueError(f"{name} must be a finite Decimal or None")
    bounded = parse_bounded_decimal(value)
    if bounded is None:
        raise ValueError(f"{name} is outside the canonical amount bounds")
    return bounded


def _require_bounded_evidence(evidence: Mapping[str, Any]) -> None:
    """Evidence copied into the chain must canonicalize, UTF-8 encode, and stay small."""
    try:
        encoded = canonical_json(evidence).encode("utf-8")
    except (ValueError, TypeError, UnicodeEncodeError) as exc:
        raise ValueError(f"evidence is not canonical JSON: {type(exc).__name__}") from exc
    if len(encoded) > MAX_EVIDENCE_BYTES:
        raise ValueError("evidence exceeds the maximum canonical size")


@dataclass(frozen=True)
class SettlementRecord:
    status: SettlementStatus
    effect_id: str | None = None
    amount_usd: Decimal | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    authoritative: bool = False
    verified_request_hash: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", SettlementStatus(self.status))
        if self.effect_id is not None and (not isinstance(self.effect_id, str) or len(self.effect_id) > MAX_CANONICAL_STRING_CHARS):
            raise ValueError("settlement effect_id must be a bounded string or None")
        if self.verified_request_hash is not None and (
            not isinstance(self.verified_request_hash, str) or len(self.verified_request_hash) > MAX_CANONICAL_STRING_CHARS
        ):
            raise ValueError("verified_request_hash must be a bounded string or None")
        object.__setattr__(self, "evidence", _deep_freeze(self.evidence))
        _require_bounded_evidence(self.evidence)
        _require_bool("authoritative", self.authoritative)
        if self.authoritative and not self.verified_request_hash:
            raise ValueError("authoritative settlement records require verified_request_hash")
        object.__setattr__(self, "amount_usd", _bounded_amount("settlement amount_usd", self.amount_usd))


@dataclass(frozen=True)
class ExecutionReceipt:
    effect_id: str
    status: SettlementStatus
    evidence: Mapping[str, Any] = field(default_factory=dict)
    amount_usd: Decimal | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", SettlementStatus(self.status))
        object.__setattr__(self, "evidence", _deep_freeze(self.evidence))
        _require_bounded_evidence(self.evidence)
        object.__setattr__(self, "amount_usd", _bounded_amount("execution amount_usd", self.amount_usd))
        # effect_id validity is deliberately enforced by the runtime, not here.
        # Adapter output is a trust boundary and malformed output must become an
        # explicit STOP rather than an adapter-construction exception/UNKNOWN.


@dataclass(frozen=True)
class OutcomeCriterion:
    path: str
    op: str
    value: Any = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _deep_freeze(self.value))
        if not self.path:
            raise ValueError("outcome criterion path is required")
        if self.op not in {"present", "eq", "gte", "lte"}:
            raise ValueError("unsupported outcome criterion op")


@dataclass(frozen=True)
class TaskContract:
    task_id: str
    intent_id: str
    objective: str
    criteria: tuple[OutcomeCriterion, ...]
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "criteria", tuple(self.criteria))
        _require_identifier("task_id", self.task_id)
        _require_identifier("intent_id", self.intent_id, minimum=MIN_INTENT_ID_CHARS)
        if not isinstance(self.objective, str) or not self.objective.strip():
            raise ValueError("task_id, intent_id and objective are required")
        if not self.criteria:
            raise ValueError("task contract must define at least one success criterion")
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("task timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("task expires_at must be after issued_at")


@dataclass(frozen=True)
class OutcomeResult:
    verdict: OutcomeVerdict
    reason_codes: tuple[str, ...]
    evaluated: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "verdict", OutcomeVerdict(self.verdict))
        object.__setattr__(self, "reason_codes", tuple(self.reason_codes))
        object.__setattr__(self, "evaluated", _deep_freeze(self.evaluated))


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
