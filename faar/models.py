from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from typing import Any, Mapping


def _aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _deep_freeze(value: Any) -> Any:
    """Copy untrusted nested data into an immutable JSON-like structure.

    Frozen dataclasses are only shallowly immutable. Without this copy/freeze, a
    caller retaining the original dict could mutate an already-authorized intent
    between hashing/gating and adapter submission.
    """
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("mapping keys must be strings")
            out[key] = _deep_freeze(item)
        return MappingProxyType(out)
    if isinstance(value, (list, tuple)):
        return tuple(_deep_freeze(v) for v in value)
    if isinstance(value, (set, frozenset)):
        return frozenset(_deep_freeze(v) for v in value)
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("non-finite Decimals are not allowed in canonical data")
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("non-finite floats are not allowed in canonical data")
        return value
    if value is None or isinstance(value, (str, int, bool, datetime, StrEnum)):
        return value
    raise ValueError(f"unsupported canonical value type: {type(value).__name__}")


def _require_int(name: str, value: int, *, minimum: int | None = None) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")


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
    FINALIZED = "FINALIZED"
    CONTRADICTORY = "CONTRADICTORY"


class AttestationKind(StrEnum):
    AUTHORITY = "AUTHORITY"
    RISK = "RISK"
    TASK = "TASK"


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
        for name in (
            "max_slippage_bps",
            "max_price_impact_bps",
            "max_market_data_age_seconds",
            "max_risk_snapshot_age_seconds",
            "max_intent_ttl_seconds",
            "max_clock_skew_seconds",
            "max_actions_per_window",
        ):
            value = getattr(self, name)
            if value is not None:
                _require_int(name, value, minimum=0)
        if self.action_window_seconds is not None:
            _require_int("action_window_seconds", self.action_window_seconds, minimum=1)
        if self.max_actions_per_window is not None and self.action_window_seconds is None:
            raise ValueError("action_window_seconds is required when max_actions_per_window is set")
        _require_int("max_submission_attempts", self.max_submission_attempts, minimum=1)


@dataclass(frozen=True)
class CapabilityGrant:
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
        if not self.grant_id or not self.actor_id:
            raise ValueError("grant_id and actor_id are required")
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
    schema_version: str = "0.2"

    def __post_init__(self) -> None:
        object.__setattr__(self, "primitive", EconomicPrimitive(self.primitive))
        object.__setattr__(self, "payload", _deep_freeze(self.payload))
        object.__setattr__(self, "metadata", _deep_freeze(self.metadata))
        if not self.intent_id or not self.actor_id or not self.grant_id or not self.venue:
            raise ValueError("intent identifiers and venue are required")
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

    intent_id: str
    primitive: EconomicPrimitive
    venue: str
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "primitive", EconomicPrimitive(self.primitive))
        object.__setattr__(self, "payload", _deep_freeze(self.payload))
        if not self.intent_id or not self.venue:
            raise ValueError("execution request identity and venue are required")

    @classmethod
    def from_intent(cls, intent: Intent) -> "ExecutionRequest":
        return cls(
            intent_id=intent.intent_id,
            primitive=intent.primitive,
            venue=intent.venue,
            payload=intent.payload,
        )


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
class Attestation:
    kind: AttestationKind
    key_id: str
    subject_hash: str
    intent_hash: str
    issued_at: datetime
    expires_at: datetime
    mac: str

    def __post_init__(self) -> None:
        if not self.key_id or not self.subject_hash or not self.intent_hash or not self.mac:
            raise ValueError("attestation fields cannot be empty")
        if not _aware(self.issued_at) or not _aware(self.expires_at):
            raise ValueError("attestation timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("attestation expires_at must be after issued_at")


@dataclass(frozen=True)
class SettlementRecord:
    status: SettlementStatus
    effect_id: str | None = None
    amount_usd: Decimal | None = None
    evidence: Mapping[str, Any] = field(default_factory=dict)
    authoritative: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", SettlementStatus(self.status))
        object.__setattr__(self, "evidence", _deep_freeze(self.evidence))
        _require_bool("authoritative", self.authoritative)
        if self.amount_usd is not None:
            if not isinstance(self.amount_usd, Decimal) or not self.amount_usd.is_finite():
                raise ValueError("settlement amount_usd must be finite Decimal or None")


@dataclass(frozen=True)
class ExecutionReceipt:
    effect_id: str
    status: SettlementStatus
    evidence: Mapping[str, Any] = field(default_factory=dict)
    amount_usd: Decimal | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", SettlementStatus(self.status))
        object.__setattr__(self, "evidence", _deep_freeze(self.evidence))
        if self.amount_usd is not None:
            if not isinstance(self.amount_usd, Decimal) or not self.amount_usd.is_finite():
                raise ValueError("execution amount_usd must be finite Decimal or None")
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
        if not self.task_id or not self.intent_id or not self.objective.strip():
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
