from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from .models import (
    Attestation,
    AttestationAlgorithm,
    AttestationKind,
    AuthorityDecision,
    AuthorityPosture,
    AuthorityPrimitive,
    CapabilityGrant,
    CapabilityLimits,
    EconomicPrimitive,
    GrantStatus,
    Intent,
    RiskSnapshot,
)


_INTENT_FIELDS = frozenset({
    "schema_version", "principal_id", "intent_id", "actor_id", "grant_id", "grant_version",
    "primitive", "venue", "created_at", "expires_at", "payload", "metadata",
})
_GRANT_FIELDS = frozenset({
    "schema_version", "principal_id", "grant_id", "version", "actor_id", "status",
    "allowed_primitives", "allowed_venues", "allowed_assets", "allowed_targets", "denied_targets",
    "valid_until", "limits",
})
_LIMIT_FIELDS = frozenset({
    "max_order_usd", "max_position_usd", "max_daily_turnover_usd", "max_daily_loss_usd",
    "max_slippage_bps", "max_price_impact_bps", "max_market_data_age_seconds",
    "max_risk_snapshot_age_seconds", "max_intent_ttl_seconds", "max_clock_skew_seconds",
    "max_actions_per_window", "action_window_seconds", "max_submission_attempts",
})
_RISK_FIELDS = frozenset({
    "observed_at", "state_version", "scope", "position_after_usd", "daily_turnover_after_usd",
    "daily_loss_usd", "market_data_age_seconds", "requested_slippage_bps", "price_impact_bps",
    "actions_in_window", "circuit_breaker_active", "data_complete", "source_count", "sources_agree",
})
_AUTHORITY_FIELDS = frozenset({"posture", "primitive", "reason_codes", "source"})
_ATTESTATION_FIELDS = frozenset({
    "kind", "key_id", "algorithm", "subject_hash", "intent_hash", "issued_at", "expires_at", "signature",
})


def _document(data: Any, name: str, allowed: frozenset[str]) -> dict[str, Any]:
    """Reject unknown keys so a misspelled limit cannot silently become 'unbounded'.

    Every optional limit defaults to "not enforced" when absent, which makes a
    typo in a grant document a security-relevant event rather than a cosmetic one.
    """
    if not isinstance(data, dict):
        raise ValueError(f"{name} document must be a JSON object")
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ValueError(f"{name} document has unknown fields: {unknown}")
    return data


def _dt(value: Any) -> datetime | None:
    # Only an absent/null value means "no timestamp". Falsy values such as "" or 0
    # must not silently turn a required timestamp (or a grant expiry) into None.
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 string")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamps must include a timezone offset")
    return parsed


def _required_dt(value: Any, name: str) -> datetime:
    parsed = _dt(value)
    if parsed is None:
        raise ValueError(f"{name} is required")
    return parsed


def _strict_bool(value: Any, name: str) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be a JSON boolean")
    return value


def _int(value: Any, name: str, *, optional: bool = False) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be a JSON integer")
    return value


def _dec(value: Any) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("decimal value cannot be boolean")
    try:
        out = Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise ValueError("invalid decimal value") from exc
    if not out.is_finite():
        raise ValueError("decimal value must be finite")
    return out


def parse_authority(data: dict[str, Any]) -> AuthorityDecision:
    data = _document(data, "authority decision", _AUTHORITY_FIELDS)
    reason_codes = data.get("reason_codes", [])
    if not isinstance(reason_codes, list) or not all(isinstance(r, str) for r in reason_codes):
        raise ValueError("reason_codes must be a list of strings")
    return AuthorityDecision(
        posture=AuthorityPosture(data["posture"]),
        primitive=AuthorityPrimitive(data["primitive"]),
        reason_codes=tuple(reason_codes),
        source=data.get("source", "external"),
    )


def parse_attestation(data: dict[str, Any]) -> Attestation:
    data = _document(data, "attestation", _ATTESTATION_FIELDS)
    return Attestation(
        kind=AttestationKind(data["kind"]),
        key_id=data["key_id"],
        algorithm=AttestationAlgorithm(data["algorithm"]),
        subject_hash=data["subject_hash"],
        intent_hash=data["intent_hash"],
        issued_at=_required_dt(data["issued_at"], "issued_at"),
        expires_at=_required_dt(data["expires_at"], "expires_at"),
        signature=data["signature"],
    )


def parse_intent(data: dict[str, Any]) -> Intent:
    data = _document(data, "intent", _INTENT_FIELDS)
    payload = data.get("payload", {})
    metadata = data.get("metadata", {})
    if not isinstance(payload, dict) or not isinstance(metadata, dict):
        raise ValueError("intent payload and metadata must be JSON objects")
    return Intent(
        schema_version=data.get("schema_version", "0.3"),
        principal_id=data["principal_id"],
        intent_id=data["intent_id"],
        actor_id=data["actor_id"],
        grant_id=data["grant_id"],
        grant_version=_int(data["grant_version"], "grant_version"),
        primitive=EconomicPrimitive(data["primitive"]),
        venue=data["venue"],
        created_at=_required_dt(data["created_at"], "created_at"),
        expires_at=_required_dt(data["expires_at"], "expires_at"),
        payload=payload,
        metadata=metadata,
    )


def parse_grant(data: dict[str, Any]) -> CapabilityGrant:
    data = _document(data, "capability grant", _GRANT_FIELDS)
    raw_limits = _document(data.get("limits", {}), "capability grant limits", _LIMIT_FIELDS)
    limits = CapabilityLimits(
        max_order_usd=_dec(raw_limits.get("max_order_usd")),
        max_position_usd=_dec(raw_limits.get("max_position_usd")),
        max_daily_turnover_usd=_dec(raw_limits.get("max_daily_turnover_usd")),
        max_daily_loss_usd=_dec(raw_limits.get("max_daily_loss_usd")),
        max_slippage_bps=_int(raw_limits.get("max_slippage_bps"), "max_slippage_bps", optional=True),
        max_price_impact_bps=_int(raw_limits.get("max_price_impact_bps"), "max_price_impact_bps", optional=True),
        max_market_data_age_seconds=_int(raw_limits.get("max_market_data_age_seconds"), "max_market_data_age_seconds", optional=True),
        max_risk_snapshot_age_seconds=_int(raw_limits.get("max_risk_snapshot_age_seconds"), "max_risk_snapshot_age_seconds", optional=True),
        max_intent_ttl_seconds=_int(raw_limits.get("max_intent_ttl_seconds"), "max_intent_ttl_seconds", optional=True),
        max_clock_skew_seconds=_int(raw_limits.get("max_clock_skew_seconds", 5), "max_clock_skew_seconds"),
        max_actions_per_window=_int(raw_limits.get("max_actions_per_window"), "max_actions_per_window", optional=True),
        action_window_seconds=_int(raw_limits.get("action_window_seconds"), "action_window_seconds", optional=True),
        max_submission_attempts=_int(raw_limits.get("max_submission_attempts", 2), "max_submission_attempts"),
    )
    return CapabilityGrant(
        principal_id=data["principal_id"],
        grant_id=data["grant_id"],
        version=_int(data["version"], "grant version"),
        actor_id=data["actor_id"],
        status=GrantStatus(data["status"]),
        allowed_primitives=frozenset(EconomicPrimitive(v) for v in data["allowed_primitives"]),
        allowed_venues=frozenset(data["allowed_venues"]),
        allowed_assets=frozenset(data.get("allowed_assets", [])),
        allowed_targets=frozenset(data.get("allowed_targets", [])),
        denied_targets=frozenset(data.get("denied_targets", [])),
        valid_until=_dt(data.get("valid_until")),
        limits=limits,
    )


def parse_risk(data: dict[str, Any]) -> RiskSnapshot:
    data = _document(data, "risk snapshot", _RISK_FIELDS)
    return RiskSnapshot(
        observed_at=_required_dt(data["observed_at"], "observed_at"),
        state_version=_int(data.get("state_version", 1), "state_version"),
        scope=str(data.get("scope", "portfolio")),
        position_after_usd=_dec(data.get("position_after_usd")),
        daily_turnover_after_usd=_dec(data.get("daily_turnover_after_usd")),
        daily_loss_usd=_dec(data.get("daily_loss_usd")),
        market_data_age_seconds=_int(data.get("market_data_age_seconds"), "market_data_age_seconds", optional=True),
        requested_slippage_bps=_int(data.get("requested_slippage_bps"), "requested_slippage_bps", optional=True),
        price_impact_bps=_int(data.get("price_impact_bps"), "price_impact_bps", optional=True),
        actions_in_window=_int(data.get("actions_in_window", 0), "actions_in_window"),
        circuit_breaker_active=_strict_bool(data.get("circuit_breaker_active", False), "circuit_breaker_active"),
        data_complete=_strict_bool(data.get("data_complete", True), "data_complete"),
        source_count=_int(data.get("source_count", 1), "source_count"),
        sources_agree=_strict_bool(data.get("sources_agree", True), "sources_agree"),
    )
