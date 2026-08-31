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
    ExecutionPermit,
    ExecutionRequest,
    GrantStatus,
    Intent,
    PermitAlgorithm,
    RiskSnapshot,
    SignedExecutionPermit,
)


def _dt(value: str | None) -> datetime | None:
    if not value:
        return None
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 string")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamps must include a timezone offset")
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
    return AuthorityDecision(
        posture=AuthorityPosture(data["posture"]),
        primitive=AuthorityPrimitive(data["primitive"]),
        reason_codes=tuple(data.get("reason_codes", [])),
        source=data.get("source", "external"),
    )


def parse_attestation(data: dict[str, Any]) -> Attestation:
    return Attestation(
        kind=AttestationKind(data["kind"]),
        key_id=data["key_id"],
        algorithm=AttestationAlgorithm(data["algorithm"]),
        subject_hash=data["subject_hash"],
        intent_hash=data["intent_hash"],
        issued_at=_dt(data["issued_at"]),
        expires_at=_dt(data["expires_at"]),
        signature=data["signature"],
    )


def parse_intent(data: dict[str, Any]) -> Intent:
    return Intent(
        schema_version=data.get("schema_version", "0.3"),
        principal_id=data["principal_id"],
        intent_id=data["intent_id"],
        actor_id=data["actor_id"],
        grant_id=data["grant_id"],
        grant_version=_int(data["grant_version"], "grant_version"),
        primitive=EconomicPrimitive(data["primitive"]),
        venue=data["venue"],
        created_at=_dt(data["created_at"]),
        expires_at=_dt(data["expires_at"]),
        payload=data.get("payload", {}),
        metadata=data.get("metadata", {}),
    )


def parse_grant(data: dict[str, Any]) -> CapabilityGrant:
    raw_limits = data.get("limits", {})
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
    return RiskSnapshot(
        observed_at=_dt(data["observed_at"]),
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


def parse_execution_request(data: dict[str, Any]) -> ExecutionRequest:
    return ExecutionRequest(
        principal_id=data["principal_id"],
        intent_id=data["intent_id"],
        primitive=EconomicPrimitive(data["primitive"]),
        venue=data["venue"],
        payload=data.get("payload", {}),
    )


def parse_signed_permit(data: dict[str, Any]) -> SignedExecutionPermit:
    body = data["permit"]
    return SignedExecutionPermit(
        permit=ExecutionPermit(
            permit_id=body["permit_id"],
            principal_id=body["principal_id"],
            intent_id=body["intent_id"],
            grant_id=body["grant_id"],
            grant_version=_int(body["grant_version"], "grant_version"),
            grant_hash=body["grant_hash"],
            request_hash=body["request_hash"],
            authority_attestation_hash=body["authority_attestation_hash"],
            risk_attestation_hash=body["risk_attestation_hash"],
            grant_epoch=_int(body["grant_epoch"], "grant_epoch"),
            fence_token=_int(body["fence_token"], "fence_token"),
            max_amount_usd=_dec(body.get("max_amount_usd")),
            issued_at=_dt(body["issued_at"]),
            expires_at=_dt(body["expires_at"]),
        ),
        signer_id=data["signer_id"],
        algorithm=PermitAlgorithm(data["algorithm"]),
        signature=data["signature"],
    )
