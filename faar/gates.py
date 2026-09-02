from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal

from .canonical import parse_bounded_decimal
from .models import (
    AuthorityDecision,
    AuthorityPosture,
    AuthorityPrimitive,
    CapabilityGrant,
    Decision,
    EconomicPrimitive,
    Intent,
    MONETARY_PRIMITIVES,
    RiskSnapshot,
    Verdict,
)


def _decision(layer: str, reasons: list[str], *, stop: bool = False, defer: bool = False) -> Decision:
    if stop:
        verdict = Verdict.STOP
    elif reasons:
        verdict = Verdict.DEFER if defer else Verdict.DENY
    else:
        verdict = Verdict.ALLOW
    return Decision(verdict=verdict, reason_codes=tuple(reasons), layer=layer)


def evaluate_authority(authority: AuthorityDecision) -> Decision:
    if authority.posture == AuthorityPosture.STOP:
        return Decision(Verdict.STOP, ("AUTHORITY_STOP",) + authority.reason_codes, "authority")
    if authority.posture == AuthorityPosture.DEFER:
        return Decision(Verdict.DEFER, ("AUTHORITY_DEFER",) + authority.reason_codes, "authority")
    if authority.posture != AuthorityPosture.EXECUTE:
        return Decision(Verdict.DENY, ("AUTHORITY_POSTURE_NOT_EXECUTE",), "authority")
    if authority.primitive != AuthorityPrimitive.EXECUTE_ACTION:
        return Decision(Verdict.DENY, ("AUTHORITY_PRIMITIVE_NOT_EXECUTION",), "authority")
    return Decision(Verdict.ALLOW, (), "authority")


def _decimal(raw: object) -> Decimal | None:
    # Shared bounded parser: the same grammar and bounds are applied by usage
    # reservation, the permit signer, settlement integrity and reference venues.
    return parse_bounded_decimal(raw)


def _amount_usd(intent: Intent) -> Decimal | None:
    return _decimal(intent.payload.get("amount_usd", intent.payload.get("notional_usd")))


def _assets(intent: Intent) -> set[str]:
    fields = ("asset", "base_asset", "quote_asset", "from_asset", "to_asset")
    # Use presence, not truthiness: a falsy-but-present asset value (0, False)
    # must still be validated against the allowlist, not silently dropped.
    return {str(intent.payload[f]) for f in fields if intent.payload.get(f) not in (None, "")}


_RAW_EXECUTION_FIELDS = {
    "raw_calldata",
    "calldata",
    "raw_transaction",
    "signed_transaction",
    "private_key",
    "seed_phrase",
    "delegatecall",
    "unlimited_approval",
    "approval_amount_raw",
    "signing_payload",
}

# The model proposes a small, typed economic action. It does not get a generic
# dictionary that a future adapter may accidentally reinterpret as extra authority.
# Strategy/debug context belongs in Intent.metadata, which adapters must ignore.
_ALLOWED_PAYLOAD_FIELDS: dict[EconomicPrimitive, frozenset[str]] = {
    EconomicPrimitive.PAY: frozenset({"asset", "amount_usd", "target", "payment_reference"}),
    EconomicPrimitive.SWAP: frozenset({"from_asset", "to_asset", "amount_usd", "target"}),
    EconomicPrimitive.BUY: frozenset({
        "base_asset", "quote_asset", "amount_usd", "notional_usd", "target",
        "order_type", "limit_price", "time_in_force",
    }),
    EconomicPrimitive.SELL: frozenset({
        "base_asset", "quote_asset", "amount_usd", "notional_usd", "target",
        "order_type", "limit_price", "time_in_force",
    }),
    EconomicPrimitive.PLACE_ORDER: frozenset({
        "base_asset", "quote_asset", "amount_usd", "notional_usd", "target",
        "order_type", "limit_price", "time_in_force",
    }),
    EconomicPrimitive.CANCEL_ORDER: frozenset({"order_id", "target"}),
}


def _validate_intent_shape(intent: Intent) -> list[str]:
    reasons: list[str] = []
    payload = intent.payload
    if _RAW_EXECUTION_FIELDS.intersection(payload):
        reasons.append("UNSAFE_RAW_EXECUTION_FIELD")
    allowed = _ALLOWED_PAYLOAD_FIELDS[intent.primitive]
    unknown = sorted(set(payload) - allowed)
    if unknown:
        reasons.append("UNKNOWN_EXECUTION_FIELDS:" + ",".join(unknown))

    if intent.primitive == EconomicPrimitive.PAY:
        for field in ("asset", "amount_usd", "target"):
            if payload.get(field) in (None, ""):
                reasons.append(f"PAYLOAD_FIELD_REQUIRED:{field}")
    elif intent.primitive == EconomicPrimitive.SWAP:
        for field in ("from_asset", "to_asset", "amount_usd", "target"):
            if payload.get(field) in (None, ""):
                reasons.append(f"PAYLOAD_FIELD_REQUIRED:{field}")
        # Presence and normalised comparison, matching how the allowlist check
        # sees assets (str()), so 0/0 or 0/"0" cannot slip past as distinct.
        from_asset, to_asset = payload.get("from_asset"), payload.get("to_asset")
        if from_asset not in (None, "") and to_asset not in (None, "") and str(from_asset) == str(to_asset):
            reasons.append("SWAP_ASSETS_IDENTICAL")
    elif intent.primitive in {EconomicPrimitive.BUY, EconomicPrimitive.SELL, EconomicPrimitive.PLACE_ORDER}:
        for field in ("base_asset", "quote_asset"):
            if payload.get(field) in (None, ""):
                reasons.append(f"PAYLOAD_FIELD_REQUIRED:{field}")
        if payload.get("amount_usd") is None and payload.get("notional_usd") is None:
            reasons.append("PAYLOAD_FIELD_REQUIRED:notional_usd")
        # Exactly one economic amount may be authorized. Two fields would let the
        # ceiling be enforced on one while an adapter executes the other.
        if "amount_usd" in payload and "notional_usd" in payload:
            reasons.append("AMOUNT_FIELDS_AMBIGUOUS")
        # A present limit_price is the request's venue-side price/slippage bound.
        # Garbage here must not reach an adapter that could ignore or reinterpret it.
        if "limit_price" in payload:
            limit_price = _decimal(payload.get("limit_price"))
            if limit_price is None or limit_price <= 0:
                reasons.append("LIMIT_PRICE_INVALID")
    elif intent.primitive == EconomicPrimitive.CANCEL_ORDER:
        if payload.get("order_id") in (None, ""):
            reasons.append("PAYLOAD_FIELD_REQUIRED:order_id")
    return reasons


def evaluate_capability(intent: Intent, grant: CapabilityGrant, now: datetime) -> Decision:
    reasons: list[str] = _validate_intent_shape(intent)

    # `grant.status` is the provisioning-time initial runtime state and is part of
    # the immutable grant fingerprint. Current lifecycle state is maintained by the
    # trusted grant registry/store and checked by FAARRuntime. Re-checking this
    # frozen field here would make a PAUSED grant impossible to resume without
    # mutating its fingerprint.

    if intent.principal_id != grant.principal_id:
        reasons.append("PRINCIPAL_MISMATCH")
    if intent.actor_id != grant.actor_id:
        reasons.append("ACTOR_MISMATCH")
    if intent.grant_id != grant.grant_id:
        reasons.append("GRANT_ID_MISMATCH")
    if intent.grant_version != grant.version:
        reasons.append("GRANT_VERSION_MISMATCH")
    if intent.primitive not in grant.allowed_primitives:
        reasons.append("PRIMITIVE_NOT_ALLOWED")
    if intent.venue not in grant.allowed_venues:
        reasons.append("VENUE_NOT_ALLOWED")

    skew = timedelta(seconds=grant.limits.max_clock_skew_seconds)
    if intent.created_at > now + skew:
        reasons.append("INTENT_CREATED_IN_FUTURE")
    if now > intent.expires_at:
        reasons.append("INTENT_EXPIRED")
    ttl_seconds = (intent.expires_at - intent.created_at).total_seconds()
    if grant.limits.max_intent_ttl_seconds is not None and ttl_seconds > grant.limits.max_intent_ttl_seconds:
        reasons.append("INTENT_TTL_EXCEEDED")
    if grant.valid_until is not None and now > grant.valid_until:
        reasons.append("GRANT_EXPIRED")

    # `target` is the single authoritative counterparty/router key. Presence, not
    # truthiness: a falsy target (0, False) must still reach the denied_targets /
    # TARGET_REQUIRED checks.
    target = intent.payload.get("target")
    if target is not None:
        target = str(target)
        if target in grant.denied_targets:
            reasons.append("TARGET_DENIED")
        if grant.allowed_targets and target not in grant.allowed_targets:
            reasons.append("TARGET_NOT_ALLOWED")
    elif grant.allowed_targets:
        reasons.append("TARGET_REQUIRED")

    assets = _assets(intent)
    if grant.allowed_assets:
        unknown = sorted(assets - grant.allowed_assets)
        if unknown:
            reasons.append("ASSET_NOT_ALLOWED:" + ",".join(unknown))

    amount_raw = intent.payload.get("amount_usd", intent.payload.get("notional_usd"))
    amount = _amount_usd(intent)
    if amount_raw is not None and amount is None:
        reasons.append("AMOUNT_INVALID_OR_NONFINITE")
    elif amount is not None:
        if amount <= 0:
            reasons.append("AMOUNT_NOT_POSITIVE")
        if grant.limits.max_order_usd is not None and amount > grant.limits.max_order_usd:
            reasons.append("MAX_ORDER_USD_EXCEEDED")
    elif intent.primitive in MONETARY_PRIMITIVES:
        reasons.append("AMOUNT_REQUIRED")

    return _decision("capability", reasons)


def _risk_decimal_reason(name: str, value: Decimal | None) -> str | None:
    if value is None:
        return None
    if not value.is_finite():
        return f"{name}_NONFINITE"
    return None


def evaluate_risk(intent: Intent, grant: CapabilityGrant, risk: RiskSnapshot, now: datetime) -> Decision:
    if risk.circuit_breaker_active:
        return Decision(Verdict.STOP, ("CIRCUIT_BREAKER_ACTIVE",), "risk")
    if not risk.data_complete:
        return Decision(Verdict.DEFER, ("RISK_DATA_INCOMPLETE",), "risk")
    if risk.source_count < 1 or not risk.sources_agree:
        return Decision(Verdict.DEFER, ("RISK_SOURCES_CONTRADICTORY",), "risk")

    skew = timedelta(seconds=grant.limits.max_clock_skew_seconds)
    if risk.observed_at > now + skew:
        return Decision(Verdict.DEFER, ("RISK_SNAPSHOT_FROM_FUTURE",), "risk")
    if grant.limits.max_risk_snapshot_age_seconds is not None:
        age = (now - risk.observed_at).total_seconds()
        if age > grant.limits.max_risk_snapshot_age_seconds:
            return Decision(Verdict.DEFER, ("RISK_SNAPSHOT_STALE",), "risk")

    reasons: list[str] = []
    limits = grant.limits

    for name in ("position_after_usd", "daily_turnover_after_usd", "daily_loss_usd"):
        reason = _risk_decimal_reason(name.upper(), getattr(risk, name))
        if reason:
            reasons.append(reason)

    if limits.max_position_usd is not None:
        if risk.position_after_usd is None:
            reasons.append("POSITION_DATA_REQUIRED")
        elif risk.position_after_usd.is_finite() and abs(risk.position_after_usd) > limits.max_position_usd:
            reasons.append("MAX_POSITION_USD_EXCEEDED")

    if limits.max_daily_turnover_usd is not None:
        if risk.daily_turnover_after_usd is None:
            reasons.append("TURNOVER_DATA_REQUIRED")
        elif risk.daily_turnover_after_usd.is_finite() and risk.daily_turnover_after_usd > limits.max_daily_turnover_usd:
            reasons.append("MAX_DAILY_TURNOVER_USD_EXCEEDED")

    if limits.max_daily_loss_usd is not None:
        if risk.daily_loss_usd is None:
            reasons.append("LOSS_DATA_REQUIRED")
        elif risk.daily_loss_usd.is_finite() and risk.daily_loss_usd > limits.max_daily_loss_usd:
            reasons.append("MAX_DAILY_LOSS_USD_EXCEEDED")

    numeric_nonnegative = {
        "MARKET_DATA_AGE": risk.market_data_age_seconds,
        "SLIPPAGE": risk.requested_slippage_bps,
        "PRICE_IMPACT": risk.price_impact_bps,
        "ACTIONS_IN_WINDOW": risk.actions_in_window,
    }
    for label, value in numeric_nonnegative.items():
        if value is not None and value < 0:
            reasons.append(f"{label}_NEGATIVE")

    if limits.max_market_data_age_seconds is not None:
        if risk.market_data_age_seconds is None:
            reasons.append("MARKET_DATA_AGE_REQUIRED")
        elif risk.market_data_age_seconds >= 0 and risk.market_data_age_seconds > limits.max_market_data_age_seconds:
            reasons.append("MARKET_DATA_STALE")

    if limits.max_slippage_bps is not None:
        if risk.requested_slippage_bps is None:
            reasons.append("SLIPPAGE_DATA_REQUIRED")
        elif risk.requested_slippage_bps >= 0 and risk.requested_slippage_bps > limits.max_slippage_bps:
            reasons.append("MAX_SLIPPAGE_BPS_EXCEEDED")

    if limits.max_price_impact_bps is not None:
        if risk.price_impact_bps is None:
            reasons.append("PRICE_IMPACT_DATA_REQUIRED")
        elif risk.price_impact_bps >= 0 and risk.price_impact_bps > limits.max_price_impact_bps:
            reasons.append("MAX_PRICE_IMPACT_BPS_EXCEEDED")

    if limits.max_actions_per_window is not None:
        if risk.actions_in_window >= limits.max_actions_per_window:
            reasons.append("ACTION_VELOCITY_EXCEEDED")

    # A proven limit breach is a deterministic policy failure (DENY). Missing,
    # malformed or stale data is ambiguity and routes to DEFER. Both are terminal
    # and equally safe; the distinction keeps audit evidence machine-readable.
    breach = any(reason.endswith("_EXCEEDED") for reason in reasons)
    return _decision("risk", reasons, defer=not breach)
