from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from faar.attestation import HMACTrustStore
from faar.models import (
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

NOW = datetime(2026, 8, 30, 18, 0, tzinfo=timezone.utc)
AUTH = AuthorityDecision(AuthorityPosture.EXECUTE, AuthorityPrimitive.EXECUTE_ACTION, source="test")
TRUST_KEYS = {
    "authority-test": b"authority-test-key-32-bytes-long!!!",
    "risk-test": b"risk-test-key-32-bytes-long!!!!!!!!",
    "task-test": b"task-test-key-32-bytes-long!!!!!!!!",
}
TRUST_KEY_KINDS = {
    "authority-test": {AttestationKind.AUTHORITY},
    "risk-test": {AttestationKind.RISK},
    "task-test": {AttestationKind.TASK},
}


def trust() -> HMACTrustStore:
    return HMACTrustStore(TRUST_KEYS, key_kinds=TRUST_KEY_KINDS)


def intent(**changes):
    base = Intent(
        intent_id="intent_test_000000000001",
        actor_id="agent:quant",
        grant_id="grant:test",
        grant_version=1,
        primitive=EconomicPrimitive.SWAP,
        venue="mock-dex",
        created_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=14),
        payload={
            "from_asset": "USDC",
            "to_asset": "MEME",
            "amount_usd": "50",
            "target": "router:approved",
        },
    )
    return replace(base, **changes)


def grant(**changes):
    base = CapabilityGrant(
        grant_id="grant:test",
        version=1,
        actor_id="agent:quant",
        status=GrantStatus.ACTIVE,
        allowed_primitives=frozenset({EconomicPrimitive.SWAP}),
        allowed_venues=frozenset({"mock-dex"}),
        allowed_assets=frozenset({"USDC", "MEME"}),
        allowed_targets=frozenset({"router:approved"}),
        limits=CapabilityLimits(
            max_order_usd=Decimal("75"),
            max_position_usd=Decimal("250"),
            max_daily_turnover_usd=Decimal("1500"),
            max_daily_loss_usd=Decimal("100"),
            max_slippage_bps=75,
            max_price_impact_bps=100,
            max_market_data_age_seconds=10,
            max_risk_snapshot_age_seconds=5,
            max_intent_ttl_seconds=15,
            max_clock_skew_seconds=2,
            max_actions_per_window=10,
            action_window_seconds=60,
            max_submission_attempts=2,
        ),
    )
    return replace(base, **changes)


def risk(**changes):
    base = RiskSnapshot(
        observed_at=NOW,
        state_version=1,
        scope="portfolio",
        position_after_usd=Decimal("150"),
        daily_turnover_after_usd=Decimal("600"),
        daily_loss_usd=Decimal("20"),
        market_data_age_seconds=2,
        requested_slippage_bps=50,
        price_impact_bps=40,
        actions_in_window=1,
        circuit_breaker_active=False,
        data_complete=True,
        source_count=2,
        sources_agree=True,
    )
    return replace(base, **changes)


def attest_pair(t: HMACTrustStore, i: Intent, auth: AuthorityDecision, rs: RiskSnapshot, now: datetime = NOW):
    aa = t.sign("authority-test", AttestationKind.AUTHORITY, auth, i, issued_at=now, ttl_seconds=20)
    ra = t.sign("risk-test", AttestationKind.RISK, rs, i, issued_at=now, ttl_seconds=20)
    return aa, ra
