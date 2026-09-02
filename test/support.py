from __future__ import annotations

import os
import tempfile
from dataclasses import replace
from types import SimpleNamespace
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from faar.attestation import Ed25519TrustStore, HMACTrustStore, has_signing_api
from faar.permits import ConstrainedPermitAuthority, Ed25519PermitSignature, ExecutionPermitVerifier
from faar.adapters import MockVenue, MockMode
from faar.settlement import MockSettlementVerifier
from faar.runtime import FAARRuntime
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

PRINCIPAL = "principal:test"
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


def temp_path(case, suffix: str = ".sqlite") -> str:
    """A unique path inside a per-test temporary directory that is removed at cleanup.

    Nothing is created at the path itself, so it serves for SQLite files (and their
    -wal/-shm companions), anchor files and snapshots alike.
    """
    tmpdir = tempfile.TemporaryDirectory(prefix="faar-test-")
    case.addCleanup(tmpdir.cleanup)
    return os.path.join(tmpdir.name, "store" + suffix)


def temp_file(case, suffix: str = ".sqlite"):
    """`temp_path` wrapped so `.name` reads like a NamedTemporaryFile."""
    return SimpleNamespace(name=temp_path(case, suffix))


def trust() -> Ed25519TrustStore:
    return Ed25519TrustStore.generate(TRUST_KEY_KINDS)


def verification_trust(t):
    return t.public_verifier() if has_signing_api(t) and hasattr(t, "public_verifier") else t


def intent(**changes):
    base = Intent(
        principal_id=PRINCIPAL,
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
        principal_id=PRINCIPAL,
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


def attest_pair(t, i: Intent, auth: AuthorityDecision, rs: RiskSnapshot, now: datetime = NOW):
    aa = t.sign("authority-test", AttestationKind.AUTHORITY, auth, i, issued_at=now, ttl_seconds=20)
    ra = t.sign("risk-test", AttestationKind.RISK, rs, i, issued_at=now, ttl_seconds=20)
    return aa, ra


class Clock:
    """Deterministic, advanceable clock shared by the runtime and a venue in tests."""

    def __init__(self, start: datetime = NOW) -> None:
        self.now = start

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> datetime:
        self.now = self.now + timedelta(seconds=seconds)
        return self.now


def permit_stack(store, trust_store=None, *, max_permit_ttl_seconds=5):
    trust_store = trust_store or trust()
    verifier_trust = verification_trust(trust_store)
    sig = Ed25519PermitSignature("permit-test")
    authority = ConstrainedPermitAuthority(store, verifier_trust, sig, max_permit_ttl_seconds=max_permit_ttl_seconds)
    verifier = ExecutionPermitVerifier(sig.public_verifier(), store)
    return authority, verifier


def build_mock_runtime(
    store,
    trust_store=None,
    *,
    name="mock-dex",
    mode=MockMode.SUCCESS,
    runtime_clock=lambda: NOW,
    venue_clock=lambda: NOW,
    allow_test_time_override=True,
    max_permit_ttl_seconds=5,
    adapter_deadline_seconds=None,
):
    trust_store = trust_store or trust()
    verifier_trust = verification_trust(trust_store)
    permit_authority, permit_verifier = permit_stack(store, trust_store, max_permit_ttl_seconds=max_permit_ttl_seconds)
    venue = MockVenue(permit_verifier=permit_verifier, name=name, mode=mode, clock=venue_clock)
    settlement = MockSettlementVerifier(venue=venue)
    runtime = FAARRuntime(
        store, {name: venue}, verifier_trust, permit_authority, {name: settlement},
        clock=runtime_clock, allow_test_time_override=allow_test_time_override,
        adapter_deadline_seconds=adapter_deadline_seconds,
    )
    return runtime, venue, settlement, permit_authority, permit_verifier
