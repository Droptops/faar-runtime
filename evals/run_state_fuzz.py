#!/usr/bin/env python3
"""Seeded state-machine fuzz for FAAR's reference invariants.

No third-party property-testing dependency is used. This is deliberately modest:
it broadens regression coverage but is not formal verification.
"""

from __future__ import annotations

import json
import random
import threading
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from faar.adapters import MockMode, MockVenue
from faar.attestation import HMACTrustStore
from faar.canonical import canonical_hash
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
from faar.runtime import FAARRuntime
from faar.store import SQLiteIntentStore


NOW = datetime(2026, 8, 30, 18, tzinfo=timezone.utc)
KEYS = {
    "auth": b"fuzz-authority-key-material-32-bytes!!",
    "risk": b"fuzz-risk-key-material-32-bytes-long!!",
}
KEY_KINDS = {
    "auth": {AttestationKind.AUTHORITY},
    "risk": {AttestationKind.RISK},
}
AUTH = AuthorityDecision(AuthorityPosture.EXECUTE, AuthorityPrimitive.EXECUTE_ACTION, source="fuzz")


def make_grant(*, daily_cap: str = "100", attempts: int = 3) -> CapabilityGrant:
    return CapabilityGrant(
        grant_id="grant:fuzz",
        version=1,
        actor_id="agent:fuzz",
        status=GrantStatus.ACTIVE,
        allowed_primitives=frozenset({EconomicPrimitive.SWAP}),
        allowed_venues=frozenset({"mock-dex"}),
        allowed_assets=frozenset({"USDC", "MEME"}),
        allowed_targets=frozenset({"router:ok"}),
        limits=CapabilityLimits(
            max_order_usd=Decimal("50"),
            max_position_usd=Decimal("1000"),
            max_daily_turnover_usd=Decimal(daily_cap),
            max_daily_loss_usd=Decimal("1000"),
            max_slippage_bps=100,
            max_price_impact_bps=100,
            max_market_data_age_seconds=10,
            max_risk_snapshot_age_seconds=5,
            max_intent_ttl_seconds=20,
            max_actions_per_window=100,
            action_window_seconds=60,
            max_submission_attempts=attempts,
        ),
    )


def make_intent(iid: str, amount: int) -> Intent:
    return Intent(
        intent_id=iid,
        actor_id="agent:fuzz",
        grant_id="grant:fuzz",
        grant_version=1,
        primitive=EconomicPrimitive.SWAP,
        venue="mock-dex",
        created_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=19),
        payload={
            "from_asset": "USDC",
            "to_asset": "MEME",
            "amount_usd": str(amount),
            "target": "router:ok",
        },
    )


def make_risk(version: int) -> RiskSnapshot:
    return RiskSnapshot(
        observed_at=NOW,
        state_version=version,
        scope="portfolio",
        position_after_usd=Decimal("100"),
        daily_turnover_after_usd=Decimal("0"),
        daily_loss_usd=Decimal("0"),
        market_data_age_seconds=1,
        requested_slippage_bps=10,
        price_impact_bps=10,
        actions_in_window=0,
        circuit_breaker_active=False,
        data_complete=True,
        source_count=2,
        sources_agree=True,
    )


def signed(trust: HMACTrustStore, i: Intent, r: RiskSnapshot):
    return (
        trust.sign("auth", AttestationKind.AUTHORITY, AUTH, i, issued_at=NOW, ttl_seconds=30),
        trust.sign("risk", AttestationKind.RISK, r, i, issued_at=NOW, ttl_seconds=30),
    )


def replay_fuzz(seed: int) -> None:
    rng = random.Random(seed)
    store = SQLiteIntentStore(":memory:")
    grant = make_grant(daily_cap="500")
    store.provision_grant(grant, canonical_hash(grant))
    venue = MockVenue(name="mock-dex", mode=rng.choice(list(MockMode)))
    trust = HMACTrustStore(KEYS, key_kinds=KEY_KINDS)
    runtime = FAARRuntime(store, {"mock-dex": venue}, trust, allow_test_time_override=True)
    i = make_intent(f"fuzz_replay_{seed:04d}_000000000", 25)
    r = make_risk(1)
    aa, ra = signed(trust, i, r)

    for _ in range(8):
        venue.set_mode(rng.choice(list(MockMode)))
        runtime.process(i, AUTH, grant, r, authority_attestation=aa, risk_attestation=ra, now=NOW)
        if venue.successful_effect_count(i.intent_id) > 1:
            raise AssertionError(f"seed {seed}: duplicate economic effect")


def concurrent_budget_fuzz(seed: int) -> None:
    rng = random.Random(seed + 100_000)
    store = SQLiteIntentStore(":memory:")
    grant = make_grant(daily_cap="100")
    store.provision_grant(grant, canonical_hash(grant))
    venue = MockVenue(name="mock-dex", mode=MockMode.SUCCESS)
    trust = HMACTrustStore(KEYS, key_kinds=KEY_KINDS)
    runtime = FAARRuntime(store, {"mock-dex": venue}, trust, allow_test_time_override=True)

    jobs = []
    for idx in range(8):
        amount = rng.randint(10, 50)
        i = make_intent(f"fuzz_budget_{seed:04d}_{idx:02d}_000000", amount)
        r = make_risk(idx + 1)
        aa, ra = signed(trust, i, r)
        jobs.append((i, r, aa, ra))
    rng.shuffle(jobs)

    errors: list[BaseException] = []

    def worker(job):
        i, r, aa, ra = job
        try:
            runtime.process(i, AUTH, grant, r, authority_attestation=aa, risk_attestation=ra, now=NOW)
        except BaseException as exc:  # preserve any thread failure for the harness
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(job,)) for job in jobs]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        raise AssertionError(f"seed {seed}: worker exception: {errors[0]!r}")

    counted = Decimal("0")
    for row in store.usage(grant.grant_id, grant.version):
        if row["status"] in {"HELD", "COMMITTED"}:
            counted += Decimal(row["amount_usd"])
    if counted > grant.limits.max_daily_turnover_usd:
        raise AssertionError(f"seed {seed}: atomic daily budget exceeded: {counted}")


def main() -> None:
    replay_seeds = 64
    budget_seeds = 32
    for seed in range(replay_seeds):
        replay_fuzz(seed)
    for seed in range(budget_seeds):
        concurrent_budget_fuzz(seed)

    print(json.dumps({
        "suite": "FAAR v0.2 seeded state-machine fuzz",
        "replay_seeds": replay_seeds,
        "concurrent_budget_seeds": budget_seeds,
        "total_seed_scenarios": replay_seeds + budget_seeds,
        "duplicate_effect_violations": 0,
        "aggregate_budget_violations": 0,
        "pass": True,
        "claim_boundary": "Seeded regression fuzz; not exhaustive property testing or formal verification.",
    }, indent=2))


if __name__ == "__main__":
    main()
