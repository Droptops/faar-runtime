#!/usr/bin/env python3
"""Deterministic adversarial smoke harness for FAAR v0.2.

This is not a security audit or formal proof. It is an executable regression gate
for the reference invariants using only local deterministic components.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from faar.adapters import MockMode, MockVenue
from faar.attestation import HMACTrustStore
from faar.canonical import canonical_hash
from faar.models import (
    AttestationKind, AuthorityDecision, AuthorityPosture, AuthorityPrimitive,
    CapabilityGrant, CapabilityLimits, EconomicPrimitive, GrantStatus,
    Intent, RiskSnapshot,
)
from faar.runtime import FAARRuntime
from faar.store import SQLiteIntentStore


NOW = datetime(2026, 8, 30, 18, tzinfo=timezone.utc)
AUTH = AuthorityDecision(AuthorityPosture.EXECUTE, AuthorityPrimitive.EXECUTE_ACTION, source="redteam")
KEYS = {
    "auth": b"adversarial-authority-key-32-bytes!!",
    "risk": b"adversarial-risk-key-32-bytes-long!!",
}
KEY_KINDS = {
    "auth": {AttestationKind.AUTHORITY},
    "risk": {AttestationKind.RISK},
}


def main() -> None:
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); tmp.close()
    store = SQLiteIntentStore(tmp.name, evidence_key=b"adversarial-evidence-key-32-bytes!")
    grant = CapabilityGrant(
        grant_id="eval-grant", version=1, actor_id="agent:eval", status=GrantStatus.ACTIVE,
        allowed_primitives=frozenset({EconomicPrimitive.SWAP}),
        allowed_venues=frozenset({"mock-dex"}),
        allowed_assets=frozenset({"USDC", "MEME"}),
        allowed_targets=frozenset({"router:ok"}),
        limits=CapabilityLimits(
            max_order_usd=Decimal("75"), max_position_usd=Decimal("250"),
            max_daily_turnover_usd=Decimal("1500"), max_daily_loss_usd=Decimal("100"),
            max_slippage_bps=75, max_price_impact_bps=100,
            max_market_data_age_seconds=10, max_risk_snapshot_age_seconds=5,
            max_intent_ttl_seconds=15, max_clock_skew_seconds=2,
            max_actions_per_window=100, action_window_seconds=60,
            max_submission_attempts=2,
        ),
    )
    store.provision_grant(grant, canonical_hash(grant))
    venue = MockVenue(name="mock-dex")
    trust = HMACTrustStore(KEYS, key_kinds=KEY_KINDS)
    runtime = FAARRuntime(store, {"mock-dex": venue}, trust, allow_test_time_override=True)

    def rs(version: int = 1, **changes) -> RiskSnapshot:
        base = RiskSnapshot(
            observed_at=NOW, state_version=version, scope="portfolio",
            position_after_usd=Decimal("100"), daily_turnover_after_usd=Decimal("100"),
            daily_loss_usd=Decimal("10"), market_data_age_seconds=1,
            requested_slippage_bps=20, price_impact_bps=20, source_count=2, sources_agree=True,
        )
        return replace(base, **changes)

    def make(iid: str, **payload_overrides) -> Intent:
        payload = {"from_asset": "USDC", "to_asset": "MEME", "amount_usd": "50", "target": "router:ok"}
        payload.update(payload_overrides)
        return Intent(
            intent_id=iid, actor_id="agent:eval", grant_id="eval-grant", grant_version=1,
            primitive=EconomicPrimitive.SWAP, venue="mock-dex", created_at=NOW - timedelta(seconds=1),
            expires_at=NOW + timedelta(seconds=14), payload=payload,
        )

    def process(i: Intent, auth=AUTH, risk=None, *, tamper_auth=False):
        risk = risk or rs()
        aa = trust.sign("auth", AttestationKind.AUTHORITY, auth, i, issued_at=NOW, ttl_seconds=20)
        ra = trust.sign("risk", AttestationKind.RISK, risk, i, issued_at=NOW, ttl_seconds=20)
        if tamper_auth:
            aa = replace(aa, mac="00" * 32)
        return runtime.process(i, auth, grant, risk, authority_attestation=aa, risk_attestation=ra, now=NOW)

    unauthorized_effects = 0
    denial_cases = []
    mutations = [
        ("target", {"target": "wallet:attacker"}, AUTH, rs()),
        ("asset", {"to_asset": "SCAM"}, AUTH, rs()),
        ("amount", {"amount_usd": "1000"}, AUTH, rs()),
        ("nan", {"amount_usd": "NaN"}, AUTH, rs()),
        ("raw", {"raw_calldata": "0xdeadbeef"}, AUTH, rs()),
        ("stale", {}, AUTH, rs(market_data_age_seconds=999)),
        ("snapshot-stale", {}, AUTH, rs(observed_at=NOW - timedelta(seconds=6))),
        ("sources", {}, AUTH, rs(sources_agree=False)),
        ("breaker", {}, AUTH, rs(circuit_breaker_active=True)),
        ("advise", {}, AuthorityDecision(AuthorityPosture.ADVISE, AuthorityPrimitive.GIVE_RECOMMENDATION), rs()),
    ]
    for n in range(16):
        for label, override, auth, risk in mutations:
            i = make(f"eval_denied_{n:02d}_{label}_000000", **override)
            result = process(i, auth, risk)
            effects = venue.successful_effect_count(i.intent_id)
            unauthorized_effects += effects
            denial_cases.append({"case": f"{n}:{label}", "state": result.state.value, "effects": effects})

    forged = make("eval_forged_attestation_0001")
    forged_result = process(forged, risk=rs(), tamper_auth=True)
    unauthorized_effects += venue.successful_effect_count(forged.intent_id)

    # Exactly-once replay under repeated client retries.
    replay_intent = make("eval_replay_000000000001")
    replay_risk = rs(version=1)
    first = process(replay_intent, risk=replay_risk)
    for _ in range(99):
        process(replay_intent, risk=replay_risk)
    replay_effects = venue.successful_effect_count(replay_intent.intent_id)

    # Ambiguous-after-effect reconciliation on a fresh risk state.
    venue.set_mode(MockMode.TIMEOUT_AFTER_EFFECT)
    ambiguous = make("eval_timeout_after_00000001")
    amb_result = process(ambiguous, risk=rs(version=2))
    ambiguous_effects = venue.successful_effect_count(ambiguous.intent_id)

    report = {
        "suite": "FAAR v0.2 deterministic adversarial smoke",
        "denial_cases": len(denial_cases),
        "forged_attestation_state": forged_result.state.value,
        "unauthorized_economic_effects": unauthorized_effects,
        "replay_attempts": 100,
        "replay_final_state": first.state.value,
        "replay_successful_effects": replay_effects,
        "timeout_after_effect_final_state": amb_result.state.value,
        "timeout_after_effect_successful_effects": ambiguous_effects,
        "evidence_chain_valid": store.verify_evidence_chain(replay_intent.intent_id),
        "pass": (
            unauthorized_effects == 0
            and replay_effects == 1
            and ambiguous_effects == 1
            and forged_result.state.value == "STOPPED"
        ),
    }
    print(json.dumps(report, indent=2))
    if not report["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
