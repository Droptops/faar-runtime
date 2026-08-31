#!/usr/bin/env python3
"""Deterministic failure-injection gate for FAAR v0.4.

Extends the mock-venue fault catalog. Not a live-network or OS crash simulator.
"""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from faar.adapters import MockMode, MockVenue
from faar.attestation import Ed25519TrustStore
from faar.canonical import canonical_hash
from faar.faults import InjectedFault
from faar.models import (
    AttestationKind, AuthorityDecision, AuthorityPosture, AuthorityPrimitive,
    CapabilityGrant, CapabilityLimits, EconomicPrimitive, GrantStatus, Intent,
    IntentState, RiskSnapshot, ExecutionRequest, SettlementRecord, SettlementStatus,
)
from faar.permits import ConstrainedPermitAuthority, Ed25519PermitSignature, ExecutionPermitVerifier
from faar.runtime import FAARRuntime
from faar.settlement import MockSettlementVerifier, QuorumSettlementVerifier, REFERENCE_SETTLEMENT_PROFILE
from faar.store import SQLiteIntentStore


NOW = datetime(2026, 8, 30, 18, tzinfo=timezone.utc)
AUTH = AuthorityDecision(AuthorityPosture.EXECUTE, AuthorityPrimitive.EXECUTE_ACTION, source="fault")
KEY_KINDS = {
    "auth": {AttestationKind.AUTHORITY},
    "risk": {AttestationKind.RISK},
}


def _stack(mode=MockMode.SUCCESS):
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); tmp.close()
    store = SQLiteIntentStore(tmp.name)
    grant = CapabilityGrant(
        principal_id="principal:test",
        grant_id="fault-grant", version=1, actor_id="agent:eval", status=GrantStatus.ACTIVE,
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
    trust = Ed25519TrustStore.generate(KEY_KINDS)
    sig = Ed25519PermitSignature("fault-permit")
    authority = ConstrainedPermitAuthority(store, trust.public_verifier(), sig)
    verifier = ExecutionPermitVerifier(sig.public_verifier(), store)
    venue = MockVenue(permit_verifier=verifier, name="mock-dex", mode=mode, clock=lambda: NOW)
    settlement = MockSettlementVerifier(venue)
    runtime = FAARRuntime(
        store, {"mock-dex": venue}, trust.public_verifier(), authority, {"mock-dex": settlement},
        allow_test_time_override=True,
    )
    return store, grant, trust, runtime, venue, verifier


def _intent(n: str) -> Intent:
    return Intent(
        principal_id="principal:test", intent_id=n, actor_id="agent:eval",
        grant_id="fault-grant", grant_version=1, primitive=EconomicPrimitive.SWAP,
        venue="mock-dex", created_at=NOW - timedelta(seconds=1), expires_at=NOW + timedelta(seconds=14),
        payload={"from_asset": "USDC", "to_asset": "MEME", "amount_usd": "50", "target": "router:ok"},
    )


def _risk(version: int) -> RiskSnapshot:
    return RiskSnapshot(
        observed_at=NOW, state_version=version, scope="portfolio",
        position_after_usd=Decimal("100"), daily_turnover_after_usd=Decimal("100"),
        daily_loss_usd=Decimal("10"), market_data_age_seconds=1,
        requested_slippage_bps=20, price_impact_bps=20, source_count=2, sources_agree=True,
    )


def _attest(trust, i, rs):
    aa = trust.sign("auth", AttestationKind.AUTHORITY, AUTH, i, issued_at=NOW, ttl_seconds=20)
    ra = trust.sign("risk", AttestationKind.RISK, rs, i, issued_at=NOW, ttl_seconds=20)
    return aa, ra


def _run(runtime, trust, grant, i, version):
    rs = _risk(version)
    aa, ra = _attest(trust, i, rs)
    return runtime.process(i, AUTH, grant, rs, authority_attestation=aa, risk_attestation=ra, now=NOW)


def main() -> None:
    cases: list[dict] = []

    store, grant, trust, runtime, venue, verifier = _stack(MockMode.TIMEOUT_BEFORE_EFFECT)
    i = _intent("fault_before_0000000000000001")
    result = _run(runtime, trust, grant, i, 1)
    cases.append({
        "fault": InjectedFault.TIMEOUT_BEFORE_ACCEPT.value,
        "state": result.state.value,
        "effects": venue.successful_effect_count(i.intent_id),
        "pass": result.state != IntentState.FINALIZED and venue.successful_effect_count(i.intent_id) == 0,
    })
    store.close()

    store, grant, trust, runtime, venue, verifier = _stack(MockMode.TIMEOUT_AFTER_EFFECT)
    i = _intent("fault_after_00000000000000001")
    result = _run(runtime, trust, grant, i, 1)
    cases.append({
        "fault": InjectedFault.TIMEOUT_AFTER_ACCEPT.value,
        "state": result.state.value,
        "effects": venue.successful_effect_count(i.intent_id),
        "pass": result.state == IntentState.FINALIZED and venue.successful_effect_count(i.intent_id) == 1,
    })
    store.close()

    store, grant, trust, runtime, venue, verifier = _stack(MockMode.AMBIGUOUS)
    i = _intent("fault_ambiguous_000000000000001")
    result = _run(runtime, trust, grant, i, 1)
    cases.append({
        "fault": InjectedFault.NETWORK_AMBIGUITY.value,
        "state": result.state.value,
        "effects": venue.successful_effect_count(i.intent_id),
        "pass": venue.successful_effect_count(i.intent_id) <= 1 and result.state != IntentState.FINALIZED,
    })
    store.close()

    store, grant, trust, runtime, venue, verifier = _stack()
    i = _intent("fault_stale_verifier_00000000001")
    first = _run(runtime, trust, grant, i, 1)
    verifier.lifecycle.revoke("fault-permit", at=NOW)
    i2 = _intent("fault_stale_verifier_00000000002")
    second = _run(runtime, trust, grant, i2, 2)
    cases.append({
        "fault": InjectedFault.STALE_VERIFIER.value,
        "first": first.state.value,
        "second": second.state.value,
        "pass": first.state == IntentState.FINALIZED and second.state != IntentState.FINALIZED,
    })
    store.close()

    store, grant, trust, runtime, venue, verifier = _stack()
    store.set_grant_status("principal:test", grant.grant_id, grant.version, "REVOKED")
    i = _intent("fault_revoke_submit_000000000001")
    result = _run(runtime, trust, grant, i, 1)
    cases.append({
        "fault": InjectedFault.REVOKE_DURING_SUBMIT.value,
        "state": result.state.value,
        "effects": venue.successful_effect_count(i.intent_id),
        "pass": result.state != IntentState.FINALIZED and venue.successful_effect_count(i.intent_id) == 0,
    })
    store.close()

    store, grant, trust, runtime, venue, verifier = _stack(MockMode.TIMEOUT_AFTER_EFFECT)
    i = _intent("fault_process_crash_00000000001")
    result = _run(runtime, trust, grant, i, 3)
    path = store.path
    store.close()
    restarted = SQLiteIntentStore(path)
    row = restarted._conn.execute(
        "SELECT consumed_at FROM execution_permits WHERE intent_id=?", (i.intent_id,)
    ).fetchone()
    cases.append({
        "fault": InjectedFault.PROCESS_CRASH.value,
        "state": result.state.value,
        "consumed_after_restart": row is not None and row["consumed_at"] is not None,
        "pass": result.state == IntentState.FINALIZED and row is not None and row["consumed_at"] is not None,
    })
    restarted.close()

    store, grant, trust, runtime, venue, verifier = _stack(MockMode.PARTIAL_FILL)
    i = _intent("fault_partial_fill_000000000001")
    result = _run(runtime, trust, grant, i, 4)
    second = _run(runtime, trust, grant, i, 4)
    cases.append({
        "fault": InjectedFault.PARTIAL_FILL.value,
        "first": result.state.value,
        "second": second.state.value,
        "effects": venue.successful_effect_count(i.intent_id),
        "pass": (
            result.state == IntentState.CONFIRMED
            and second.state == IntentState.CONFIRMED
            and venue.successful_effect_count(i.intent_id) == 1
            and result.effect_id == second.effect_id
        ),
    })
    store.close()

    req = ExecutionRequest.from_intent(_intent("fault_inconsistent_00000000001"))
    req_hash = canonical_hash(req)

    class _Source:
        security_profile = REFERENCE_SETTLEMENT_PROFILE
        def __init__(self, record, name):
            self.record = record
            self.name = name
        def verify(self, request):
            return self.record

    a = SettlementRecord(SettlementStatus.FINALIZED, "fx-a", Decimal("50"), authoritative=True, verified_request_hash=req_hash)
    b = SettlementRecord(SettlementStatus.NONE, authoritative=True, verified_request_hash=req_hash)
    inconsistent = QuorumSettlementVerifier([_Source(a, "provider-a"), _Source(b, "provider-b")], quorum=2).verify(req)
    cases.append({
        "fault": InjectedFault.INCONSISTENT_PROVIDER.value,
        "status": inconsistent.status.value,
        "pass": inconsistent.status == SettlementStatus.CONTRADICTORY and inconsistent.authoritative,
    })

    store, grant, trust, runtime, venue, verifier = _stack()
    i = _intent("fault_datastore_interrupt_000001")
    rs = _risk(5)
    store.register(i, canonical_hash(i))
    store.reserve_usage(i, grant, rs, NOW)
    aa, ra = _attest(trust, i, rs)
    req = ExecutionRequest.from_intent(i)
    permit = runtime.permit_authority.issue(
        req, intent=i, authority=AUTH, grant=grant, risk=rs,
        authority_attestation=aa, risk_attestation=ra, now=NOW,
    )
    store.close()
    ok, consume_reasons = verifier.consume(permit, req, now=NOW)
    cases.append({
        "fault": InjectedFault.DATASTORE_INTERRUPT.value,
        "consumed": ok,
        "reasons": list(consume_reasons),
        "pass": not ok,
    })

    store, grant, trust, runtime, venue, verifier = _stack()
    i = _intent("fault_duplicate_worker_000000001")
    rs = _risk(6)
    store.register(i, canonical_hash(i))
    store.reserve_usage(i, grant, rs, NOW)
    aa, ra = _attest(trust, i, rs)
    req = ExecutionRequest.from_intent(i)
    permit = runtime.permit_authority.issue(
        req, intent=i, authority=AUTH, grant=grant, risk=rs,
        authority_attestation=aa, risk_attestation=ra, now=NOW,
    )
    first_ok, _ = verifier.consume(permit, req, now=NOW)
    second_ok, second_reasons = verifier.consume(permit, req, now=NOW)
    cases.append({
        "fault": InjectedFault.DUPLICATE_WORKER.value,
        "first": first_ok,
        "second": second_ok,
        "pass": first_ok and not second_ok and "PERMIT_ALREADY_CONSUMED" in second_reasons,
    })
    store.close()

    passed = all(c["pass"] for c in cases)
    report = {
        "suite": "FAAR v0.4 deterministic failure injection",
        "faults": len(InjectedFault),
        "cases": cases,
        "unauthorized_extra_effects": 0 if passed else 1,
        "pass": passed,
        "claim_boundary": "In-process mock-venue fault catalog; not a live-network or production crash test.",
    }
    print(json.dumps(report, indent=2))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
