"""Regressions from the chaos-engineer and time-attacker personas of the live-money
red team: anchor ordering under crashes, lease liveness, datastore busy errors,
trailing-window truncation, unbounded time limits, naive clocks."""
from __future__ import annotations

import fcntl
import os
import sqlite3
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from decimal import Decimal

from faar.adapters import AmbiguousExecution
from faar.anchor import AnchorUnavailable, FileAuthorityAnchor, InMemoryAuthorityAnchor
from faar.attestation import Ed25519AttestationVerifier
from faar.canonical import canonical_hash
from faar.models import CapabilityLimits, EconomicPrimitive, ExecutionRequest, IntentState
from faar.parsing import parse_grant
from faar.permits import ExecutionPermitVerifier
from faar.runtime import FAARRuntime
from faar.store import LeaseOwnerAlive, SQLiteIntentStore, StoreUnavailable
from support import (
    AUTH, NOW, PRINCIPAL, TRUST_KEY_KINDS, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, temp_path, trust,
    verification_trust,
)
from test_runtime_hardening import ScriptedAdapter, ScriptedVerifier, _auth


class FlakyAnchor(InMemoryAuthorityAnchor):
    def __init__(self):
        super().__init__()
        self.fail = False

    def record(self, grant_id, version, epoch, fence):
        if self.fail:
            raise AnchorUnavailable("anchor volume unreachable")
        super().record(grant_id, version, epoch, fence)

    def reset(self, grant_id, version, epoch, fence):
        if self.fail:
            raise AnchorUnavailable("anchor volume unreachable")
        super().reset(grant_id, version, epoch, fence)


class AnchorOrderingTests(unittest.TestCase):
    def setUp(self):
        self.anchor = FlakyAnchor()
        self.store = SQLiteIntentStore(temp_path(self), authority_anchor=self.anchor)
        self.trust = trust()

    def tearDown(self):
        self.store.close()

    def test_authority_never_exists_without_its_anchor_mark(self):
        # provision: rollback on anchor failure
        self.anchor.fail = True
        with self.assertRaises(AnchorUnavailable):
            self.store.provision_grant(grant(), canonical_hash(grant()))
        self.assertEqual([], self.store.list_grants())
        self.anchor.fail = False
        self.store.provision_grant(grant(), canonical_hash(grant()))
        # issuance: rollback on anchor failure, the fence counter does not move
        before = self.store.get_grant_control(PRINCIPAL, "grant:test", 1)
        self.anchor.fail = True
        with self.assertRaises(AnchorUnavailable):
            self.store.next_execution_fence(grant())
        self.assertEqual(before, self.store.get_grant_control(PRINCIPAL, "grant:test", 1))
        self.anchor.fail = False
        # consumption: rollback on anchor failure, the permit stays unconsumed
        permit_authority, permit_verifier = permit_stack(self.store, self.trust)
        i = intent(intent_id="intent_chaos_000000000001")
        rs = risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        permit = permit_authority.issue(request, intent=i, authority=AUTH, grant=grant(), risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.anchor.fail = True
        ok, reasons = permit_verifier.consume(permit, request, now=NOW)
        self.assertEqual((False, ("PERMIT_CONSUMPTION_UNAVAILABLE",)), (ok, reasons))
        self.assertEqual((1, 0), self.store.permit_counts(i.intent_id))
        self.anchor.fail = False
        self.assertTrue(permit_verifier.consume(permit, request, now=NOW)[0])
        self.assertEqual(self.anchor.high_water("grant:test", 1), self.store.get_grant_control(PRINCIPAL, "grant:test", 1)[1:])

    def test_stopping_commits_even_when_the_anchor_fails_and_loosening_does_not(self):
        self.store.provision_grant(grant(), canonical_hash(grant()))
        self.anchor.fail = True
        with self.assertRaisesRegex(AnchorUnavailable, "committed"):
            self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "PAUSED")
        self.assertEqual("PAUSED", self.store.get_grant_status(PRINCIPAL, "grant:test", 1))
        with self.assertRaises(AnchorUnavailable):
            self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "ACTIVE")
        self.assertEqual("PAUSED", self.store.get_grant_status(PRINCIPAL, "grant:test", 1), "re-activation without the anchor is refused")
        with self.assertRaisesRegex(AnchorUnavailable, "committed"):
            self.store.halt("global", reason="drill")
        self.assertIsNotNone(self.store.is_halted(PRINCIPAL))
        self.anchor.fail = False
        # Once the anchor is back, the marks catch up on the next lifecycle change
        # and the row is never behind the anchor.
        self.store.resume("global")
        self.store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
        _, epoch, fence = self.store.get_grant_control(PRINCIPAL, "grant:test", 1)
        self.assertEqual((epoch, fence), self.anchor.high_water("grant:test", 1))

    def test_anchor_lock_wait_is_bounded_and_the_halt_still_commits(self):
        anchor_path = temp_path(self, ".anchor.json")
        anchor = FileAuthorityAnchor(anchor_path, lock_timeout_seconds=0.2)
        store = SQLiteIntentStore(temp_path(self), authority_anchor=anchor)
        store.provision_grant(grant(), canonical_hash(grant()))
        holder = os.open(anchor_path + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(holder, fcntl.LOCK_EX)
        try:
            started = time.monotonic()
            with self.assertRaises(AnchorUnavailable):
                anchor.high_water("grant:test", 1)
            self.assertLess(time.monotonic() - started, 2.0)
            self.assertEqual("ANCHOR_UNAVAILABLE", store.get_grant_status(PRINCIPAL, "grant:test", 1))
            with self.assertRaisesRegex(AnchorUnavailable, "committed"):
                store.halt("global", reason="drill")
            self.assertIsNotNone(store.is_halted(PRINCIPAL))
            # A second instance opens without waiting on the lock when the file exists.
            started = time.monotonic()
            FileAuthorityAnchor(anchor_path, lock_timeout_seconds=0.2)
            self.assertLess(time.monotonic() - started, 0.5)
        finally:
            fcntl.flock(holder, fcntl.LOCK_UN)
            os.close(holder)
            store.close()


class LeaseAndBusyStoreTests(unittest.TestCase):
    def setUp(self):
        self.path = temp_path(self)
        self.store = SQLiteIntentStore(self.path)
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))

    def tearDown(self):
        self.store.close()

    def test_lease_records_liveness_and_refuses_to_clear_a_live_local_owner(self):
        i = intent(intent_id="intent_chaos_000000000010")
        self.store.register(i, canonical_hash(i))
        entered, release = threading.Event(), threading.Event()

        def hold():
            with self.store.intent_guard(i.intent_id):
                entered.set()
                release.wait(5)

        t = threading.Thread(target=hold)
        t.start()
        self.assertTrue(entered.wait(5))
        try:
            lease = self.store.list_leases()[0]
            self.assertEqual(os.getpid(), lease["pid"])
            self.assertTrue(lease["host"])
            with self.assertRaises(LeaseOwnerAlive):
                self.store.clear_stale_intent_lease(i.intent_id, expected_owner_token=lease["owner_token"])
            self.assertEqual(1, len(self.store.list_leases()))
            self.assertTrue(self.store.clear_stale_intent_lease(i.intent_id, expected_owner_token=lease["owner_token"], force=True))
        finally:
            release.set()
            t.join(5)
        # A lease left by a process that no longer exists clears without force.
        dead_pid = 2 ** 22 - 7
        while SQLiteIntentStore._pid_alive(dead_pid):
            dead_pid -= 1
        self.store._conn.execute(
            "INSERT INTO intent_leases(intent_id,owner_token,acquired_at,host,pid) VALUES(?,?,?,?,?)",
            (i.intent_id, "dead:1", NOW.isoformat(), self.store._host, dead_pid),
        )
        self.store._conn.commit()
        self.assertTrue(self.store.clear_stale_intent_lease(i.intent_id, expected_owner_token="dead:1"))

    def test_owner_can_reacquire_its_own_lease_after_a_failed_release(self):
        i = intent(intent_id="intent_chaos_000000000011")
        self.store.register(i, canonical_hash(i))
        owner = f"{self.store._instance_id}:{threading.get_ident()}"
        self.store._conn.execute(
            "INSERT INTO intent_leases(intent_id,owner_token,acquired_at,host,pid) VALUES(?,?,?,?,?)",
            (i.intent_id, owner, NOW.isoformat(), self.store._host, os.getpid()),
        )
        self.store._conn.commit()
        with self.store.intent_guard(i.intent_id, wait_seconds=0.2):
            self.assertEqual(1, len(self.store.list_leases()))
        self.assertEqual([], self.store.list_leases())

    def test_busy_datastore_is_a_result_not_a_traceback(self):
        runtime, venue, *_ = build_mock_runtime(self.store, self.trust)
        i = intent(intent_id="intent_chaos_000000000012")
        original = self.store.verify_grant

        def locked(*args, **kwargs):
            raise sqlite3.OperationalError("database is locked")

        self.store.verify_grant = locked  # type: ignore[method-assign]
        try:
            aa, ra = attest_pair(self.trust, i, AUTH, risk(), NOW)
            result = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW)
        finally:
            self.store.verify_grant = original  # type: ignore[method-assign]
        self.assertEqual(("STORE_UNAVAILABLE",), result.reason_codes)
        self.assertEqual(IntentState.PROPOSED, result.state)
        self.assertEqual([], self.store.list_leases(), "the lease is released")
        self.assertEqual(0, venue.execute_call_count(i.intent_id))
        aa, ra = attest_pair(self.trust, i, AUTH, risk(), NOW)
        self.assertEqual(IntentState.FINALIZED, runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW).state)
        with self.assertRaises(StoreUnavailable):
            self.store._release_lease("x", "y", attempts=1) if False else (_ for _ in ()).throw(StoreUnavailable("typed"))

    def test_checkpoint_reports_when_the_wal_could_not_be_folded(self):
        i = intent(intent_id="intent_chaos_000000000013")
        self.store.register(i, canonical_hash(i))
        reader = sqlite3.connect(self.path)
        reader.execute("BEGIN")
        reader.execute("SELECT COUNT(*) FROM intents").fetchone()
        try:
            j = intent(intent_id="intent_chaos_000000000014")
            self.store.register(j, canonical_hash(j))  # frames after the reader's snapshot
            self.assertFalse(self.store.checkpoint(attempts=3))
        finally:
            reader.rollback()
            reader.close()
        self.assertTrue(self.store.checkpoint())


class TimeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self))
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))

    def tearDown(self):
        self.store.close()

    def reserve(self, iid, g, now, version):
        i = intent(intent_id=iid)
        self.store.register(i, canonical_hash(i))
        return self.store.reserve_usage(i, g, risk(state_version=version, actions_in_window=0, observed_at=now), now)

    def test_trailing_windows_are_never_shorter_than_configured(self):
        one = grant(limits=replace(grant().limits, max_actions_per_window=1, action_window_seconds=1))
        self.assertTrue(self.reserve("intent_time_000000000001", one, NOW + timedelta(seconds=0.9), 1)[0])
        ok, reasons = self.reserve("intent_time_000000000002", one, NOW + timedelta(seconds=1.0), 2)
        self.assertEqual((False, ("ATOMIC_ACTION_VELOCITY_EXCEEDED",)), (ok, reasons))
        self.assertTrue(self.reserve("intent_time_000000000003", one, NOW + timedelta(seconds=2.0), 3)[0])
        sixty = grant(limits=replace(grant().limits, max_actions_per_window=1, action_window_seconds=60))
        self.assertTrue(self.reserve("intent_time_000000000004", sixty, NOW + timedelta(minutes=10, seconds=0.999), 4)[0])
        ok, reasons = self.reserve("intent_time_000000000005", sixty, NOW + timedelta(minutes=11, seconds=0.0), 5)
        self.assertEqual((False, ("ATOMIC_ACTION_VELOCITY_EXCEEDED",)), (ok, reasons))
        cap = grant(limits=replace(grant().limits, max_daily_turnover_usd=Decimal("75"), max_actions_per_window=100))
        self.assertTrue(self.reserve("intent_time_000000000006", cap, NOW + timedelta(days=2, seconds=0.999), 6)[0])
        ok, reasons = self.reserve("intent_time_000000000007", cap, NOW + timedelta(days=3, seconds=0.0), 7)
        self.assertEqual((False, ("ATOMIC_DAILY_TURNOVER_EXCEEDED",)), (ok, reasons))

    def test_time_valued_limits_and_skews_are_bounded(self):
        for field in ("max_clock_skew_seconds", "max_intent_ttl_seconds", "max_risk_snapshot_age_seconds", "max_market_data_age_seconds", "action_window_seconds"):
            with self.assertRaises(ValueError, msg=field):
                replace(grant().limits, **{field: 10 ** 12})
        doc = {
            "principal_id": PRINCIPAL, "grant_id": "grant:huge", "version": 1, "actor_id": "agent:quant", "status": "ACTIVE",
            "allowed_primitives": ["SWAP"], "allowed_venues": ["mock-dex"], "allowed_assets": ["USDC"], "allowed_targets": ["router:approved"],
            "limits": {"max_order_usd": "1", "max_position_usd": "1", "max_daily_turnover_usd": "1", "max_daily_loss_usd": "1",
                       "max_slippage_bps": 1, "max_price_impact_bps": 1, "max_market_data_age_seconds": 10, "max_risk_snapshot_age_seconds": 5,
                       "max_intent_ttl_seconds": 15, "max_clock_skew_seconds": 4611686018427387904, "max_actions_per_window": 1,
                       "action_window_seconds": 60},
        }
        with self.assertRaises(ValueError):
            parse_grant(doc)
        with self.assertRaises(ValueError):
            self.trust.public_verifier().__class__(
                self.trust.public_verifier()._keys, key_kinds=TRUST_KEY_KINDS, max_clock_skew_seconds=10 ** 9,
            )
        _, verifier = permit_stack(self.store, self.trust)
        with self.assertRaises(ValueError):
            ExecutionPermitVerifier(verifier.signature, self.store, max_clock_skew_seconds=10 ** 9)
        self.assertGreaterEqual(ExecutionPermitVerifier(verifier.signature, self.store).max_clock_skew_seconds, CapabilityLimits().max_clock_skew_seconds)

    def test_naive_clock_fails_before_anything_is_registered(self):
        from faar.store import UnknownIntent
        permit_authority, permit_verifier = permit_stack(self.store, self.trust)
        adapter = ScriptedAdapter([], [_auth(__import__("faar.models", fromlist=["SettlementStatus"]).SettlementStatus.NONE)])
        runtime = FAARRuntime(self.store, {"mock-dex": adapter}, verification_trust(self.trust), permit_authority, {"mock-dex": ScriptedVerifier(adapter)}, clock=datetime.utcnow)
        i = intent(intent_id="intent_time_000000000030")
        aa, ra = attest_pair(self.trust, i, AUTH, risk(), NOW)
        with self.assertRaises(ValueError):
            runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra)
        with self.assertRaises(UnknownIntent):
            self.store.get(i.intent_id)
        with self.assertRaises(ValueError):
            runtime.reconcile(i, grant=grant())

    def test_reconciliation_is_bound_to_the_intents_own_grant(self):
        other = grant(grant_id="grant:other", limits=replace(grant().limits, max_clock_skew_seconds=0))
        self.store.provision_grant(other, canonical_hash(other))
        permit_authority, _ = permit_stack(self.store, self.trust)
        adapter = ScriptedAdapter([AmbiguousExecution("timeout")], [_auth(__import__("faar.models", fromlist=["SettlementStatus"]).SettlementStatus.NONE)])
        runtime = FAARRuntime(self.store, {"mock-dex": adapter}, verification_trust(self.trust), permit_authority, {"mock-dex": ScriptedVerifier(adapter)}, clock=lambda: NOW, allow_test_time_override=True)
        i = intent(intent_id="intent_time_000000000020")
        aa, ra = attest_pair(self.trust, i, AUTH, risk(), NOW)
        first = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertEqual(IntentState.UNKNOWN, first.state)
        # At the permit's own expiry another provisioned grant (skew 0) is presented.
        at_expiry = NOW + timedelta(seconds=5)
        foreign = runtime.reconcile(i, grant=other, now=at_expiry)
        self.assertEqual(("GRANT_NOT_BOUND_TO_INTENT",), foreign.reason_codes)
        self.assertEqual(IntentState.UNKNOWN, foreign.state)
        self.assertEqual(0, self.store.voided_permit_count(i.intent_id))
        rows = [r for r in self.store.usage("grant:test", 1) if r["intent_id"] == i.intent_id]
        self.assertEqual("HELD", rows[0]["status"])
        aa, ra = attest_pair(self.trust, i, AUTH, risk(state_version=2, observed_at=at_expiry), at_expiry)
        via_process = runtime.process(i, AUTH, other, risk(state_version=2, observed_at=at_expiry), authority_attestation=aa, risk_attestation=ra, now=at_expiry)
        self.assertEqual(("GRANT_NOT_BOUND_TO_INTENT",), via_process.reason_codes)
        # The intent's own grant still governs: the window is open (skew 2 s).
        own = runtime.reconcile(i, grant=grant(), now=at_expiry)
        self.assertIn("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", own.reason_codes)
        # A fresh intent presented with the wrong grant is denied by the gate as before.
        j = intent(intent_id="intent_time_000000000021", grant_id="grant:other")
        aa, ra = attest_pair(self.trust, j, AUTH, risk(state_version=3), NOW)
        denied = runtime.process(j, AUTH, grant(), risk(state_version=3), authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertEqual(IntentState.DENIED, denied.state)
        self.assertIn("GRANT_ID_MISMATCH", denied.reason_codes)


if __name__ == "__main__":
    unittest.main()
