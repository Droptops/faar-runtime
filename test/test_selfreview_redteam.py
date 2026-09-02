"""Adversarial self-review of the RT-91..RT-116 fixes (RT-117..RT-127).

An identity claim that is atomic with the budget release, windows scoped to the
principal that owns the grant id, an anchor that is repaired on re-run and on
open, stops that commit under an unreadable anchor with a machine-readable
"committed" flag, an instance-bound lease token with a bounded release, a precise
born-with-head watermark, bounded authority reason codes, a bounded outcome
evaluation, limit prices that only bound limit orders, a mandatory slippage cap for
trade grants, and read-only store opens for operator commands.
"""
from __future__ import annotations

import io
import json
import os
import sqlite3
import threading
import time
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from unittest import mock

from faar import cli
from faar.anchor import AnchorUnavailable, AnchorUnavailableAfterCommit, InMemoryAuthorityAnchor
from faar.canonical import canonical_hash
from faar.gates import evaluate_capability
from faar.models import (
    AuthorityDecision, AuthorityPosture, AuthorityPrimitive, EconomicPrimitive, ExecutionReceipt, IntentState,
    OutcomeCriterion, OutcomeVerdict, SettlementRecord, SettlementStatus, TaskContract, Verdict,
)
from faar.outcomes import verify_task_outcome
from faar.parsing import parse_grant
from faar.runtime import FAARRuntime
from faar.store import EvidenceIntegrityError, SQLiteIntentStore, StoreUnavailable
from support import AUTH, NOW, PRINCIPAL, attest_pair, grant, intent, permit_stack, risk, temp_path, trust, verification_trust
from test_runtime_hardening import ScriptedAdapter, ScriptedVerifier, _auth

RECEIPT = ExecutionReceipt("order-1", SettlementStatus.PARTIALLY_FILLED, {"venue": "mock-dex"}, Decimal("20"))


class FlakyAnchor(InMemoryAuthorityAnchor):
    """In-memory anchor whose writes or reads can be made to fail on demand."""

    fail_record = False
    unreadable = False

    def record(self, grant_id, version, epoch, fence):
        if self.fail_record or self.unreadable:
            raise AnchorUnavailable("anchor volume unreachable (simulated)")
        super().record(grant_id, version, epoch, fence)

    def reset(self, grant_id, version, epoch, fence):
        if self.unreadable:
            raise AnchorUnavailable("anchor unreadable (simulated)")
        super().reset(grant_id, version, epoch, fence)

    def high_water(self, grant_id, version):
        if self.unreadable:
            raise AnchorUnavailable("anchor unreadable (simulated)")
        return super().high_water(grant_id, version)


class _Case(unittest.TestCase):
    def setUp(self):
        self.path = temp_path(self)
        self.store = SQLiteIntentStore(self.path, evidence_key=b"evidence-test-key-32-bytes-long!!!!")
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))
        self.n = 0

    def tearDown(self):
        self.store.close()

    def runtime_for(self, adapter):
        permit_authority, _ = permit_stack(self.store, self.trust)
        return FAARRuntime(
            self.store, {"mock-dex": adapter}, verification_trust(self.trust), permit_authority,
            {"mock-dex": ScriptedVerifier(adapter)}, clock=lambda: NOW, allow_test_time_override=True,
        )

    def run_case(self, runtime, i, g=None, now=NOW):
        g = g or grant()
        self.n += 1
        rs = risk(state_version=self.n, observed_at=now)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, now)
        return runtime.process(i, AUTH, g, rs, authority_attestation=aa, risk_attestation=ra, now=now)

    def usage_status(self, intent_id, grant_id="grant:test", version=1):
        rows = [r for r in self.store.usage(grant_id, version) if r["intent_id"] == intent_id]
        return rows[0]["status"] if rows else None


class AtomicIdentityClaimTests(_Case):
    def test_unfilled_cancel_release_cannot_be_overtaken_by_a_concurrent_claim(self):
        owner = intent(intent_id="intent_race_0000000000001")
        victim = intent(intent_id="intent_race_0000000000002")
        self.store.register(owner, canonical_hash(owner))
        for src, dst in ((IntentState.PROPOSED, IntentState.AUTHORIZED), (IntentState.AUTHORIZED, IntentState.RESERVED), (IntentState.RESERVED, IntentState.RECONCILING)):
            self.assertTrue(self.store.transition(owner.intent_id, src, dst))
        adapter = ScriptedAdapter([RECEIPT], [_auth(SettlementStatus.CANCELLED, "fx-shared", None)])
        runtime = self.runtime_for(adapter)
        original = self.store.void_unconsumed_permits
        state = {"claimed": False}

        def void_then_lose_the_race(intent_id):
            count = original(intent_id)
            if intent_id == victim.intent_id and not state["claimed"]:
                # Between the victim's last lookup and its release, another intent
                # binds the same order identity at this venue.
                state["claimed"] = True
                self.store.transition(owner.intent_id, IntentState.RECONCILING, IntentState.CONFIRMED, effect_id="fx-shared")
            return count

        self.store.void_unconsumed_permits = void_then_lose_the_race
        result = self.run_case(runtime, victim)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertEqual(("EFFECT_ID_ALREADY_CLAIMED",), result.reason_codes)
        self.assertEqual("HELD", self.usage_status(victim.intent_id))
        self.assertIsNone(self.store.get(victim.intent_id).effect_id)
        self.assertEqual(owner.intent_id, self.store.effect_owner("mock-dex", "fx-shared"))


class PrincipalScopedWindowsTests(_Case):
    def test_windows_are_per_principal_and_grant_id_and_count_legacy_rows(self):
        limits = replace(grant().limits, max_daily_turnover_usd=Decimal("100"), max_actions_per_window=1, action_window_seconds=3600)
        mine = grant(grant_id="grant:shared", limits=limits)
        theirs = grant(grant_id="grant:shared", version=2, principal_id="principal:other", limits=limits)
        for g in (mine, theirs):
            self.store.provision_grant(g, canonical_hash(g))

        def reserve(iid, g, version, amount="75"):
            i = intent(
                intent_id=iid, principal_id=g.principal_id, grant_id=g.grant_id, grant_version=g.version,
                payload={**intent().payload, "amount_usd": amount},
            )
            self.store.register(i, canonical_hash(i))
            return self.store.reserve_usage(i, g, risk(state_version=version), NOW)

        self.assertTrue(reserve("intent_share_000000000001", mine, 1)[0])
        # Another principal sharing the grant id is not locked out by my usage.
        self.assertTrue(reserve("intent_share_000000000002", theirs, 1)[0])
        ok, reasons = reserve("intent_share_000000000003", mine, 2)
        self.assertFalse(ok)
        self.assertLessEqual({"ATOMIC_DAILY_TURNOVER_EXCEEDED", "ATOMIC_ACTION_VELOCITY_EXCEEDED"}, set(reasons))
        # Rows migrated without a principal count for every principal of the grant id.
        self.store._conn.execute(
            "INSERT INTO usage_reservations(intent_id,principal_id,grant_id,grant_version,day_key,velocity_bucket,velocity_ts,amount_usd,status,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            ("legacy_row_0000000000001", "legacy:unknown", "grant:shared", 1, NOW.date().isoformat(), 0, int(NOW.timestamp()), "50", "COMMITTED", NOW.isoformat(), NOW.isoformat()),
        )
        self.store._conn.commit()
        later = grant(grant_id="grant:shared", version=3, principal_id="principal:other", limits=replace(limits, max_actions_per_window=5))
        self.store.provision_grant(later, canonical_hash(later))
        ok, reasons = reserve("intent_share_000000000004", later, 1, amount="1")
        self.assertFalse(ok)
        self.assertIn("ATOMIC_DAILY_TURNOVER_EXCEEDED", reasons)


class AnchorRepairTests(unittest.TestCase):
    def test_a_stop_whose_anchor_write_failed_is_repaired_on_rerun_and_on_open(self):
        anchor = FlakyAnchor()
        path = temp_path(self)
        store = SQLiteIntentStore(path, authority_anchor=anchor)
        try:
            store.provision_grant(grant(), canonical_hash(grant()))
            second = grant(grant_id="grant:two")
            store.provision_grant(second, canonical_hash(second))
            anchor.fail_record = True
            with self.assertRaises(AnchorUnavailableAfterCommit):
                store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
            with self.assertRaises(AnchorUnavailableAfterCommit):
                store.set_grant_status(PRINCIPAL, "grant:two", 1, "PAUSED")
            rows = {r["grant_id"]: r for r in store.list_grants()}
            self.assertEqual(("REVOKED", 2), (rows["grant:test"]["runtime_status"], rows["grant:test"]["runtime_epoch"]))
            self.assertEqual((1, 0), anchor.high_water("grant:test", 1))
            self.assertTrue(rows["grant:test"]["anchor_behind"])
            anchor.fail_record = False
            # Re-running the same stop is not a no-op: it raises the mark.
            store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
            self.assertEqual((2, 0), anchor.high_water("grant:test", 1))
            self.assertFalse({r["grant_id"]: r for r in store.list_grants()}["grant:test"]["anchor_behind"])
            self.assertEqual((1, 0), anchor.high_water("grant:two", 1))
        finally:
            store.close()
        # The next anchored open repairs whatever is still behind.
        reopened = SQLiteIntentStore(path, authority_anchor=anchor)
        try:
            self.assertEqual((2, 0), anchor.high_water("grant:two", 1))
            # A pre-revoke backup restored over this database is now detected.
            reopened._conn.execute("UPDATE grants SET runtime_status='ACTIVE', runtime_epoch=1 WHERE grant_id='grant:test'")
            reopened._conn.commit()
            self.assertEqual("REGRESSED", reopened.get_grant_status(PRINCIPAL, "grant:test", 1))
        finally:
            reopened.close()

    def test_stops_commit_under_an_unreadable_anchor_and_loosening_does_not(self):
        anchor = FlakyAnchor()
        store = SQLiteIntentStore(temp_path(self), authority_anchor=anchor)
        try:
            store.provision_grant(grant(), canonical_hash(grant()))
            anchor.unreadable = True
            with self.assertRaises(AnchorUnavailableAfterCommit):
                store.set_grant_status(PRINCIPAL, "grant:test", 1, "PAUSED")
            self.assertEqual("PAUSED", store.list_grants()[0]["runtime_status"])
            with self.assertRaises(AnchorUnavailable) as ctx:
                store.set_grant_status(PRINCIPAL, "grant:test", 1, "ACTIVE")
            self.assertNotIsInstance(ctx.exception, AnchorUnavailableAfterCommit)
            self.assertEqual("PAUSED", store.list_grants()[0]["runtime_status"])
            with self.assertRaises(AnchorUnavailableAfterCommit):
                store.revoke_after_restore("grant:test", 1)
            self.assertEqual("REVOKED", store.list_grants()[0]["runtime_status"])
            anchor.unreadable = False
            self.assertEqual("REVOKED", store.get_grant_status(PRINCIPAL, "grant:test", 1))
        finally:
            store.close()

    def test_cli_reports_whether_a_stop_committed(self):
        anchor = FlakyAnchor()
        path = temp_path(self)
        store = SQLiteIntentStore(path, authority_anchor=anchor)
        store.provision_grant(grant(), canonical_hash(grant()))
        store.close()
        anchor.fail_record = True
        with mock.patch.object(cli, "FileAuthorityAnchor", lambda _path: anchor):
            buf = io.StringIO()
            with redirect_stdout(buf), self.assertRaises(SystemExit) as ctx:
                cli.main(["set-grant-status", "--principal-id", PRINCIPAL, "--grant-id", "grant:test", "--grant-version", "1", "--status", "PAUSED", "--db", path, "--anchor", "x"])
            self.assertEqual(2, ctx.exception.code)
            payload = json.loads(buf.getvalue())
            self.assertEqual(("AnchorUnavailableAfterCommit", True), (payload["error"], payload["committed"]))
            anchor.fail_record = False
            anchor.unreadable = True
            buf = io.StringIO()
            with redirect_stdout(buf), self.assertRaises(SystemExit):
                cli.main(["set-grant-status", "--principal-id", PRINCIPAL, "--grant-id", "grant:test", "--grant-version", "1", "--status", "ACTIVE", "--db", path, "--anchor", "x"])
            payload = json.loads(buf.getvalue())
            self.assertEqual(("AnchorUnavailable", False), (payload["error"], payload["committed"]))


class LeaseTokenTests(_Case):
    def test_any_thread_of_the_owning_instance_reacquires_its_lease(self):
        i = intent(intent_id="intent_lease_000000000001")
        self.store.register(i, canonical_hash(i))
        self.store._conn.execute(
            "INSERT INTO intent_leases(intent_id,owner_token,acquired_at,host,pid) VALUES(?,?,?,?,?)",
            (i.intent_id, self.store._instance_id, NOW.isoformat(), self.store._host, os.getpid()),
        )
        self.store._conn.commit()
        outcome = {}

        def worker():
            try:
                with self.store.intent_guard(i.intent_id, wait_seconds=0.5):
                    outcome["acquired"] = True
            except Exception as exc:  # pragma: no cover - reported through the assertion
                outcome["error"] = repr(exc)

        t = threading.Thread(target=worker)
        t.start()
        t.join(5)
        self.assertEqual({"acquired": True}, outcome)
        self.assertEqual([], self.store.list_leases())

    def test_release_wait_is_bounded_and_the_owner_recovers(self):
        i = intent(intent_id="intent_lease_000000000002")
        self.store.register(i, canonical_hash(i))
        other = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        started = time.monotonic()
        try:
            with self.assertRaises(StoreUnavailable):
                with self.store.intent_guard(i.intent_id):
                    other.execute("BEGIN IMMEDIATE")
                    other.execute("UPDATE store_settings SET value=value WHERE key='heads_since'")
        finally:
            other.execute("ROLLBACK")
            other.close()
        self.assertLess(time.monotonic() - started, 20.0, "a failed release must not wait attempts x busy_timeout")
        self.assertEqual(1, len(self.store.list_leases()))
        with self.store.intent_guard(i.intent_id, wait_seconds=0.5):
            pass
        self.assertEqual([], self.store.list_leases())


class HeadsSinceTests(unittest.TestCase):
    def test_databases_written_by_an_earlier_head_writing_build_are_not_legacy(self):
        path = temp_path(self)
        key = b"evidence-test-key-32-bytes-long!!!!"
        store = SQLiteIntentStore(path, evidence_key=key)
        tampered, intact = intent(intent_id="intent_heads_000000000001"), intent(intent_id="intent_heads_000000000002")
        for i in (tampered, intact):
            store.register(i, canonical_hash(i))
            store.add_evidence(i.intent_id, "authorized", {"n": 1})
        store.close()
        conn = sqlite3.connect(path)
        # A build that wrote signed heads but never recorded the watermark.
        conn.execute("DELETE FROM store_settings WHERE key IN ('heads_since','schema_revision')")
        conn.execute("DELETE FROM evidence_head WHERE intent_id=?", (tampered.intent_id,))
        conn.execute("DELETE FROM evidence WHERE intent_id=? AND event_type='authorized'", (tampered.intent_id,))
        conn.commit()
        conn.close()
        reopened = SQLiteIntentStore(path, evidence_key=key)
        try:
            self.assertEqual("head_deleted", reopened.evidence_status(tampered.intent_id)["status"])
            with self.assertRaises(EvidenceIntegrityError):
                reopened.rebuild_evidence_head(tampered.intent_id)
            self.assertEqual("ok", reopened.evidence_status(intact.intent_id)["status"])
        finally:
            reopened.close()


class BoundedAuthorityAndOutcomeTests(unittest.TestCase):
    def test_authority_reason_codes_are_bounded_at_construction(self):
        AuthorityDecision(AuthorityPosture.STOP, AuthorityPrimitive.EXECUTE_ACTION, tuple(f"CODE_{n}" for n in range(64)))
        with self.assertRaises(ValueError):
            AuthorityDecision(AuthorityPosture.STOP, AuthorityPrimitive.EXECUTE_ACTION, tuple(f"CODE_{n}" for n in range(65)))
        with self.assertRaises(ValueError):
            AuthorityDecision(AuthorityPosture.STOP, AuthorityPrimitive.EXECUTE_ACTION, ("x" * 257,))
        with self.assertRaises(ValueError):
            AuthorityDecision(AuthorityPosture.STOP, AuthorityPrimitive.EXECUTE_ACTION, (123,))  # type: ignore[arg-type]

    def test_an_outcome_evaluation_past_the_budget_is_not_done(self):
        evidence = {"a": {"big": ["x" * 8000] * 7}}
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED, effect_id="fx-1", amount_usd=Decimal("50"), evidence=evidence, authoritative=True,
            verified_request_hash=canonical_hash({"request": 1}),
        )
        overlapping = (OutcomeCriterion("a", "present"), OutcomeCriterion("a.big", "present"))
        met = verify_task_outcome(TaskContract("task-b", "intent_test_000000000001", "bounded", overlapping, NOW, NOW + timedelta(hours=1)), settlement)
        self.assertEqual((OutcomeVerdict.UNKNOWN, ("OUTCOME_EVALUATION_UNBOUNDED",)), (met.verdict, met.reason_codes))
        failing = overlapping + (OutcomeCriterion("status", "eq", "NOPE"),)
        not_met = verify_task_outcome(TaskContract("task-c", "intent_test_000000000001", "bounded", failing, NOW, NOW + timedelta(hours=1)), settlement)
        self.assertEqual(OutcomeVerdict.NOT_MET, not_met.verdict)
        self.assertIn("OUTCOME_EVALUATION_UNBOUNDED", not_met.reason_codes)
        self.assertTrue(any(r.startswith("OUTCOME_CRITERION_FAILED") for r in not_met.reason_codes))
        small = verify_task_outcome(TaskContract("task-d", "intent_test_000000000001", "bounded", (OutcomeCriterion("effect_id", "present"),), NOW, NOW + timedelta(hours=1)), settlement)
        self.assertEqual(OutcomeVerdict.MET, small.verdict)


class TradeGrantsRequireSlippageCapTests(unittest.TestCase):
    def test_a_trade_grant_cannot_omit_the_cap(self):
        for primitive in (EconomicPrimitive.SWAP, EconomicPrimitive.BUY, EconomicPrimitive.SELL, EconomicPrimitive.PLACE_ORDER):
            with self.assertRaisesRegex(ValueError, "max_slippage_bps"):
                grant(allowed_primitives=frozenset({primitive}), limits=replace(grant().limits, max_slippage_bps=None))
        doc = {
            "schema_version": "0.3", "principal_id": "p", "grant_id": "g", "version": 1, "actor_id": "a", "status": "ACTIVE",
            "allowed_primitives": ["SWAP"], "allowed_venues": ["v"], "allowed_assets": ["USDC", "MEME"], "allowed_targets": ["r"],
            "limits": {"max_order_usd": "75", "max_daily_turnover_usd": "1500", "max_actions_per_window": 10, "action_window_seconds": 60},
        }
        with self.assertRaisesRegex(ValueError, "max_slippage_bps"):
            parse_grant(doc)
        parse_grant({**doc, "limits": {**doc["limits"], "max_slippage_bps": 50}})
        # Payment-only grants have no slippage concept.
        grant(allowed_primitives=frozenset({EconomicPrimitive.PAY}), limits=replace(grant().limits, max_slippage_bps=None))

    def test_a_limit_price_only_bounds_a_declared_limit_order(self):
        g = grant(allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_assets=frozenset({"BTC", "USD"}))
        base = {"base_asset": "BTC", "quote_asset": "USD", "notional_usd": "10", "target": "router:approved", "limit_price": "60000"}
        self.assertIn("PAYLOAD_FIELD_REQUIRED:max_slippage_bps", evaluate_capability(intent(primitive=EconomicPrimitive.BUY, payload=base), g, NOW).reason_codes)
        self.assertIn("PAYLOAD_FIELD_REQUIRED:max_slippage_bps", evaluate_capability(intent(primitive=EconomicPrimitive.BUY, payload={**base, "order_type": "market"}), g, NOW).reason_codes)
        self.assertEqual(Verdict.ALLOW, evaluate_capability(intent(primitive=EconomicPrimitive.BUY, payload={**base, "order_type": "LIMIT"}), g, NOW).verdict)


class ReadOnlyOpenTests(unittest.TestCase):
    def test_operator_reads_do_not_need_the_write_lock(self):
        path = temp_path(self)
        store = SQLiteIntentStore(path)
        store.provision_grant(grant(), canonical_hash(grant()))
        store.close()
        other = sqlite3.connect(path, isolation_level=None)
        other.execute("BEGIN IMMEDIATE")
        other.execute("UPDATE store_settings SET value=value WHERE key='heads_since'")
        started = time.monotonic()
        try:
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli.main(["list-leases", "--db", path])
            self.assertEqual([], json.loads(buf.getvalue()))
            self.assertLess(time.monotonic() - started, 10.0, "an up-to-date database opens without a write transaction")
        finally:
            other.execute("ROLLBACK")
            other.close()

    def test_a_busy_datastore_is_a_typed_refusal_for_the_cli(self):
        path = temp_path(self)
        store = SQLiteIntentStore(path)
        store.provision_grant(grant(), canonical_hash(grant()))
        store.close()
        with mock.patch("faar.cli.SQLiteIntentStore", side_effect=sqlite3.OperationalError("database is locked")):
            buf = io.StringIO()
            with redirect_stdout(buf), self.assertRaises(SystemExit) as ctx:
                cli.main(["list-leases", "--db", path])
        self.assertEqual(2, ctx.exception.code)
        self.assertEqual("StoreUnavailable", json.loads(buf.getvalue())["error"])


if __name__ == "__main__":
    unittest.main()
