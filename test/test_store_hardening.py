from __future__ import annotations

import multiprocessing as mp
import sqlite3
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from faar.canonical import canonical_hash
from faar.models import EconomicPrimitive, IntentState
from faar.store import EffectConflict, EvidenceIntegrityError, IntentBusy, SQLiteIntentStore
from support import NOW, PRINCIPAL, grant, intent, risk

EVIDENCE_KEY = b"evidence-test-key-32-bytes-long!!!!!"


def _tmp_db() -> str:
    f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    f.close()
    return f.name


def _open_worker(path, barrier, queue):
    try:
        barrier.wait()
        store = SQLiteIntentStore(path)
        store.close()
        queue.put("ok")
    except Exception as exc:  # report, never hang the parent
        queue.put(f"{type(exc).__name__}: {exc}")


class SchemaMigrationTests(unittest.TestCase):
    def _make_legacy(self, path: str) -> None:
        """Downgrade a fresh database to the v0.3.0 shape (no velocity_ts column)."""
        store = SQLiteIntentStore(path)
        g = grant(limits=replace(grant().limits, max_daily_turnover_usd=Decimal("75")))
        store.provision_grant(g, canonical_hash(g))
        store.close()
        conn = sqlite3.connect(path)
        conn.execute("DROP INDEX IF EXISTS ix_usage_grant_velocity_ts")
        conn.execute("ALTER TABLE usage_reservations DROP COLUMN velocity_ts")
        conn.execute("ALTER TABLE execution_permits DROP COLUMN consumed_at")
        # A HELD reservation written by the old version: calendar-day keyed only.
        conn.execute(
            "INSERT INTO usage_reservations(intent_id,principal_id,grant_id,grant_version,day_key,velocity_bucket,amount_usd,status,created_at,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("legacy_held_000000000001", PRINCIPAL, "grant:test", 1, NOW.date().isoformat(), 0, "50", "HELD", "x", "x"),
        )
        conn.commit()
        conn.close()

    def setUp(self):
        if sqlite3.sqlite_version_info < (3, 35, 0):
            self.skipTest("ALTER TABLE DROP COLUMN requires SQLite >= 3.35")

    def test_v030_database_opens_migrates_and_still_counts_legacy_holds(self):
        path = _tmp_db()
        self._make_legacy(path)
        store = SQLiteIntentStore(path)  # v0.3.1 raised OperationalError here
        try:
            cols = {r[1] for r in store._conn.execute("PRAGMA table_info(usage_reservations)")}
            self.assertIn("velocity_ts", cols)
            g = grant(limits=replace(grant().limits, max_daily_turnover_usd=Decimal("75")))
            i = intent(intent_id="post_upgrade_00000000001")
            store.register(i, canonical_hash(i))
            ok, reasons = store.reserve_usage(i, g, risk(), NOW)
            self.assertFalse(ok, "legacy HELD row must still count against turnover after upgrade")
            self.assertIn("ATOMIC_DAILY_TURNOVER_EXCEEDED", reasons)
        finally:
            store.close()

    def test_concurrent_open_of_legacy_database_migrates_cleanly(self):
        path = _tmp_db()
        self._make_legacy(path)
        ctx = mp.get_context("spawn")
        barrier = ctx.Barrier(4)
        queue = ctx.Queue()
        procs = [ctx.Process(target=_open_worker, args=(path, barrier, queue)) for _ in range(4)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(30)
        results = [queue.get(timeout=5) for _ in procs]
        self.assertEqual(["ok"] * 4, results)


class TurnoverWindowTests(unittest.TestCase):
    def test_turnover_limit_is_trailing_window_not_calendar_day(self):
        store = SQLiteIntentStore(":memory:")
        g = grant(limits=replace(grant().limits, max_daily_turnover_usd=Decimal("75")))
        store.provision_grant(g, canonical_hash(g))
        t0 = datetime(2026, 9, 1, 23, 59, 59, tzinfo=timezone.utc)
        t1 = t0 + timedelta(seconds=2)            # across UTC midnight
        t2 = t0 + timedelta(hours=24, seconds=1)  # legitimately outside the window
        ids = ["turn_000000000000000001", "turn_000000000000000002", "turn_000000000000000003"]
        for n, iid in enumerate(ids):
            i = intent(intent_id=iid)
            store.register(i, canonical_hash(i))
        ok0, _ = store.reserve_usage(intent(intent_id=ids[0]), g, risk(state_version=1), t0)
        ok1, reasons1 = store.reserve_usage(intent(intent_id=ids[1]), g, risk(state_version=2), t1)
        ok2, _ = store.reserve_usage(intent(intent_id=ids[2]), g, risk(state_version=3), t2)
        self.assertTrue(ok0)
        self.assertFalse(ok1, "a calendar-day bucket would admit 2x the cap across midnight")
        self.assertIn("ATOMIC_DAILY_TURNOVER_EXCEEDED", reasons1)
        self.assertTrue(ok2)


class ReservationIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(":memory:")
        self.g = grant(allowed_primitives=frozenset({EconomicPrimitive.SWAP, EconomicPrimitive.CANCEL_ORDER}))
        self.store.provision_grant(self.g, canonical_hash(self.g))

    def test_invalid_monetary_amount_cannot_reserve_zero(self):
        for n, bad in enumerate(["NaN", "-500", "abc", "Infinity", None, True]):
            payload = dict(intent().payload)
            if bad is None:
                payload.pop("amount_usd")
            else:
                payload["amount_usd"] = bad
            i = intent(intent_id=f"bad_amount_00000000000{n}", payload=payload)
            self.store.register(i, canonical_hash(i))
            ok, reasons = self.store.reserve_usage(i, self.g, risk(state_version=n + 1), NOW)
            self.assertFalse(ok, f"{bad!r} must not create a zero-cost reservation")
            self.assertIn("USAGE_AMOUNT_INVALID", reasons)
        self.assertEqual([], [r for r in self.store.usage("grant:test", 1)])

    def test_non_monetary_primitive_reserves_velocity_only(self):
        i = intent(
            intent_id="cancel_only_00000000001", primitive=EconomicPrimitive.CANCEL_ORDER,
            payload={"order_id": "order-1", "target": "router:approved"},
        )
        self.store.register(i, canonical_hash(i))
        ok, reasons = self.store.reserve_usage(i, self.g, risk(), NOW)
        self.assertTrue(ok, reasons)
        self.assertEqual("0", self.store.usage("grant:test", 1)[0]["amount_usd"])

    def test_monotonic_ceiling_spans_initial_and_permit_ledgers(self):
        a = intent(intent_id="ledger_a_000000000000001")
        b = intent(intent_id="ledger_b_000000000000001")
        for i in (a, b):
            self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(a, self.g, risk(state_version=5), NOW)[0])
        claimed, _ = self.store.claim_permit_risk_state(a, self.g, risk(state_version=7))
        self.assertTrue(claimed)
        ok, reasons = self.store.reserve_usage(b, self.g, risk(state_version=6), NOW)
        self.assertFalse(ok, "a version older than one already consumed by a retry is stale")
        self.assertIn("RISK_STATE_VERSION_NOT_MONOTONIC", reasons)

    def test_transition_can_release_usage_in_the_same_transaction(self):
        i = intent(intent_id="atomic_rel_00000000000001")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, self.g, risk(), NOW)[0])
        self.assertTrue(self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.STOPPED, reason_codes=("X",), release_usage=True))
        self.assertEqual("RELEASED", self.store.usage("grant:test", 1)[0]["status"])


class EffectIdentityScopeTests(unittest.TestCase):
    def _finalize(self, store, iid, venue, effect_id):
        i = intent(intent_id=iid, venue=venue)
        store.register(i, canonical_hash(i))
        store.transition(iid, IntentState.PROPOSED, IntentState.AUTHORIZED)
        store.transition(iid, IntentState.AUTHORIZED, IntentState.RESERVED)
        store.transition(iid, IntentState.RESERVED, IntentState.RECONCILING)
        store.transition(iid, IntentState.RECONCILING, IntentState.FINALIZED, effect_id=effect_id)

    def test_effect_identity_is_unique_per_venue(self):
        store = SQLiteIntentStore(":memory:")
        self._finalize(store, "fx_scope_0000000000001", "venue-a", "12345")
        # A different venue's identifier namespace may legitimately reuse the string.
        self._finalize(store, "fx_scope_0000000000002", "venue-b", "12345")
        # The same venue reporting one effect for two intents is still a conflict.
        with self.assertRaises(EffectConflict):
            self._finalize(store, "fx_scope_0000000000003", "venue-a", "12345")

    def test_transition_rejects_non_string_effect_id(self):
        store = SQLiteIntentStore(":memory:")
        i = intent(intent_id="fx_type_00000000000001")
        store.register(i, canonical_hash(i))
        with self.assertRaises(ValueError):
            store.transition(i.intent_id, IntentState.PROPOSED, IntentState.STOPPED, effect_id=b"bytes")  # type: ignore[arg-type]


class GuardAndFenceTests(unittest.TestCase):
    def test_intent_guard_wait_bound_applies_to_in_process_contention(self):
        store = SQLiteIntentStore(":memory:")
        i = intent(intent_id="guard_wait_00000000000001")
        store.register(i, canonical_hash(i))
        entered = threading.Event()
        release = threading.Event()

        def holder():
            with store.intent_guard(i.intent_id):
                entered.set()
                release.wait(5)

        t = threading.Thread(target=holder)
        t.start()
        self.assertTrue(entered.wait(2))
        started = time.monotonic()
        with self.assertRaises(IntentBusy):
            with store.intent_guard(i.intent_id, wait_seconds=0.05):
                pass
        self.assertLess(time.monotonic() - started, 1.0, "wait_seconds must bound in-process waiting too")
        release.set()
        t.join(5)
        # Reference-counted lock registry is pruned once nobody holds or waits.
        self.assertEqual({}, store._intent_locks)

    def test_execution_fence_is_shared_by_store_instances_on_the_same_file(self):
        path = _tmp_db()
        a = SQLiteIntentStore(path)
        b = SQLiteIntentStore(path)
        g = grant()
        a.provision_grant(g, canonical_hash(g))
        entered = threading.Event()
        release = threading.Event()

        def in_flight():
            with a.execution_guard(g.grant_id, g.version):
                entered.set()
                release.wait(5)

        t = threading.Thread(target=in_flight)
        t.start()
        self.assertTrue(entered.wait(2))
        revoked = threading.Event()

        def revoke():
            b.set_grant_status(g.principal_id, g.grant_id, g.version, "REVOKED")
            revoked.set()

        r = threading.Thread(target=revoke)
        r.start()
        self.assertFalse(revoked.wait(0.3), "revocation through a second instance must wait for the in-flight fence")
        release.set()
        self.assertTrue(revoked.wait(5))
        t.join(5); r.join(5)
        self.assertEqual("REVOKED", a.get_grant_status(g.principal_id, g.grant_id, g.version))
        a.close(); b.close()


class EvidenceIntegrityTests(unittest.TestCase):
    def _seed(self, key, iid="evi_hard_00000000000001", events=3):
        store = SQLiteIntentStore(":memory:", evidence_key=key)
        i = intent(intent_id=iid)
        store.register(i, canonical_hash(i))
        for n in range(events):
            store.add_evidence(iid, f"event_{n}", {"n": n})
        return store, iid

    def test_append_after_tail_truncation_fails_closed_instead_of_healing(self):
        store, iid = self._seed(EVIDENCE_KEY)
        store._conn.execute(
            "DELETE FROM evidence WHERE id IN (SELECT id FROM evidence WHERE intent_id=? ORDER BY id DESC LIMIT 2)", (iid,)
        )
        self.assertFalse(store.verify_evidence_chain(iid))
        with self.assertRaises(EvidenceIntegrityError):
            store.add_evidence(iid, "later", {})
        self.assertFalse(store.verify_evidence_chain(iid), "a refused append must not re-commit the head")

    def test_unknown_intent_and_deleted_chain_are_invalid(self):
        for key in (EVIDENCE_KEY, None):
            store, iid = self._seed(key)
            self.assertFalse(store.verify_evidence_chain("intent_does_not_exist_01"))
        store, iid = self._seed(EVIDENCE_KEY)
        store._conn.execute("DELETE FROM evidence WHERE intent_id=?", (iid,))
        store._conn.execute("DELETE FROM evidence_head WHERE intent_id=?", (iid,))
        self.assertFalse(store.verify_evidence_chain(iid), "an existing intent with no chain is deletion, not emptiness")

    def test_registration_starts_the_chain_atomically(self):
        store, iid = self._seed(EVIDENCE_KEY, events=0)
        events = store.evidence(iid)
        self.assertEqual(["intent_registered"], [e["event_type"] for e in events])
        self.assertTrue(store.verify_evidence_chain(iid))

    def test_rebuild_head_only_for_verified_legacy_chains(self):
        store, iid = self._seed(EVIDENCE_KEY)
        store._conn.execute("DELETE FROM evidence_head WHERE intent_id=?", (iid,))  # pre-head database shape
        with self.assertRaises(EvidenceIntegrityError):
            store.add_evidence(iid, "blocked", {})
        self.assertTrue(store.rebuild_evidence_head(iid))
        self.assertFalse(store.rebuild_evidence_head(iid), "idempotent once a head exists")
        store.add_evidence(iid, "after_rebuild", {})
        self.assertTrue(store.verify_evidence_chain(iid))

        tampered = "evi_hard_00000000000002"
        i = intent(intent_id=tampered)
        store.register(i, canonical_hash(i))
        store.add_evidence(tampered, "x", {"v": 1})
        store._conn.execute("DELETE FROM evidence_head WHERE intent_id=?", (tampered,))
        store._conn.execute("UPDATE evidence SET payload_json='{\"v\":2}' WHERE intent_id=? AND event_type='x'", (tampered,))
        with self.assertRaises(EvidenceIntegrityError):
            store.rebuild_evidence_head(tampered)

    def test_verifier_has_no_false_negatives_under_concurrent_appends(self):
        store, iid = self._seed(EVIDENCE_KEY)
        stop = threading.Event()
        failures: list[BaseException] = []

        def writer():
            n = 0
            try:
                while not stop.is_set() and n < 400:
                    store.add_evidence(iid, "tick", {"n": n})
                    n += 1
            except BaseException as exc:  # pragma: no cover - surfaced via assertion
                failures.append(exc)

        t = threading.Thread(target=writer)
        t.start()
        results = [store.verify_evidence_chain(iid) for _ in range(200)]
        stop.set()
        t.join(10)
        self.assertEqual([], failures)
        self.assertTrue(all(results), f"{results.count(False)} spurious tamper alarms under concurrent appends")


if __name__ == "__main__":
    unittest.main()
