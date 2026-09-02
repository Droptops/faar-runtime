from __future__ import annotations

import multiprocessing as mp
import sqlite3
import threading
import time
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from faar.canonical import canonical_hash
from faar.models import EconomicPrimitive, IntentState
from faar.store import EffectConflict, EvidenceIntegrityError, IntentBusy, MigrationError, SQLiteIntentStore
from support import AUTH, NOW, PRINCIPAL, attest_pair, build_mock_runtime, grant, intent, risk, temp_path, trust

EVIDENCE_KEY = b"evidence-test-key-32-bytes-long!!!!!"


def _open_worker(path, barrier, queue):
    try:
        barrier.wait()
        store = SQLiteIntentStore(path)
        store.close()
        queue.put("ok")
    except Exception as exc:  # report, never hang the parent
        queue.put(f"{type(exc).__name__}: {exc}")


class SchemaMigrationTests(unittest.TestCase):
    LEGACY_EFFECT = "fx_legacy_000000000000001"
    LEGACY_FINAL = "legacy_final_00000000001"
    LEGACY_INFLIGHT = "legacy_inflight_000000001"
    LEGACY_UPDATED_AT = (NOW - timedelta(seconds=20)).isoformat()

    def _make_legacy(self, path: str, *, created_at: str | None = None) -> None:
        """Downgrade a fresh database to the v0.3.0 shape.

        No `velocity_ts`, `consumed_at`, `expires_at`, `venue` or `ambiguity_until`
        columns, the global effect-id index, and rows an old worker would have left
        behind: a FINALIZED intent with an effect id, an in-flight UNKNOWN intent,
        and HELD reservations keyed by calendar day only.
        """
        store = SQLiteIntentStore(path)
        g = grant(limits=replace(grant().limits, max_daily_turnover_usd=Decimal("75")))
        store.provision_grant(g, canonical_hash(g))
        for iid in (self.LEGACY_FINAL, self.LEGACY_INFLIGHT):
            i = intent(intent_id=iid)
            store.register(i, canonical_hash(i))
        store.close()
        conn = sqlite3.connect(path)
        conn.execute("DROP INDEX IF EXISTS ix_usage_grant_velocity_ts")
        conn.execute("DROP INDEX IF EXISTS ix_usage_principal_velocity_ts")
        conn.execute("DROP INDEX IF EXISTS ux_effect_id_per_venue")
        conn.execute("DROP TABLE IF EXISTS exposure_caps")
        conn.execute("ALTER TABLE usage_reservations DROP COLUMN velocity_ts")
        conn.execute("ALTER TABLE execution_permits DROP COLUMN consumed_at")
        conn.execute("ALTER TABLE execution_permits DROP COLUMN expires_at")
        conn.execute("ALTER TABLE intents DROP COLUMN venue")
        conn.execute("ALTER TABLE intents DROP COLUMN ambiguity_until")
        conn.execute("DROP TABLE store_settings")
        conn.execute("CREATE UNIQUE INDEX ux_effect_id_nonnull ON intents(effect_id) WHERE effect_id IS NOT NULL")
        conn.execute(
            "UPDATE intents SET state='FINALIZED', effect_id=?, submission_count=1, updated_at=? WHERE intent_id=?",
            (self.LEGACY_EFFECT, self.LEGACY_UPDATED_AT, self.LEGACY_FINAL),
        )
        conn.execute(
            "UPDATE intents SET state='UNKNOWN', reason_codes='[\"SETTLEMENT_UNKNOWN\"]', submission_count=1, updated_at=? WHERE intent_id=?",
            (self.LEGACY_UPDATED_AT, self.LEGACY_INFLIGHT),
        )
        # The in-flight legacy attempt holds a permit whose expiry 0.3.x never stored.
        conn.execute(
            "INSERT INTO execution_permits(permit_id,intent_id,principal_id,grant_id,grant_version,grant_epoch,fence_token,permit_hash,issued_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            ("permit_legacy_1", self.LEGACY_INFLIGHT, PRINCIPAL, "grant:test", 1, 1, 1, "h", self.LEGACY_UPDATED_AT),
        )
        stamp = created_at if created_at is not None else (NOW - timedelta(seconds=30)).isoformat()
        for iid, amount in (("legacy_held_000000000001", "50"), ("legacy_held_000000000002", "20")):
            conn.execute(
                "INSERT INTO usage_reservations(intent_id,principal_id,grant_id,grant_version,day_key,velocity_bucket,amount_usd,status,created_at,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (iid, PRINCIPAL, "grant:test", 1, NOW.date().isoformat(), 0, amount, "HELD", stamp, stamp),
            )
        conn.commit()
        conn.close()

    def setUp(self):
        if sqlite3.sqlite_version_info < (3, 35, 0):
            self.skipTest("ALTER TABLE DROP COLUMN requires SQLite >= 3.35")

    def _walk_to_reconciling(self, store, i):
        store.register(i, canonical_hash(i))
        self.assertTrue(store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED))
        self.assertTrue(store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED))
        self.assertTrue(store.transition(i.intent_id, IntentState.RESERVED, IntentState.RECONCILING))

    def test_v030_database_opens_migrates_and_still_counts_legacy_holds(self):
        path = temp_path(self)
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

    def test_legacy_effect_ids_stay_bound_to_their_venue_after_upgrade(self):
        # The per-venue effect-id index only protects rows in their real venue
        # namespace; without the backfill every legacy effect would be claimable
        # again by a new intent at the same venue (I-11).
        path = temp_path(self)
        self._make_legacy(path)
        store = SQLiteIntentStore(path)
        try:
            venues = {r[0]: r[1] for r in store._conn.execute("SELECT intent_id, venue FROM intents")}
            self.assertEqual("mock-dex", venues[self.LEGACY_FINAL])
            same_venue = intent(intent_id="post_upgrade_00000000002")
            self._walk_to_reconciling(store, same_venue)
            with self.assertRaises(EffectConflict):
                store.transition(same_venue.intent_id, IntentState.RECONCILING, IntentState.FINALIZED, effect_id=self.LEGACY_EFFECT)
            other_venue = intent(intent_id="post_upgrade_00000000003", venue="other-dex")
            self._walk_to_reconciling(store, other_venue)
            self.assertTrue(store.transition(other_venue.intent_id, IntentState.RECONCILING, IntentState.FINALIZED, effect_id=self.LEGACY_EFFECT))
        finally:
            store.close()

    def test_legacy_reservations_count_toward_velocity_after_upgrade(self):
        path = temp_path(self)
        self._make_legacy(path)
        store = SQLiteIntentStore(path)
        try:
            g = grant(limits=replace(grant().limits, max_actions_per_window=2, max_daily_turnover_usd=Decimal("1500")))
            i = intent(intent_id="post_upgrade_00000000004")
            store.register(i, canonical_hash(i))
            ok, reasons = store.reserve_usage(i, g, risk(actions_in_window=0), NOW)
            self.assertFalse(ok, "two legacy actions inside the window must fill a limit of two")
            self.assertIn("ATOMIC_ACTION_VELOCITY_EXCEEDED", reasons)
            ok, _ = store.reserve_usage(i, g, risk(actions_in_window=0), NOW + timedelta(seconds=61))
            self.assertTrue(ok, "legacy actions age out of the window normally")
        finally:
            store.close()

    def test_legacy_in_flight_intent_gets_a_conservative_ambiguity_window(self):
        path = temp_path(self)
        self._make_legacy(path)
        store = SQLiteIntentStore(path)
        try:
            row = store.get(self.LEGACY_INFLIGHT)
            self.assertEqual(IntentState.UNKNOWN, row.state)
            expected = datetime.fromisoformat(self.LEGACY_UPDATED_AT) + timedelta(seconds=60)
            self.assertEqual(expected.isoformat(), row.ambiguity_until)
            self.assertIsNone(store.get(self.LEGACY_FINAL).ambiguity_until, "terminal rows get no window")
            # A row that never obtained a permit transported nothing: no window, so a
            # worker that crashed between begin_submission and the permit record is
            # retried as soon as absence is authoritative.
            i = intent(intent_id="post_upgrade_00000000009")
            store.register(i, canonical_hash(i))
            self.assertTrue(store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED))
            self.assertTrue(store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED))
            self.assertEqual((True, False, 1), store.begin_submission(i.intent_id, {IntentState.RESERVED}, max_attempts=2))
        finally:
            store.close()
        reopened = SQLiteIntentStore(path)
        try:
            self.assertEqual(IntentState.SUBMITTED, reopened.get("post_upgrade_00000000009").state)
            self.assertIsNone(reopened.get("post_upgrade_00000000009").ambiguity_until)
        finally:
            reopened.close()

    def test_unreadable_legacy_timestamp_fails_closed(self):
        path = temp_path(self)
        self._make_legacy(path, created_at="not-a-timestamp")
        with self.assertRaises(MigrationError):
            SQLiteIntentStore(path)

    def test_concurrent_open_of_legacy_database_migrates_cleanly(self):
        path = temp_path(self)
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
        path = temp_path(self)
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


class LegacyChainTests(unittest.TestCase):
    """Keyed 0.4 store over chains written before signed heads existed."""

    def _keyed(self):
        path = temp_path(self)
        store = SQLiteIntentStore(path, evidence_key=EVIDENCE_KEY)
        store.provision_grant(grant(), canonical_hash(grant()))
        return path, store

    @staticmethod
    def _drop_heads(path, *, empty_intent=None):
        conn = sqlite3.connect(path)
        conn.execute("DELETE FROM evidence_head")
        if empty_intent is not None:
            conn.execute("DELETE FROM evidence WHERE intent_id=?", (empty_intent,))
        conn.commit()
        conn.close()

    def test_runtime_does_not_advance_state_on_a_chain_it_cannot_extend(self):
        path, store = self._keyed()
        t = trust()
        i = intent(intent_id="legacy_chain_000000000001")
        store.register(i, canonical_hash(i))
        self.assertTrue(store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.assertTrue(store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED))
        self.assertTrue(store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED))
        store.close()
        self._drop_heads(path)

        reopened = SQLiteIntentStore(path, evidence_key=EVIDENCE_KEY)
        try:
            self.assertEqual("head_missing", reopened.evidence_status(i.intent_id)["status"])
            runtime, venue, *_ = build_mock_runtime(reopened, t)
            aa, ra = attest_pair(t, i, AUTH, risk(), NOW)
            events_before = len(reopened.evidence(i.intent_id))
            result = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW)
            self.assertEqual(("EVIDENCE_INTEGRITY_FAILURE",), result.reason_codes)
            self.assertEqual(IntentState.RESERVED, result.state, "no transition without evidence")
            self.assertEqual(IntentState.RESERVED, reopened.get(i.intent_id).state)
            self.assertEqual(events_before, len(reopened.evidence(i.intent_id)))
            self.assertEqual(0, venue.execute_call_count(i.intent_id))
            self.assertEqual(("EVIDENCE_INTEGRITY_FAILURE",), runtime.reconcile(i, grant=grant()).reason_codes)
            # The explicit operator migration restores service for the whole database.
            self.assertEqual({i.intent_id: "committed"}, reopened.rebuild_evidence_heads())
            self.assertEqual("ok", reopened.evidence_status(i.intent_id)["status"])
            result = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW)
            self.assertEqual(IntentState.FINALIZED, result.state)
            self.assertTrue(reopened.verify_evidence_chain(i.intent_id))
        finally:
            reopened.close()

    def test_empty_legacy_chain_is_adopted_only_on_request_and_records_the_adoption(self):
        path, store = self._keyed()
        i = intent(intent_id="legacy_chain_000000000002")
        store.register(i, canonical_hash(i))
        store.close()
        self._drop_heads(path, empty_intent=i.intent_id)
        reopened = SQLiteIntentStore(path, evidence_key=EVIDENCE_KEY)
        try:
            self.assertEqual("chain_empty", reopened.evidence_status(i.intent_id)["status"])
            self.assertEqual({i.intent_id: "skipped_empty"}, reopened.rebuild_evidence_heads())
            with self.assertRaises(EvidenceIntegrityError):
                reopened.rebuild_evidence_head(i.intent_id)
            self.assertEqual({i.intent_id: "adopted_empty"}, reopened.rebuild_evidence_heads(allow_empty=True))
            self.assertEqual(["evidence_head_adopted"], [e["event_type"] for e in reopened.evidence(i.intent_id)])
            self.assertTrue(reopened.verify_evidence_chain(i.intent_id))
            self.assertEqual({}, reopened.rebuild_evidence_heads(allow_empty=True))
        finally:
            reopened.close()

    def test_tampered_chain_is_not_adopted_by_the_bulk_rebuild(self):
        path, store = self._keyed()
        i = intent(intent_id="legacy_chain_000000000003")
        store.register(i, canonical_hash(i))
        store.add_evidence(i.intent_id, "note", {"n": 1})
        store.close()
        self._drop_heads(path)
        conn = sqlite3.connect(path)
        conn.execute("UPDATE evidence SET payload_json='{\"n\": 2}' WHERE intent_id=? AND event_type='note'", (i.intent_id,))
        conn.commit()
        conn.close()
        reopened = SQLiteIntentStore(path, evidence_key=EVIDENCE_KEY)
        try:
            self.assertEqual("chain_invalid", reopened.evidence_status(i.intent_id)["status"])
            outcomes = reopened.rebuild_evidence_heads(allow_empty=True)
            self.assertTrue(outcomes[i.intent_id].startswith("refused:"), outcomes)
            self.assertFalse(reopened.verify_evidence_chain(i.intent_id))
        finally:
            reopened.close()


if __name__ == "__main__":
    unittest.main()
