from __future__ import annotations

import multiprocessing as mp
import tempfile
import unittest
from dataclasses import replace
from decimal import Decimal

from faar.canonical import canonical_hash
from faar.models import IntentState
from faar.store import IntentBusy, SQLiteIntentStore
from support import NOW, grant, intent, risk


def _reserve_worker(path, grant_id, intent_id, risk_version, daily_cap, barrier, queue):
    store = SQLiteIntentStore(path)
    try:
        g = grant(grant_id=grant_id, limits=replace(grant().limits, max_daily_turnover_usd=Decimal(daily_cap)))
        i = intent(intent_id=intent_id, grant_id=grant_id)
        r = risk(state_version=risk_version)
        barrier.wait()
        ok, reasons = store.reserve_usage(i, g, r, NOW)
        queue.put((ok, reasons))
    finally:
        store.close()


def _lease_holder(path, intent_id, acquired, release, queue):
    store = SQLiteIntentStore(path)
    try:
        with store.intent_guard(intent_id, wait_seconds=1):
            acquired.set()
            release.wait(5)
            queue.put("holder-released")
    finally:
        store.close()


def _lease_challenger(path, intent_id, acquired, queue):
    store = SQLiteIntentStore(path)
    try:
        acquired.wait(5)
        try:
            with store.intent_guard(intent_id, wait_seconds=0.05):
                queue.put("challenger-acquired")
        except IntentBusy:
            queue.put("challenger-busy")
    finally:
        store.close()


def _submit_worker(path, intent_id, barrier, queue):
    store = SQLiteIntentStore(path)
    try:
        barrier.wait()
        queue.put(store.begin_submission(intent_id, [IntentState.RESERVED], max_attempts=2))
    finally:
        store.close()


class MultiProcessStoreTests(unittest.TestCase):
    def test_distinct_processes_cannot_oversubscribe_daily_budget(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        parent = SQLiteIntentStore(f.name)
        tight = grant(
            grant_id="grant:mp-budget",
            limits=replace(grant().limits, max_daily_turnover_usd=Decimal("75")),
        )
        parent.provision_grant(tight, canonical_hash(tight))
        parent.close()

        ctx = mp.get_context("spawn")
        barrier = ctx.Barrier(2)
        queue = ctx.Queue()
        i1 = intent(intent_id="mp_budget_000000000001", grant_id=tight.grant_id)
        i2 = intent(intent_id="mp_budget_000000000002", grant_id=tight.grant_id)
        p1 = ctx.Process(target=_reserve_worker, args=(f.name, tight.grant_id, i1.intent_id, 101, "75", barrier, queue))
        p2 = ctx.Process(target=_reserve_worker, args=(f.name, tight.grant_id, i2.intent_id, 102, "75", barrier, queue))
        p1.start(); p2.start(); p1.join(10); p2.join(10)
        self.assertEqual(0, p1.exitcode); self.assertEqual(0, p2.exitcode)
        results = [queue.get(timeout=2), queue.get(timeout=2)]
        self.assertEqual(1, sum(1 for ok, _ in results if ok))
        denied = [reasons for ok, reasons in results if not ok]
        self.assertEqual(1, len(denied))
        self.assertIn("ATOMIC_DAILY_TURNOVER_EXCEEDED", denied[0])

    def test_distinct_processes_cannot_both_begin_same_submission(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        parent = SQLiteIntentStore(f.name)
        i = intent(intent_id="mp_submit_0000000000001")
        parent.register(i, canonical_hash(i))
        parent.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        parent.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        parent.close()

        ctx = mp.get_context("spawn")
        barrier = ctx.Barrier(2)
        queue = ctx.Queue()
        p1 = ctx.Process(target=_submit_worker, args=(f.name, i.intent_id, barrier, queue))
        p2 = ctx.Process(target=_submit_worker, args=(f.name, i.intent_id, barrier, queue))
        p1.start(); p2.start(); p1.join(10); p2.join(10)
        self.assertEqual(0, p1.exitcode); self.assertEqual(0, p2.exitcode)
        results = [queue.get(timeout=2), queue.get(timeout=2)]
        self.assertEqual(1, sum(1 for started, _, _ in results if started))
        store = SQLiteIntentStore(f.name)
        try:
            self.assertEqual(IntentState.SUBMITTED, store.get(i.intent_id).state)
            self.assertEqual(1, store.get(i.intent_id).submission_count)
        finally:
            store.close()
    def test_durable_intent_lease_blocks_second_process(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        parent = SQLiteIntentStore(f.name)
        i = intent(intent_id="mp_lease_00000000000001")
        parent.register(i, canonical_hash(i))
        parent.close()

        ctx = mp.get_context("spawn")
        acquired = ctx.Event(); release = ctx.Event(); queue = ctx.Queue()
        holder = ctx.Process(target=_lease_holder, args=(f.name, i.intent_id, acquired, release, queue))
        challenger = ctx.Process(target=_lease_challenger, args=(f.name, i.intent_id, acquired, queue))
        holder.start(); self.assertTrue(acquired.wait(5)); challenger.start()
        challenger.join(5)
        self.assertEqual(0, challenger.exitcode)
        self.assertEqual("challenger-busy", queue.get(timeout=2))
        release.set(); holder.join(5)
        self.assertEqual(0, holder.exitcode)
        self.assertEqual("holder-released", queue.get(timeout=2))

        store = SQLiteIntentStore(f.name)
        try:
            self.assertIsNone(store.intent_lease(i.intent_id))
            with store.intent_guard(i.intent_id, wait_seconds=0.05):
                self.assertIsNotNone(store.intent_lease(i.intent_id))
        finally:
            store.close()



if __name__ == "__main__":
    unittest.main()
