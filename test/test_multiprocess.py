from __future__ import annotations

import multiprocessing as mp
import unittest
from dataclasses import replace
from decimal import Decimal

from faar.canonical import canonical_hash
from faar.models import IntentState
from faar.store import IntentBusy, SQLiteIntentStore
from support import NOW, grant, intent, risk, temp_file


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
        queue.put(store.begin_submission(intent_id, [IntentState.RESERVED], max_attempts=2, now=NOW))
    finally:
        store.close()


def _blocked_submit_worker(path, entered, go, queue):
    """Process A: submits through a runtime whose adapter blocks until B signals."""
    from faar.adapters import REFERENCE_SAFE_PROFILE, MockVenue
    from faar.runtime import FAARRuntime
    from faar.settlement import MockSettlementVerifier
    from support import AUTH, attest_pair, permit_stack, trust, verification_trust

    t = trust()
    store = SQLiteIntentStore(path)
    try:
        permit_authority, permit_verifier = permit_stack(store, t)
        inner = MockVenue(permit_verifier=permit_verifier, name="mock-dex", clock=lambda: NOW)

        class Blocking:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE

            def execute(self, request, permit):
                entered.set()
                go.wait(10)  # the other process revokes while we sit here
                return inner.execute(request, permit)  # venue checks the permit against the shared ledger

        runtime = FAARRuntime(store, {"mock-dex": Blocking()}, verification_trust(t), permit_authority,
                              {"mock-dex": MockSettlementVerifier(inner)}, clock=lambda: NOW, allow_test_time_override=True)
        i = intent(intent_id="mp_revoke_000000000001")
        aa, ra = attest_pair(t, i, AUTH, risk(), NOW)
        result = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW)
        queue.put((result.state.value, list(result.reason_codes), inner.successful_effect_count(i.intent_id),
                   [e["payload"].get("message", "") for e in store.evidence(i.intent_id) if e["event_type"] == "adapter_rejection_untrusted"]))
    finally:
        store.close()


def _revoke_worker(path, entered, go, queue):
    """Process B: revokes the grant while A's adapter call is in flight."""
    import time as _time
    from support import PRINCIPAL
    store = SQLiteIntentStore(path)
    try:
        entered.wait(10)
        started = _time.monotonic()
        store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
        queue.put(("revoked", _time.monotonic() - started))
    finally:
        go.set()
        store.close()


class MultiProcessStoreTests(unittest.TestCase):
    def test_distinct_processes_cannot_oversubscribe_daily_budget(self):
        f = temp_file(self)
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
        f = temp_file(self)
        parent = SQLiteIntentStore(f.name)
        g = grant()
        parent.provision_grant(g, canonical_hash(g))
        i = intent(intent_id="mp_submit_0000000000001")
        parent.register(i, canonical_hash(i))
        self.assertTrue(parent.reserve_usage(i, g, risk(), NOW)[0])
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
        self.assertEqual(1, sum(1 for started, _, _, _ in results if started))
        store = SQLiteIntentStore(f.name)
        try:
            self.assertEqual(IntentState.SUBMITTED, store.get(i.intent_id).state)
            self.assertEqual(1, store.get(i.intent_id).submission_count)
        finally:
            store.close()
    def test_durable_intent_lease_blocks_second_process(self):
        f = temp_file(self)
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


    def test_revocation_in_other_process_during_submission_prevents_effect(self):
        # Release gate 6 / I-17 across processes: the in-process fence cannot stop
        # a revoke issued elsewhere, so the durable epoch checked at permit
        # consumption must refuse the in-flight attempt.
        f = temp_file(self)
        parent = SQLiteIntentStore(f.name)
        parent.provision_grant(grant(), canonical_hash(grant()))
        parent.close()
        ctx = mp.get_context("spawn")
        entered, go, queue = ctx.Event(), ctx.Event(), ctx.Queue()
        a = ctx.Process(target=_blocked_submit_worker, args=(f.name, entered, go, queue))
        b = ctx.Process(target=_revoke_worker, args=(f.name, entered, go, queue))
        a.start(); b.start(); a.join(40); b.join(40)
        self.assertEqual(0, a.exitcode); self.assertEqual(0, b.exitcode)
        results = {}
        for _ in range(2):
            item = queue.get(timeout=5)
            results["B" if item[0] == "revoked" else "A"] = item
        self.assertLess(results["B"][1], 5.0, "revocation must not wait on another process's adapter call")
        state, reasons, effects, rejections = results["A"]
        self.assertIn(state, {"FAILED_SAFE", "STOPPED", "UNKNOWN"})
        self.assertEqual(0, effects)
        self.assertTrue(any("PERMIT_GRANT_NOT_ACTIVE" in r or "PERMIT_GRANT_EPOCH_STALE" in r for r in rejections), rejections)



if __name__ == "__main__":
    unittest.main()
