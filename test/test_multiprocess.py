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


def _permit_consume_worker(path, payload, queue):
    store = SQLiteIntentStore(path)
    try:
        ok, reasons = store.consume_execution_permit(**payload)
        queue.put((ok, tuple(reasons)))
    finally:
        store.close()


def _record_permit_worker(path, payload, queue):
    from faar.store import PermitConflict
    store = SQLiteIntentStore(path)
    try:
        g = grant(grant_id=payload["grant_id"])
        i = intent(intent_id=payload["intent_id"], grant_id=payload["grant_id"])
        store.record_execution_permit(
            payload["permit_id"], i, g,
            payload["grant_epoch"], payload["fence_token"], payload["permit_hash"],
        )
        queue.put("ok")
    except PermitConflict:
        queue.put("conflict")
    finally:
        store.close()


def _revoke_grant_worker(path, principal_id, grant_id, version, queue):
    store = SQLiteIntentStore(path)
    try:
        store.set_grant_status(principal_id, grant_id, version, "REVOKED")
        queue.put(("revoked", ()))
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

    def test_distinct_processes_cannot_double_consume_permit(self):
        from faar.canonical import canonical_hash as ch
        from faar.models import ExecutionRequest
        from faar.permits import ConstrainedPermitAuthority, Ed25519PermitSignature
        from support import AUTH, attest_pair, trust, verification_trust

        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        store = SQLiteIntentStore(f.name)
        g = grant(grant_id="grant:mp-permit")
        store.provision_grant(g, canonical_hash(g))
        t = trust()
        sig = Ed25519PermitSignature("mp-permit")
        authority = ConstrainedPermitAuthority(store, verification_trust(t), sig)
        i = intent(intent_id="mp_permit_00000000000001", grant_id=g.grant_id)
        store.register(i, canonical_hash(i))
        rs = risk(state_version=301)
        self.assertTrue(store.reserve_usage(i, g, rs, NOW)[0])
        aa, ra = attest_pair(t, i, AUTH, rs, NOW)
        req = ExecutionRequest.from_intent(i)
        permit = authority.issue(
            req, intent=i, authority=AUTH, grant=g, risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )
        payload = dict(
            permit_id=permit.permit.permit_id,
            principal_id=permit.permit.principal_id,
            grant_id=permit.permit.grant_id,
            grant_version=permit.permit.grant_version,
            grant_epoch=permit.permit.grant_epoch,
            fence_token=permit.permit.fence_token,
            permit_hash=ch(permit),
        )
        store.close()

        ctx = mp.get_context("spawn")
        queue = ctx.Queue()
        p1 = ctx.Process(target=_permit_consume_worker, args=(f.name, payload, queue))
        p2 = ctx.Process(target=_permit_consume_worker, args=(f.name, payload, queue))
        p1.start(); p2.start(); p1.join(10); p2.join(10)
        self.assertEqual(0, p1.exitcode); self.assertEqual(0, p2.exitcode)
        results = [queue.get(timeout=2), queue.get(timeout=2)]
        self.assertEqual(1, sum(1 for ok, _ in results if ok))
        denied = [reasons for ok, reasons in results if not ok]
        self.assertEqual(1, len(denied))
        self.assertIn("PERMIT_ALREADY_CONSUMED", denied[0])

    def test_revoke_and_consume_race_never_double_consumes(self):
        from faar.canonical import canonical_hash as ch
        from faar.models import ExecutionRequest
        from faar.permits import ConstrainedPermitAuthority, Ed25519PermitSignature
        from support import AUTH, PRINCIPAL, attest_pair, trust, verification_trust

        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        store = SQLiteIntentStore(f.name)
        g = grant(grant_id="grant:mp-revoke")
        store.provision_grant(g, canonical_hash(g))
        t = trust()
        sig = Ed25519PermitSignature("mp-revoke")
        authority = ConstrainedPermitAuthority(store, verification_trust(t), sig)
        i = intent(intent_id="mp_revoke_00000000000001", grant_id=g.grant_id)
        store.register(i, canonical_hash(i))
        rs = risk(state_version=302)
        self.assertTrue(store.reserve_usage(i, g, rs, NOW)[0])
        aa, ra = attest_pair(t, i, AUTH, rs, NOW)
        req = ExecutionRequest.from_intent(i)
        permit = authority.issue(
            req, intent=i, authority=AUTH, grant=g, risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )
        payload = dict(
            permit_id=permit.permit.permit_id,
            principal_id=permit.permit.principal_id,
            grant_id=permit.permit.grant_id,
            grant_version=permit.permit.grant_version,
            grant_epoch=permit.permit.grant_epoch,
            fence_token=permit.permit.fence_token,
            permit_hash=ch(permit),
        )
        store.close()

        ctx = mp.get_context("spawn")
        queue = ctx.Queue()
        p1 = ctx.Process(target=_permit_consume_worker, args=(f.name, payload, queue))
        p2 = ctx.Process(target=_revoke_grant_worker, args=(f.name, PRINCIPAL, g.grant_id, g.version, queue))
        p1.start(); p2.start(); p1.join(10); p2.join(10)
        self.assertEqual(0, p1.exitcode); self.assertEqual(0, p2.exitcode)
        results = [queue.get(timeout=2), queue.get(timeout=2)]
        consumed = sum(1 for ok, _ in results if ok is True)
        self.assertLessEqual(consumed, 1)
        restarted = SQLiteIntentStore(f.name)
        try:
            row = restarted._conn.execute(
                "SELECT consumed_at FROM execution_permits WHERE permit_id=?", (payload["permit_id"],)
            ).fetchone()
            status = restarted.get_grant_status(PRINCIPAL, g.grant_id, g.version)
            if consumed == 1:
                self.assertIsNotNone(row["consumed_at"])
            else:
                self.assertEqual("REVOKED", status)
                self.assertIsNone(row["consumed_at"])
            if status == "REVOKED":
                ok, reasons = restarted.consume_execution_permit(**payload)
                self.assertFalse(ok)
                self.assertTrue(
                    "PERMIT_GRANT_NOT_ACTIVE" in reasons or "PERMIT_ALREADY_CONSUMED" in reasons or "PERMIT_GRANT_EPOCH_STALE" in reasons
                )
        finally:
            restarted.close()

    def test_distinct_processes_cannot_mint_two_outstanding_permits(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        parent = SQLiteIntentStore(f.name)
        g = grant(grant_id="grant:mp-outstanding")
        parent.provision_grant(g, canonical_hash(g))
        i = intent(intent_id="mp_outstanding_0000000001", grant_id=g.grant_id)
        parent.register(i, canonical_hash(i))
        parent.close()

        ctx = mp.get_context("spawn")
        queue = ctx.Queue()
        base = dict(intent_id=i.intent_id, grant_id=g.grant_id, grant_epoch=1, permit_hash="h")
        p1 = ctx.Process(target=_record_permit_worker, args=(f.name, {**base, "permit_id": "p1", "fence_token": 1}, queue))
        p2 = ctx.Process(target=_record_permit_worker, args=(f.name, {**base, "permit_id": "p2", "fence_token": 2}, queue))
        p1.start(); p2.start(); p1.join(10); p2.join(10)
        self.assertEqual(0, p1.exitcode); self.assertEqual(0, p2.exitcode)
        results = [queue.get(timeout=2), queue.get(timeout=2)]
        self.assertEqual(1, results.count("ok"))
        self.assertEqual(1, results.count("conflict"))
        store = SQLiteIntentStore(f.name)
        try:
            rows = store._conn.execute(
                "SELECT permit_id, consumed_at FROM execution_permits WHERE intent_id=?", (i.intent_id,)
            ).fetchall()
            self.assertEqual(1, len(rows))
            self.assertIsNone(rows[0]["consumed_at"])
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
