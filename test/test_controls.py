"""Emergency controls and external authority anchoring (release gates 2, 7 and 9)."""
from __future__ import annotations

import json
import multiprocessing as mp
import shutil
import unittest
from pathlib import Path

from faar.adapters import DeterministicFailure
from faar.anchor import AnchorUnavailable, AuthorityRegression, FileAuthorityAnchor, InMemoryAuthorityAnchor
from faar.canonical import canonical_hash
from faar.models import ExecutionRequest, IntentState
from faar.store import AuthorityAnchorRequired, GrantConflict, SQLiteIntentStore
from support import AUTH, NOW, PRINCIPAL, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, temp_path, trust


def _anchor_worker(path, idx, records, barrier, queue):
    """One process hammering the shared anchor file: its own grant plus a shared one."""
    try:
        anchor = FileAuthorityAnchor(path)
        barrier.wait()
        for k in range(1, records + 1):
            anchor.record(f"g{idx}", 1, 1, k)
            anchor.record("shared", 1, 1, idx * records + k)
        queue.put((idx, None))
    except Exception as exc:  # report, never hang the parent
        queue.put((idx, f"{type(exc).__name__}: {exc}"))


class KillSwitchTests(unittest.TestCase):
    def _tmp(self, suffix=".sqlite") -> str:
        return temp_path(self, suffix)

    def setUp(self):
        self.store = SQLiteIntentStore(self._tmp())
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))
        other = grant(principal_id="principal:other", grant_id="grant:other")
        self.store.provision_grant(other, canonical_hash(other))
        self.other = other

    def tearDown(self):
        self.store.close()

    def run_case(self, runtime, i, g=None, rs=None):
        g = g or grant()
        rs = rs or risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        return runtime.process(i, AUTH, g, rs, authority_attestation=aa, risk_attestation=ra, now=NOW)

    def test_global_halt_stops_new_intents_and_kills_outstanding_permits(self):
        runtime, venue, _, permit_authority, permit_verifier = build_mock_runtime(self.store, self.trust)
        # A permit minted before the halt.
        i = intent(intent_id="intent_halt_000000000001")
        rs = risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        permit = permit_authority.issue(request, intent=i, authority=AUTH, grant=grant(), risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW)

        fenced = self.store.halt("global", reason="incident-42")
        self.assertEqual(2, fenced)
        self.assertEqual("HALTED", self.store.get_grant_status(PRINCIPAL, "grant:test", 1))
        # The gateway names the halt: a venue operator can tell it from a pause.
        ok, reasons = permit_verifier.verify(permit, request, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_HALTED", reasons)
        self.assertIn("PERMIT_GRANT_EPOCH_STALE", reasons)
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_GRANT_EPOCH_STALE"):
            venue.execute(request, permit)
        j = intent(intent_id="intent_halt_000000000002")
        result = self.run_case(runtime, j, rs=risk(state_version=2))
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_RUNTIME_HALTED", result.reason_codes)
        self.assertEqual(0, venue.execute_call_count(j.intent_id))
        self.assertEqual([{"scope": "global", "halted": 1}], [{"scope": c["scope"], "halted": c["halted"]} for c in self.store.controls()])

        self.store.resume("global")
        self.assertEqual("ACTIVE", self.store.get_grant_status(PRINCIPAL, "grant:test", 1))
        # The pre-halt permit stays dead after resume: its epoch is gone for good.
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_GRANT_EPOCH_STALE"):
            venue.execute(request, permit)
        k = intent(intent_id="intent_halt_000000000003")
        self.assertEqual(IntentState.FINALIZED, self.run_case(runtime, k, rs=risk(state_version=3)).state)

    def test_principal_halt_is_scoped(self):
        self.store.halt("principal:principal:other", reason="scoped incident")
        self.assertEqual("HALTED", self.store.get_grant_status("principal:other", "grant:other", 1))
        self.assertEqual("ACTIVE", self.store.get_grant_status(PRINCIPAL, "grant:test", 1))
        self.assertEqual(1, self.store.get_grant_control(PRINCIPAL, "grant:test", 1)[1], "other principals' epochs are untouched")
        self.assertEqual(2, self.store.get_grant_control("principal:other", "grant:other", 1)[1])
        with self.assertRaises(ValueError):
            self.store.halt("everything", reason="bad scope")
        with self.assertRaises(ValueError):
            self.store.halt("global", reason="")
        with self.assertRaises(KeyError):
            self.store.resume("principal:never-halted")

    def test_halt_does_not_wait_for_an_in_flight_fence(self):
        import threading
        entered, release = threading.Event(), threading.Event()

        def hold():
            with self.store.execution_guard("grant:test", 1):
                entered.set()
                release.wait(5)

        t = threading.Thread(target=hold)
        t.start()
        self.assertTrue(entered.wait(2))
        done = threading.Event()
        threading.Thread(target=lambda: (self.store.halt("global", reason="hung adapter"), done.set())).start()
        self.assertTrue(done.wait(2), "an emergency stop must not queue behind a hung adapter call")
        release.set()
        t.join(5)

    def test_operator_queries(self):
        runtime, venue, *_ = build_mock_runtime(self.store, self.trust)
        i = intent(intent_id="intent_ops_0000000000001")
        self.assertEqual(IntentState.FINALIZED, self.run_case(runtime, i).state)
        grants = self.store.list_grants()
        self.assertEqual({"grant:test", "grant:other"}, {g["grant_id"] for g in grants})
        self.assertTrue(all(g["effective_status"] == "ACTIVE" for g in grants))
        self.assertEqual([i.intent_id], [s.intent_id for s in self.store.list_intents(state=IntentState.FINALIZED)])
        self.assertEqual([], self.store.list_intents(state="UNKNOWN"))
        self.assertEqual([], self.store.held_usage())
        self.assertEqual([], self.store.list_leases())


class AuthorityAnchorTests(unittest.TestCase):
    def _tmp(self, suffix=".sqlite") -> str:
        return temp_path(self, suffix)

    def _fresh(self, anchor):
        path = self._tmp()
        store = SQLiteIntentStore(path, authority_anchor=anchor)
        store.provision_grant(grant(), canonical_hash(grant()))
        return path, store

    def _snapshot(self, store: SQLiteIntentStore, path: str) -> str:
        # A WAL-mode database must be checkpointed before its file is copied.
        store.checkpoint()
        copy = self._tmp(".snapshot.sqlite")
        shutil.copyfile(path, copy)
        return copy

    def _permit_stack(self, store):
        from faar.permits import ConstrainedPermitAuthority, Ed25519PermitSigner, ExecutionPermitVerifier
        t = trust()
        signer = Ed25519PermitSigner("permit-restore-test")
        return t, signer, ConstrainedPermitAuthority(store, t.public_verifier(), signer), ExecutionPermitVerifier(signer.public_verifier(), store)

    def test_restored_snapshot_cannot_resurrect_a_revoked_grant(self):
        anchor = InMemoryAuthorityAnchor()
        path, store = self._fresh(anchor)
        snapshot = self._snapshot(store, path)
        store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
        store.close()

        shutil.copyfile(snapshot, path)  # "restore from backup"
        restored = SQLiteIntentStore(path, authority_anchor=anchor)
        self.assertEqual("REGRESSED", restored.get_grant_status(PRINCIPAL, "grant:test", 1))
        t = trust()
        runtime, venue, *_ = build_mock_runtime(restored, t)
        i = intent(intent_id="intent_restore_00000000001")
        aa, ra = attest_pair(t, i, AUTH, risk(), NOW)
        result = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_RUNTIME_REGRESSED", result.reason_codes)
        self.assertEqual(0, venue.execute_call_count(i.intent_id))
        with self.assertRaises(AuthorityRegression):
            restored.set_grant_status(PRINCIPAL, "grant:test", 1, "ACTIVE")
        # Operator recovery closes the grant version past the anchored history.
        epoch, fence = restored.revoke_after_restore("grant:test", 1)
        self.assertEqual("REVOKED", restored.get_grant_status(PRINCIPAL, "grant:test", 1))
        self.assertEqual(epoch, restored.get_grant_control(PRINCIPAL, "grant:test", 1)[1])
        self.assertEqual((epoch, fence), anchor.high_water("grant:test", 1))
        restored.close()

    def test_restored_snapshot_cannot_replay_a_consumed_permit(self):
        from faar.permits import ExecutionPermitVerifier
        anchor = FileAuthorityAnchor(self._tmp(".anchor.json"))
        path, store = self._fresh(anchor)
        t, signer, permit_authority, permit_verifier = self._permit_stack(store)
        i = intent(intent_id="intent_restore_00000000002")
        rs = risk()
        aa, ra = attest_pair(t, i, AUTH, rs, NOW)
        store.register(i, canonical_hash(i))
        self.assertTrue(store.reserve_usage(i, grant(), rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        permit = permit_authority.issue(request, intent=i, authority=AUTH, grant=grant(), risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        # The dangerous snapshot: the permit is recorded but not yet consumed. A
        # restore to this point would let the venue consume it a second time.
        snapshot = self._snapshot(store, path)
        self.assertTrue(permit_verifier.consume(permit, request, now=NOW)[0])
        self.assertEqual((1, 2), anchor.high_water("grant:test", 1), "consumption advances the anchored fence")
        store.close()

        shutil.copyfile(snapshot, path)
        restored = SQLiteIntentStore(path, authority_anchor=anchor)
        self.assertEqual("REGRESSED", restored.get_grant_status(PRINCIPAL, "grant:test", 1))
        verifier = ExecutionPermitVerifier(signer.public_verifier(), restored)
        ok, reasons = verifier.verify(permit, request, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_AUTHORITY_REGRESSED", reasons)
        ok, reasons = restored.consume_execution_permit(
            permit_id=permit.permit.permit_id, principal_id=PRINCIPAL, grant_id="grant:test", grant_version=1,
            grant_epoch=permit.permit.grant_epoch, fence_token=permit.permit.fence_token, permit_hash=canonical_hash(permit),
        )
        self.assertFalse(ok)
        self.assertEqual(("PERMIT_AUTHORITY_REGRESSED",), reasons)
        with self.assertRaises(GrantConflict):
            restored.next_execution_fence(grant())
        restored.close()

    def test_restored_snapshot_from_before_issuance_is_regressed_too(self):
        anchor = FileAuthorityAnchor(self._tmp(".anchor.json"))
        path, store = self._fresh(anchor)
        t, signer, permit_authority, permit_verifier = self._permit_stack(store)
        i = intent(intent_id="intent_restore_00000000003")
        rs = risk()
        aa, ra = attest_pair(t, i, AUTH, rs, NOW)
        store.register(i, canonical_hash(i))
        self.assertTrue(store.reserve_usage(i, grant(), rs, NOW)[0])
        snapshot = self._snapshot(store, path)
        request = ExecutionRequest.from_intent(i)
        permit = permit_authority.issue(request, intent=i, authority=AUTH, grant=grant(), risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertTrue(permit_verifier.consume(permit, request, now=NOW)[0])
        store.close()
        shutil.copyfile(snapshot, path)
        restored = SQLiteIntentStore(path, authority_anchor=anchor)
        self.assertEqual("REGRESSED", restored.get_grant_status(PRINCIPAL, "grant:test", 1))
        restored.close()

    def test_store_bound_to_an_anchor_refuses_unanchored_authority_changes(self):
        anchor = FileAuthorityAnchor(self._tmp(".anchor.json"))
        path, store = self._fresh(anchor)
        t, signer, permit_authority, _ = self._permit_stack(store)
        i = intent(intent_id="intent_restore_00000000004")
        rs = risk()
        aa, ra = attest_pair(t, i, AUTH, rs, NOW)
        store.register(i, canonical_hash(i))
        self.assertTrue(store.reserve_usage(i, grant(), rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        permit = permit_authority.issue(request, intent=i, authority=AUTH, grant=grant(), risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        store.close()

        # A worker or operator command that forgot the anchor cannot advance
        # authority unrecorded; every such path is refused with a typed reason.
        from faar.permits import ExecutionPermitVerifier
        unanchored = SQLiteIntentStore(path)
        self.assertTrue(unanchored.anchor_required)
        self.assertFalse(unanchored.has_anchor)
        self.assertEqual("ANCHOR_REQUIRED", unanchored.get_grant_status(PRINCIPAL, "grant:test", 1))
        for op in (
            lambda: unanchored.set_grant_status(PRINCIPAL, "grant:test", 1, "PAUSED"),
            lambda: unanchored.halt("global", reason="x"),
            lambda: unanchored.next_execution_fence(grant()),
            lambda: unanchored.provision_grant(grant(grant_id="grant:new"), canonical_hash(grant(grant_id="grant:new"))),
            lambda: unanchored.revoke_after_restore("grant:test", 1),
        ):
            with self.assertRaises(AuthorityAnchorRequired):
                op()
        ok, reasons = ExecutionPermitVerifier(signer.public_verifier(), unanchored).consume(permit, request, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_ANCHOR_REQUIRED", reasons)
        runtime, venue, *_ = build_mock_runtime(unanchored, t)
        j = intent(intent_id="intent_restore_00000000005")
        aa, ra = attest_pair(t, j, AUTH, risk(state_version=2), NOW)
        result = runtime.process(j, AUTH, grant(), risk(state_version=2), authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_RUNTIME_ANCHOR_REQUIRED", result.reason_codes)
        self.assertEqual(0, venue.execute_call_count(j.intent_id))
        unanchored.close()
        # Reopened with the anchor, the permit is still consumable exactly once.
        reopened = SQLiteIntentStore(path, authority_anchor=anchor)
        self.assertTrue(ExecutionPermitVerifier(signer.public_verifier(), reopened).consume(permit, request, now=NOW)[0])
        reopened.close()

    def test_unreadable_anchor_fails_closed(self):
        anchor_path = self._tmp(".anchor.json")
        anchor = FileAuthorityAnchor(anchor_path)
        path, store = self._fresh(anchor)
        t, signer, permit_authority, permit_verifier = self._permit_stack(store)
        i = intent(intent_id="intent_restore_00000000006")
        rs = risk()
        aa, ra = attest_pair(t, i, AUTH, rs, NOW)
        store.register(i, canonical_hash(i))
        self.assertTrue(store.reserve_usage(i, grant(), rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        permit = permit_authority.issue(request, intent=i, authority=AUTH, grant=grant(), risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        Path(anchor_path).write_text("{not json")
        with self.assertRaises(AnchorUnavailable):
            anchor.high_water("grant:test", 1)
        self.assertEqual("ANCHOR_UNAVAILABLE", store.get_grant_status(PRINCIPAL, "grant:test", 1))
        ok, reasons = permit_verifier.consume(permit, request, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_ANCHOR_UNAVAILABLE", reasons)
        runtime, venue, *_ = build_mock_runtime(store, t)
        j = intent(intent_id="intent_restore_00000000007")
        aa, ra = attest_pair(t, j, AUTH, risk(state_version=2), NOW)
        result = runtime.process(j, AUTH, grant(), risk(state_version=2), authority_attestation=aa, risk_attestation=ra, now=NOW)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("GRANT_RUNTIME_ANCHOR_UNAVAILABLE", result.reason_codes)
        self.assertEqual(0, venue.execute_call_count(j.intent_id))
        store.close()

    def test_file_anchor_is_safe_across_processes(self):
        anchor_path = self._tmp(".anchor.json")
        FileAuthorityAnchor(anchor_path)
        procs, records = 4, 25
        ctx = mp.get_context("spawn")
        barrier, queue = ctx.Barrier(procs), ctx.Queue()
        workers = [ctx.Process(target=_anchor_worker, args=(anchor_path, idx, records, barrier, queue)) for idx in range(procs)]
        for w in workers:
            w.start()
        for w in workers:
            w.join(60)
        results = dict(queue.get(timeout=5) for _ in workers)
        self.assertEqual({idx: None for idx in range(procs)}, results)
        marks = json.loads(Path(anchor_path).read_text())
        anchor = FileAuthorityAnchor(anchor_path)
        for idx in range(procs):
            self.assertEqual((1, records), anchor.high_water(f"g{idx}", 1), f"lost update on g{idx}: {marks}")
        self.assertEqual((1, procs * records), anchor.high_water("shared", 1))

    def test_without_an_anchor_a_restore_is_undetectable(self):
        # Documents the ceiling of a single-file store: this is why the anchor exists
        # and why it must live outside the database backup set.
        path, store = self._fresh(None)
        snapshot = self._snapshot(store, path)
        store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
        store.close()
        shutil.copyfile(snapshot, path)
        restored = SQLiteIntentStore(path)
        self.assertEqual("ACTIVE", restored.get_grant_status(PRINCIPAL, "grant:test", 1))
        restored.close()

    def test_file_anchor_is_monotonic_and_survives_reopen(self):
        anchor_path = self._tmp(".anchor.json")
        anchor = FileAuthorityAnchor(anchor_path)
        anchor.record("g", 1, 2, 5)
        anchor.record("g", 1, 1, 9)  # lower epoch never lowers the mark
        self.assertEqual((2, 5), FileAuthorityAnchor(anchor_path).high_water("g", 1))
        anchor.record("g", 1, 2, 7)
        self.assertEqual((2, 7), anchor.high_water("g", 1))
        self.assertIsNone(anchor.high_water("g", 2))
        leftovers = [p.name for p in Path(anchor_path).parent.iterdir() if p.suffix == ".tmp"]
        self.assertEqual([], leftovers)


if __name__ == "__main__":
    unittest.main()
