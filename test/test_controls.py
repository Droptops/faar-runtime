"""Emergency controls and external authority anchoring (release gates 2, 7 and 9)."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from faar.adapters import DeterministicFailure
from faar.anchor import AuthorityRegression, FileAuthorityAnchor, InMemoryAuthorityAnchor
from faar.canonical import canonical_hash
from faar.models import ExecutionRequest, IntentState
from faar.store import GrantConflict, SQLiteIntentStore
from support import AUTH, NOW, PRINCIPAL, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, trust


def _tmp(suffix=".sqlite") -> str:
    f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    f.close()
    return f.name


class KillSwitchTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(_tmp())
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
        runtime, venue, _, permit_authority, _ = build_mock_runtime(self.store, self.trust)
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
    def _fresh(self, anchor):
        path = _tmp()
        store = SQLiteIntentStore(path, authority_anchor=anchor)
        store.provision_grant(grant(), canonical_hash(grant()))
        return path, store

    def _snapshot(self, store: SQLiteIntentStore, path: str) -> str:
        # A WAL-mode database must be checkpointed before its file is copied.
        store.checkpoint()
        copy = _tmp(".snapshot.sqlite")
        shutil.copyfile(path, copy)
        return copy

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
        from faar.permits import ConstrainedPermitAuthority, Ed25519PermitSigner, ExecutionPermitVerifier
        anchor = FileAuthorityAnchor(_tmp(".anchor.json"))
        path, store = self._fresh(anchor)
        t = trust()
        signer = Ed25519PermitSigner("permit-restore-test")
        permit_authority = ConstrainedPermitAuthority(store, t.public_verifier(), signer)
        permit_verifier = ExecutionPermitVerifier(signer.public_verifier(), store)
        i = intent(intent_id="intent_restore_00000000002")
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
        verifier = ExecutionPermitVerifier(signer.public_verifier(), restored)
        ok, reasons = verifier.consume(permit, request, now=NOW)
        self.assertFalse(ok)
        self.assertTrue({"PERMIT_GRANT_NOT_ACTIVE", "PERMIT_NOT_RECORDED", "PERMIT_AUTHORITY_REGRESSED"} & set(reasons), reasons)
        self.assertEqual("REGRESSED", restored.get_grant_status(PRINCIPAL, "grant:test", 1))
        with self.assertRaises(GrantConflict):
            restored.next_execution_fence(grant())
        restored.close()

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
        anchor_path = _tmp(".anchor.json")
        anchor = FileAuthorityAnchor(anchor_path)
        anchor.record("g", 1, 2, 5)
        anchor.record("g", 1, 1, 9)  # lower epoch never lowers the mark
        self.assertEqual((2, 5), FileAuthorityAnchor(anchor_path).high_water("g", 1))
        anchor.record("g", 1, 2, 7)
        self.assertEqual((2, 7), anchor.high_water("g", 1))
        self.assertIsNone(anchor.high_water("g", 2))
        self.assertFalse(Path(anchor_path + ".tmp").exists())


if __name__ == "__main__":
    unittest.main()
