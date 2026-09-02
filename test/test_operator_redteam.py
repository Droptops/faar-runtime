"""Regressions from the operator/authority persona of the live-money red team:
anchor identity, evidence-head laundering, control scopes and anchored caps."""
from __future__ import annotations

import shutil
import sqlite3
import unittest
from decimal import Decimal

from faar.anchor import AnchorMismatch, FileAuthorityAnchor, InMemoryAuthorityAnchor
from faar.canonical import canonical_hash
from faar.models import ExecutionRequest, IntentState
from faar.permits import ExecutionPermitVerifier
from faar.store import EvidenceIntegrityError, SQLiteIntentStore, UnknownPrincipal
from support import AUTH, NOW, PRINCIPAL, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, temp_path, trust


class AnchorIdentityTests(unittest.TestCase):
    def _anchored(self, anchor):
        path = temp_path(self)
        store = SQLiteIntentStore(path, authority_anchor=anchor)
        store.provision_grant(grant(), canonical_hash(grant()))
        return path, store

    def test_a_fresh_or_different_anchor_cannot_un_regress_a_restored_database(self):
        anchor_path = temp_path(self, ".anchor.json")
        anchor = FileAuthorityAnchor(anchor_path)
        path, store = self._anchored(anchor)
        t = trust()
        _, signer_verifier = permit_stack(store, t)
        i = intent(intent_id="intent_opr_0000000000001")
        rs = risk()
        aa, ra = attest_pair(t, i, AUTH, rs, NOW)
        store.register(i, canonical_hash(i))
        self.assertTrue(store.reserve_usage(i, grant(), rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        permit_authority, permit_verifier = permit_stack(store, t)
        permit = permit_authority.issue(request, intent=i, authority=AUTH, grant=grant(), risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        store.checkpoint()
        snapshot = temp_path(self, ".snapshot.sqlite")
        shutil.copyfile(path, snapshot)
        self.assertTrue(permit_verifier.consume(permit, request, now=NOW)[0])
        store.set_grant_status(PRINCIPAL, "grant:test", 1, "REVOKED")
        store.close()
        shutil.copyfile(snapshot, path)

        # The real anchor detects the restore.
        restored = SQLiteIntentStore(path, authority_anchor=FileAuthorityAnchor(anchor_path))
        self.assertEqual("REGRESSED", restored.get_grant_status(PRINCIPAL, "grant:test", 1))
        restored.close()
        # An unmounted volume / wrong path presents a fresh anchor: refused outright.
        with self.assertRaises(AnchorMismatch):
            SQLiteIntentStore(path, authority_anchor=FileAuthorityAnchor(temp_path(self, ".fresh.anchor.json")))
        with self.assertRaises(AnchorMismatch):
            SQLiteIntentStore(path, authority_anchor=InMemoryAuthorityAnchor())
        # An anchor bound to another database is refused as well.
        other_anchor = InMemoryAuthorityAnchor()
        other_path, other = self._anchored(other_anchor)
        other.close()
        with self.assertRaises(AnchorMismatch):
            SQLiteIntentStore(path, authority_anchor=other_anchor)
        # The consumed permit therefore cannot be consumed again anywhere.
        again = SQLiteIntentStore(path, authority_anchor=FileAuthorityAnchor(anchor_path))
        ok, reasons = ExecutionPermitVerifier(permit_verifier.signature, again).consume(permit, request, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_AUTHORITY_REGRESSED", reasons)
        again.close()

    def test_databases_bound_before_identities_existed_adopt_the_anchor_identity(self):
        anchor = InMemoryAuthorityAnchor()
        path, store = self._anchored(anchor)
        store._conn.execute("DELETE FROM store_settings WHERE key='anchor_id'")
        store._conn.commit()
        store.close()
        reopened = SQLiteIntentStore(path, authority_anchor=anchor)  # adopts
        self.assertEqual("ACTIVE", reopened.get_grant_status(PRINCIPAL, "grant:test", 1))
        reopened.close()
        with self.assertRaises(AnchorMismatch):
            SQLiteIntentStore(path, authority_anchor=InMemoryAuthorityAnchor())


class EvidenceLaunderingTests(unittest.TestCase):
    def test_a_deleted_head_is_tampering_not_a_legacy_chain(self):
        key = b"evidence-test-key-32-bytes-long!!!!!"
        path = temp_path(self)
        store = SQLiteIntentStore(path, evidence_key=key)
        store.provision_grant(grant(), canonical_hash(grant()))
        t = trust()
        runtime, *_ = build_mock_runtime(store, t)
        i = intent(intent_id="intent_opr_0000000000010")
        aa, ra = attest_pair(t, i, AUTH, risk(), NOW)
        self.assertEqual(IntentState.FINALIZED, runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW).state)
        events = len(store.evidence(i.intent_id))
        store.close()
        conn = sqlite3.connect(path)
        conn.execute("DELETE FROM evidence WHERE intent_id=? AND id IN (SELECT id FROM evidence WHERE intent_id=? ORDER BY id DESC LIMIT 2)", (i.intent_id, i.intent_id))
        conn.execute("DELETE FROM evidence_head WHERE intent_id=?", (i.intent_id,))
        conn.commit()
        conn.close()
        reopened = SQLiteIntentStore(path, evidence_key=key)
        try:
            status = reopened.evidence_status(i.intent_id)
            self.assertEqual(("head_deleted", events - 2, False), (status["status"], status["events"], status["valid"]))
            with self.assertRaises(EvidenceIntegrityError):
                reopened.rebuild_evidence_head(i.intent_id)
            outcomes = reopened.rebuild_evidence_heads(allow_empty=True)
            self.assertTrue(outcomes[i.intent_id].startswith("refused:"), outcomes)
            self.assertFalse(reopened.verify_evidence_chain(i.intent_id))
        finally:
            reopened.close()


class ControlScopeTests(unittest.TestCase):
    def setUp(self):
        self.anchor = InMemoryAuthorityAnchor()
        self.path = temp_path(self)
        self.store = SQLiteIntentStore(self.path, authority_anchor=self.anchor)
        self.store.provision_grant(grant(), canonical_hash(grant()))

    def tearDown(self):
        self.store.close()

    def test_controls_refuse_scopes_that_match_nothing(self):
        for bad in ("principal:test", "principal:principal:test ", "principal: principal:test", "principal:Principal:Test"):
            with self.assertRaises((UnknownPrincipal, ValueError), msg=bad):
                self.store.halt(bad, reason="typo")
            with self.assertRaises((UnknownPrincipal, ValueError), msg=bad):
                self.store.set_exposure_cap(bad, Decimal("10"))
        self.assertEqual([], self.store.controls())
        self.assertEqual([], self.store.exposure_caps())
        self.assertEqual(1, self.store.halt("principal:" + PRINCIPAL, reason="real"))
        self.assertEqual(1, self.store.set_exposure_cap("principal:" + PRINCIPAL, Decimal("10")))
        self.store.resume("principal:" + PRINCIPAL)
        # Explicit override for pre-provisioning a principal.
        self.assertEqual(0, self.store.set_exposure_cap("principal:principal:future", Decimal("5"), allow_unprovisioned=True))

    def test_exposure_caps_are_anchored_against_restore(self):
        self.store.set_exposure_cap("global", Decimal("10000"))
        self.store.checkpoint()
        snapshot = temp_path(self, ".snapshot.sqlite")
        shutil.copyfile(self.path, snapshot)
        self.store.set_exposure_cap("global", Decimal("1"))  # emergency clamp after the snapshot
        self.store.close()
        shutil.copyfile(snapshot, self.path)
        restored = SQLiteIntentStore(self.path, authority_anchor=self.anchor)
        self.assertEqual("10000", restored.exposure_caps()[0]["max_turnover_usd"], "the snapshot carries the pre-incident cap")
        i = intent(intent_id="intent_opr_0000000000020")
        restored.register(i, canonical_hash(i))
        ok, reasons = restored.reserve_usage(i, grant(), risk(), NOW)
        self.assertEqual((False, ("EXPOSURE_CAPS_REGRESSED",)), (ok, reasons))
        # Re-applying the caps (any cap write) moves the version past the anchor.
        restored.set_exposure_cap("global", Decimal("1"))
        j = intent(intent_id="intent_opr_0000000000021")
        restored.register(j, canonical_hash(j))
        ok, reasons = restored.reserve_usage(j, grant(), risk(state_version=2), NOW)
        self.assertEqual((False, ("EXPOSURE_CAP_EXCEEDED",)), (ok, reasons))
        restored.set_exposure_cap("global", Decimal("500"))
        k = intent(intent_id="intent_opr_0000000000022")
        restored.register(k, canonical_hash(k))
        self.assertTrue(restored.reserve_usage(k, grant(), risk(state_version=3), NOW)[0])
        self.store = restored


if __name__ == "__main__":
    unittest.main()
