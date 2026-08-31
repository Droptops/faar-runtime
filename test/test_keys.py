from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta

from faar.keys import KeyConflict, KeyLifecycle, KeyStatus
from faar.models import ExecutionRequest
from faar.permits import ConstrainedPermitAuthority, Ed25519PermitSignature, ExecutionPermitVerifier, HMACPermitSignature
from faar.store import SQLiteIntentStore
from support import AUTH, NOW, attest_pair, grant, intent, risk, trust, verification_trust


class KeyLifecycleTests(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        self.store = SQLiteIntentStore(f.name)
        self.path = f.name
        self.lifecycle = KeyLifecycle(self.store, "PERMIT")

    def tearDown(self):
        self.store.close()

    def test_active_key_accepts_artifacts(self):
        self.lifecycle.register_active("k1")
        ok, reason = self.lifecycle.accept_artifact("k1", issued_at=NOW)
        self.assertTrue(ok, reason)
        self.assertEqual(KeyStatus.ACTIVE, self.lifecycle.get("k1").status)

    def test_retired_key_accepts_artifacts_issued_before_retirement(self):
        self.lifecycle.register_active("k1")
        retired_at = NOW + timedelta(seconds=5)
        self.lifecycle.retire("k1", at=retired_at)
        ok, reason = self.lifecycle.accept_artifact("k1", issued_at=NOW)
        self.assertTrue(ok, reason)
        ok2, reason2 = self.lifecycle.accept_artifact("k1", issued_at=retired_at + timedelta(seconds=1))
        self.assertFalse(ok2)
        self.assertEqual("KEY_RETIRED", reason2)

    def test_revoked_key_rejects_even_prior_artifacts(self):
        self.lifecycle.register_active("k1")
        self.lifecycle.revoke("k1", at=NOW + timedelta(seconds=1))
        ok, reason = self.lifecycle.accept_artifact("k1", issued_at=NOW)
        self.assertFalse(ok)
        self.assertEqual("KEY_REVOKED", reason)

    def test_revoked_key_cannot_be_resurrected(self):
        self.lifecycle.register_active("k1")
        self.lifecycle.revoke("k1", at=NOW)
        with self.assertRaisesRegex(KeyConflict, "resurrected"):
            self.lifecycle.register_active("k1")

    def test_retired_key_cannot_be_reactivated(self):
        self.lifecycle.register_active("k1")
        self.lifecycle.retire("k1", at=NOW)
        with self.assertRaisesRegex(KeyConflict, "reactivated"):
            self.lifecycle.register_active("k1")

    def test_revocation_survives_store_restart(self):
        self.lifecycle.register_active("k1")
        self.lifecycle.revoke("k1", at=NOW)
        self.store.close()
        restarted = SQLiteIntentStore(self.path)
        try:
            life = KeyLifecycle(restarted, "PERMIT")
            ok, reason = life.accept_artifact("k1", issued_at=NOW)
            self.assertFalse(ok)
            self.assertEqual("KEY_REVOKED", reason)
            with self.assertRaisesRegex(KeyConflict, "resurrected"):
                life.register_active("k1")
        finally:
            restarted.close()

    def test_unknown_key_is_rejected(self):
        ok, reason = self.lifecycle.accept_artifact("missing", issued_at=NOW)
        self.assertFalse(ok)
        self.assertEqual("KEY_UNKNOWN", reason)

    def test_plane_mismatch_is_rejected(self):
        KeyLifecycle(self.store, "ATTESTATION").register_active("shared")
        with self.assertRaisesRegex(KeyConflict, "different plane"):
            self.lifecycle.register_active("shared")


class PermitKeyRotationTests(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        self.store = SQLiteIntentStore(f.name)
        self.trust = trust()
        self.grant = grant()
        from faar.canonical import canonical_hash
        self.store.provision_grant(self.grant, canonical_hash(self.grant))
        self.sig = Ed25519PermitSignature("permit-rotate")
        self.authority = ConstrainedPermitAuthority(self.store, verification_trust(self.trust), self.sig)
        self.verifier = ExecutionPermitVerifier(self.sig.public_verifier(), self.store)

    def tearDown(self):
        self.store.close()

    def _issue(self, intent_id, version):
        i = intent(intent_id=intent_id)
        rs = risk(state_version=version)
        from faar.canonical import canonical_hash
        self.store.register(i, canonical_hash(i))
        ok, reasons = self.store.reserve_usage(i, self.grant, rs, NOW)
        self.assertTrue(ok, reasons)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        req = ExecutionRequest.from_intent(i)
        permit = self.authority.issue(
            req, intent=i, authority=AUTH, grant=self.grant, risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )
        return i, req, permit

    def test_retired_key_still_verifies_existing_permit(self):
        i, req, permit = self._issue("permit_retire_keep_000000001", 80)
        self.verifier.lifecycle.retire("permit-rotate", at=NOW + timedelta(seconds=1))
        ok, reasons = self.verifier.verify(permit, req, now=NOW)
        self.assertTrue(ok, reasons)

    def test_retired_key_cannot_mint_new_permit(self):
        self.authority.isolated_signer.lifecycle.retire("permit-rotate", at=NOW)
        with self.assertRaises(Exception) as ctx:
            self._issue("permit_retire_block_00000001", 81)
        reasons = getattr(ctx.exception, "reasons", ())
        self.assertIn("PERMIT_SIGNER_KEY_NOT_ACTIVE", reasons)

    def test_revoked_key_rejects_existing_permit(self):
        i, req, permit = self._issue("permit_revoke_drop_000000001", 82)
        self.verifier.lifecycle.revoke("permit-rotate", at=NOW)
        ok, reasons = self.verifier.verify(permit, req, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_KEY_REVOKED", reasons)

    def test_rotation_to_new_key_id(self):
        i, req, old_permit = self._issue("permit_rotate_old_0000000001", 83)
        new_sig = Ed25519PermitSignature("permit-rotate-new")
        self.verifier.lifecycle.retire("permit-rotate", at=NOW + timedelta(seconds=1))
        self.verifier.add_verifier(new_sig.public_verifier())
        new_authority = ConstrainedPermitAuthority(
            self.store, verification_trust(self.trust), new_sig,
            key_lifecycle=self.verifier.lifecycle,
        )
        i2, req2, new_permit = None, None, None
        i2 = intent(intent_id="permit_rotate_new_0000000001")
        rs = risk(state_version=84)
        from faar.canonical import canonical_hash
        self.store.register(i2, canonical_hash(i2))
        self.assertTrue(self.store.reserve_usage(i2, self.grant, rs, NOW)[0])
        aa, ra = attest_pair(self.trust, i2, AUTH, rs, NOW)
        req2 = ExecutionRequest.from_intent(i2)
        new_permit = new_authority.issue(
            req2, intent=i2, authority=AUTH, grant=self.grant, risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )
        self.assertEqual("permit-rotate-new", new_permit.signer_id)
        ok_old, _ = self.verifier.verify(old_permit, req, now=NOW)
        ok_new, reasons_new = self.verifier.verify(new_permit, req2, now=NOW)
        self.assertTrue(ok_old)
        self.assertTrue(ok_new, reasons_new)

    def test_same_key_id_cannot_bind_different_public_material(self):
        impostor = Ed25519PermitSignature("permit-rotate")
        with self.assertRaises(KeyConflict):
            self.verifier.add_verifier(impostor.public_verifier())

    def test_isolated_signer_rejects_hmac(self):
        from faar.permits import IsolatedPermitSigner
        hmac_backend = HMACPermitSignature("hmac-permit", b"symmetric-key-material-32-bytes!!!")
        with self.assertRaisesRegex(ValueError, "Ed25519"):
            IsolatedPermitSigner(hmac_backend, self.verifier.lifecycle)


if __name__ == "__main__":
    unittest.main()
