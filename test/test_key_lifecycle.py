"""Key rotation and revocation for attestation and permit signers (release gate 1)."""
from __future__ import annotations

import unittest
from datetime import timedelta

from faar.attestation import Ed25519TrustStore
from faar.canonical import canonical_hash
from faar.models import AttestationKind, ExecutionRequest, KeyValidity
from faar.permits import ConstrainedPermitAuthority, Ed25519PermitSigner, ExecutionPermitVerifier
from faar.store import SQLiteIntentStore
from support import AUTH, NOW, TRUST_KEY_KINDS, attest_pair, grant, intent, risk, temp_path, trust


class AttestationKeyLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.trust = trust()
        self.intent = intent()

    def verify_with(self, validity, aa, now=NOW):
        verifier = self.trust.public_verifier(key_validity=validity)
        return verifier.verify(aa, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=self.intent, now=now)

    def test_revoked_key_is_rejected_even_with_a_valid_signature(self):
        aa, _ = attest_pair(self.trust, self.intent, AUTH, risk(), NOW)
        self.assertTrue(self.verify_with({}, aa)[0])
        ok, reasons = self.verify_with({"authority-test": KeyValidity(revoked=True)}, aa)
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_KEY_REVOKED", reasons)

    def test_key_window_bounds_issuance_not_verification(self):
        aa, _ = attest_pair(self.trust, self.intent, AUTH, risk(), NOW)
        future = {"authority-test": KeyValidity(not_before=NOW + timedelta(minutes=1))}
        ok, reasons = self.verify_with(future, aa)
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_KEY_NOT_YET_VALID", reasons)
        retired = {"authority-test": KeyValidity(not_after=NOW - timedelta(minutes=1))}
        ok, reasons = self.verify_with(retired, aa)
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_KEY_EXPIRED", reasons)
        # Issued inside the window: stays verifiable for its own lifetime after the
        # window closes, which is what makes an overlap-based rotation safe.
        overlap = {"authority-test": KeyValidity(not_before=NOW - timedelta(minutes=1), not_after=NOW + timedelta(seconds=1))}
        self.assertTrue(self.verify_with(overlap, aa, now=NOW + timedelta(seconds=10))[0])

    def test_artifact_lifetime_bound_caps_a_retired_keys_exposure(self):
        # `not_after` is judged on the signer-controlled issued_at. A holder of a
        # retired (not revoked) key could back-date issuance and choose a ten-year
        # TTL; the verifier's lifetime bound is what makes that artifact fail.
        retired_at = NOW - timedelta(days=30)
        validity = {"authority-test": KeyValidity(not_after=retired_at)}
        backdated = self.trust.sign(
            "authority-test", AttestationKind.AUTHORITY, AUTH, self.intent,
            issued_at=retired_at - timedelta(seconds=1), ttl_seconds=10 * 365 * 86_400,
        )
        ok, reasons = self.verify_with(validity, backdated)
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_TTL_EXCEEDED", reasons)
        self.assertNotIn("ATTESTATION_KEY_EXPIRED", reasons)
        # Without the bound the same artifact would verify: the bound is the control.
        unbounded = self.trust.public_verifier(key_validity=validity, max_attestation_lifetime_seconds=20 * 365 * 86_400)
        self.assertTrue(unbounded.verify(backdated, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=self.intent, now=NOW)[0])
        # Ordinary short-lived artifacts are unaffected.
        aa, _ = attest_pair(self.trust, self.intent, AUTH, risk(), NOW)
        self.assertTrue(self.verify_with({}, aa)[0])
        with self.assertRaises(ValueError):
            self.trust.public_verifier(max_attestation_lifetime_seconds=0)

    def test_validity_map_must_reference_known_keys_and_be_well_formed(self):
        with self.assertRaises(ValueError):
            self.trust.public_verifier(key_validity={"ghost": KeyValidity(revoked=True)})
        with self.assertRaises(ValueError):
            KeyValidity(not_before=NOW, not_after=NOW)
        with self.assertRaises(ValueError):
            KeyValidity(not_before=NOW.replace(tzinfo=None))

    def test_verifier_copy_with_revocation_does_not_touch_signing_material(self):
        verifier = self.trust.public_verifier()
        revoked = verifier.with_key_validity({"risk-test": KeyValidity(revoked=True)})
        _, ra = attest_pair(self.trust, self.intent, AUTH, risk(), NOW)
        self.assertTrue(verifier.verify(ra, kind=AttestationKind.RISK, subject=risk(), intent=self.intent, now=NOW)[0])
        self.assertFalse(revoked.verify(ra, kind=AttestationKind.RISK, subject=risk(), intent=self.intent, now=NOW)[0])
        self.assertFalse(hasattr(revoked, "sign"))


class PermitSignerRotationTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self))
        self.store.provision_grant(grant(), canonical_hash(grant()))
        self.trust = trust()
        self.old = Ed25519PermitSigner("permit-2026-q3")
        self.new = Ed25519PermitSigner("permit-2026-q4")

    def tearDown(self):
        self.store.close()

    def issue(self, signer, iid, state_version):
        i = intent(intent_id=iid)
        rs = risk(state_version=state_version)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), rs, NOW)[0])
        authority = ConstrainedPermitAuthority(self.store, self.trust.public_verifier(), signer)
        request = ExecutionRequest.from_intent(i)
        return request, authority.issue(request, intent=i, authority=AUTH, grant=grant(), risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW)

    def test_gateway_trusts_both_signers_during_overlap_then_revokes_the_old_one(self):
        gateway = ExecutionPermitVerifier({s.signer_id: s.public_verifier() for s in (self.old, self.new)}, self.store)
        req_old, permit_old = self.issue(self.old, "intent_rotate_00000000001", 1)
        req_new, permit_new = self.issue(self.new, "intent_rotate_00000000002", 2)
        self.assertTrue(gateway.verify(permit_old, req_old, now=NOW)[0])
        self.assertTrue(gateway.verify(permit_new, req_new, now=NOW)[0])
        retired = gateway.with_key_validity({self.old.signer_id: KeyValidity(revoked=True)})
        ok, reasons = retired.verify(permit_old, req_old, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_SIGNER_REVOKED", reasons)
        self.assertTrue(retired.verify(permit_new, req_new, now=NOW)[0])

    def test_unknown_signer_and_misregistered_verifier_are_rejected(self):
        gateway = ExecutionPermitVerifier(self.new.public_verifier(), self.store)
        req_old, permit_old = self.issue(self.old, "intent_rotate_00000000003", 3)
        ok, reasons = gateway.verify(permit_old, req_old, now=NOW)
        self.assertFalse(ok)
        self.assertEqual(("PERMIT_SIGNER_UNKNOWN",), reasons)
        with self.assertRaises(ValueError):
            ExecutionPermitVerifier({"someone-else": self.new.public_verifier()}, self.store)
        with self.assertRaises(ValueError):
            ExecutionPermitVerifier(self.new.public_verifier(), self.store, key_validity={"ghost": KeyValidity(revoked=True)})

    def test_gateway_bounds_permit_lifetime(self):
        gateway = ExecutionPermitVerifier(self.new.public_verifier(), self.store, max_permit_lifetime_seconds=1)
        req, permit = self.issue(self.new, "intent_rotate_00000000005", 5)
        self.assertGreater(permit.permit.expires_at - permit.permit.issued_at, timedelta(seconds=1))
        ok, reasons = gateway.verify(permit, req, now=NOW)
        self.assertFalse(ok)
        self.assertEqual(("PERMIT_TTL_EXCEEDED",), reasons)
        self.assertTrue(ExecutionPermitVerifier(self.new.public_verifier(), self.store).verify(permit, req, now=NOW)[0])
        with self.assertRaises(ValueError):
            ExecutionPermitVerifier(self.new.public_verifier(), self.store, max_permit_lifetime_seconds=0)

    def test_signer_window_applies_to_permit_issuance_time(self):
        gateway = ExecutionPermitVerifier(
            self.new.public_verifier(), self.store,
            key_validity={self.new.signer_id: KeyValidity(not_before=NOW + timedelta(hours=1))},
        )
        req, permit = self.issue(self.new, "intent_rotate_00000000004", 4)
        ok, reasons = gateway.verify(permit, req, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_SIGNER_NOT_YET_VALID", reasons)


if __name__ == "__main__":
    unittest.main()
