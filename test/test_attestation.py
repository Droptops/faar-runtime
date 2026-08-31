from __future__ import annotations

import hashlib
import hmac
import unittest

from faar.attestation import Ed25519TrustStore, HMACTrustStore
from faar.canonical import canonical_hash
from faar.models import Attestation, AttestationKind
from support import AUTH, NOW, TRUST_KEYS, TRUST_KEY_KINDS, intent


class AttestationScopeTests(unittest.TestCase):
    def test_signer_cannot_use_risk_key_for_authority(self):
        t = HMACTrustStore(TRUST_KEYS, key_kinds=TRUST_KEY_KINDS)
        with self.assertRaises(PermissionError):
            t.sign("risk-test", AttestationKind.AUTHORITY, AUTH, intent(), issued_at=NOW)

    def test_valid_mac_from_wrong_role_key_is_rejected(self):
        i = intent()
        verifier = HMACTrustStore(TRUST_KEYS, key_kinds=TRUST_KEY_KINDS)

        # Simulate compromise of the risk signing key. The attacker can compute a
        # cryptographically valid AUTHORITY-shaped MAC, but role scoping must still
        # reject it at verification time.
        permissive = HMACTrustStore(
            {"risk-test": TRUST_KEYS["risk-test"]},
            key_kinds={"risk-test": {AttestationKind.AUTHORITY}},
        )
        forged = permissive.sign(
            "risk-test", AttestationKind.AUTHORITY, AUTH, i, issued_at=NOW, ttl_seconds=20
        )
        ok, reasons = verifier.verify(
            forged,
            kind=AttestationKind.AUTHORITY,
            subject=AUTH,
            intent=i,
            now=NOW,
        )
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_KEY_KIND_NOT_ALLOWED", reasons)


    def test_ed25519_public_verifier_validates_but_cannot_sign(self):
        i = intent()
        signer = Ed25519TrustStore.generate(TRUST_KEY_KINDS)
        verifier = signer.public_verifier()
        att = signer.sign(
            "authority-test", AttestationKind.AUTHORITY, AUTH, i,
            issued_at=NOW, ttl_seconds=20,
        )
        ok, reasons = verifier.verify(
            att, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=i, now=NOW
        )
        self.assertTrue(ok, reasons)
        self.assertFalse(verifier.can_sign)
        with self.assertRaises(PermissionError):
            verifier.sign(
                "authority-test", AttestationKind.AUTHORITY, AUTH, i,
                issued_at=NOW, ttl_seconds=20,
            )

    def test_key_scope_configuration_must_cover_exact_key_set(self):
        with self.assertRaises(ValueError):
            HMACTrustStore(
                {"a": b"0123456789abcdef"},
                key_kinds={"other": {AttestationKind.AUTHORITY}},
            )


if __name__ == "__main__":
    unittest.main()
