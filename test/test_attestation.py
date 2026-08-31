from __future__ import annotations

import hashlib
import hmac
import unittest

from dataclasses import replace

from faar.attestation import (
    Ed25519AttestationSigner,
    Ed25519AttestationVerifier,
    Ed25519TrustStore,
    HMACTrustStore,
    has_signing_api,
)
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
        self.assertIs(Ed25519TrustStore, Ed25519AttestationSigner)
        self.assertIsInstance(signer, Ed25519AttestationSigner)
        self.assertIsInstance(verifier, Ed25519AttestationVerifier)
        self.assertTrue(has_signing_api(signer))
        self.assertFalse(hasattr(signer, "verify"))
        self.assertFalse(has_signing_api(verifier))
        self.assertFalse(hasattr(verifier, "sign"))

    def test_attestation_verifier_rejects_private_key_material(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with self.assertRaisesRegex(ValueError, "signing-capable"):
            Ed25519AttestationVerifier(
                {"authority-test": Ed25519PrivateKey.generate()},
                key_kinds={"authority-test": {AttestationKind.AUTHORITY}},
            )

    def test_tampered_attestation_signature_fails(self):
        i = intent()
        signer = Ed25519TrustStore.generate(TRUST_KEY_KINDS)
        verifier = signer.public_verifier()
        att = signer.sign(
            "authority-test", AttestationKind.AUTHORITY, AUTH, i,
            issued_at=NOW, ttl_seconds=20,
        )
        tampered = replace(att, signature=att.signature[:-4] + "AAAA")
        ok, reasons = verifier.verify(
            tampered, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=i, now=NOW
        )
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_SIGNATURE_INVALID", reasons)

    def test_untrusted_attestation_signer_fails(self):
        i = intent()
        trusted = Ed25519TrustStore.generate(TRUST_KEY_KINDS)
        untrusted = Ed25519TrustStore.generate(TRUST_KEY_KINDS)
        verifier = trusted.public_verifier()
        forged = untrusted.sign(
            "authority-test", AttestationKind.AUTHORITY, AUTH, i,
            issued_at=NOW, ttl_seconds=20,
        )
        ok, reasons = verifier.verify(
            forged, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=i, now=NOW
        )
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_SIGNATURE_INVALID", reasons)

    def test_attestation_intent_binding_remains_enforced(self):
        i = intent()
        other = intent(intent_id="intent_other_000000000001")
        signer = Ed25519TrustStore.generate(TRUST_KEY_KINDS)
        verifier = signer.public_verifier()
        att = signer.sign(
            "authority-test", AttestationKind.AUTHORITY, AUTH, i,
            issued_at=NOW, ttl_seconds=20,
        )
        ok, reasons = verifier.verify(
            att, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=other, now=NOW
        )
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_INTENT_MISMATCH", reasons)

    def test_revoked_attestation_key_is_rejected(self):
        from faar.keys import KeyLifecycle
        from faar.store import SQLiteIntentStore
        import tempfile
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        store = SQLiteIntentStore(f.name)
        try:
            i = intent()
            signer = Ed25519TrustStore.generate(TRUST_KEY_KINDS)
            life = KeyLifecycle(store, "ATTESTATION")
            verifier = signer.public_verifier(key_lifecycle=life)
            att = signer.sign(
                "authority-test", AttestationKind.AUTHORITY, AUTH, i,
                issued_at=NOW, ttl_seconds=20,
            )
            ok, reasons = verifier.verify(
                att, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=i, now=NOW
            )
            self.assertTrue(ok, reasons)
            life.revoke("authority-test", at=NOW)
            ok2, reasons2 = verifier.verify(
                att, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=i, now=NOW
            )
            self.assertFalse(ok2)
            self.assertIn("KEY_REVOKED", reasons2)
        finally:
            store.close()
        with self.assertRaises(ValueError):
            HMACTrustStore(
                {"a": b"0123456789abcdef"},
                key_kinds={"other": {AttestationKind.AUTHORITY}},
            )


if __name__ == "__main__":
    unittest.main()
