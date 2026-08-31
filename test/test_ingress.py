from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace

from faar.canonical import canonical_hash
from faar.ingress import (
    AuthenticatedIngress,
    IngressAuthenticator,
    IngressDenied,
    IngressRole,
    IngressTokenIssuer,
    principal_intent_prefix,
)
from faar.permits import Ed25519PermitSignature
from faar.store import SQLiteIntentStore
from support import NOW, PRINCIPAL, grant, intent


class IngressTests(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        self.store = SQLiteIntentStore(f.name)
        self.issuer_sig = Ed25519PermitSignature("ingress-issuer")
        self.issuer = IngressTokenIssuer(self.issuer_sig, max_ttl_seconds=60)
        self.auth = IngressAuthenticator(self.issuer_sig.public_verifier())
        self.ingress = AuthenticatedIngress(self.store, self.auth, clock=lambda: NOW)
        self.principal = self.issuer.issue(PRINCIPAL, IngressRole.PRINCIPAL, now=NOW)
        self.admin = self.issuer.issue("admin:ops", IngressRole.ADMIN, now=NOW)

    def tearDown(self):
        self.store.close()

    def test_authenticator_has_no_sign_api(self):
        self.assertFalse(hasattr(self.auth, "sign"))

    def test_principal_cannot_substitute_another_principal(self):
        stolen = replace(intent(), principal_id="principal:victim")
        with self.assertRaises(IngressDenied) as ctx:
            self.ingress.bind_intent(self.principal, stolen)
        self.assertIn("INGRESS_PRINCIPAL_SUBSTITUTION", ctx.exception.reasons)

    def test_client_intent_id_must_be_principal_bound(self):
        with self.assertRaises(IngressDenied) as ctx:
            self.ingress.bind_intent(self.principal, intent())
        self.assertIn("INGRESS_INTENT_ID_NOT_PRINCIPAL_BOUND", ctx.exception.reasons)

    def test_server_mints_principal_bound_intent_id(self):
        proposed = replace(intent(), intent_id="__mint__")
        bound = self.ingress.bind_intent(self.principal, proposed)
        self.assertTrue(bound.intent_id.startswith(principal_intent_prefix(PRINCIPAL)))
        self.assertEqual(PRINCIPAL, bound.principal_id)
        self.assertEqual(NOW, bound.created_at)

    def test_one_principal_cannot_squat_another_intent_id(self):
        victim = "principal:victim"
        victim_token = self.issuer.issue(victim, IngressRole.PRINCIPAL, now=NOW)
        victim_intent = self.ingress.bind_intent(victim_token, replace(intent(), principal_id=victim, intent_id="__mint__"))
        self.store.register(victim_intent, canonical_hash(victim_intent))
        with self.assertRaises(IngressDenied):
            self.ingress.bind_intent(self.principal, replace(intent(), intent_id=victim_intent.intent_id))

    def test_principal_cannot_provision_or_revoke_grants(self):
        g = grant()
        with self.assertRaises(IngressDenied) as ctx:
            self.ingress.provision_grant(self.principal, g, canonical_hash(g))
        self.assertIn("INGRESS_ROLE_DENIED", ctx.exception.reasons)
        self.ingress.provision_grant(self.admin, g, canonical_hash(g))
        with self.assertRaises(IngressDenied) as ctx2:
            self.ingress.set_grant_status(self.principal, PRINCIPAL, g.grant_id, g.version, "REVOKED")
        self.assertIn("INGRESS_ROLE_DENIED", ctx2.exception.reasons)

    def test_admin_cannot_submit_execution_intents(self):
        with self.assertRaises(IngressDenied) as ctx:
            self.ingress.bind_intent(self.admin, replace(intent(), principal_id="admin:ops", intent_id="__mint__"))
        self.assertIn("INGRESS_ROLE_DENIED", ctx.exception.reasons)

    def test_tampered_ingress_token_fails(self):
        bad = replace(self.principal, signature=self.principal.signature[:-4] + "AAAA")
        with self.assertRaises(IngressDenied) as ctx:
            self.ingress.bind_intent(bad, replace(intent(), intent_id="__mint__"))
        self.assertIn("INGRESS_SIGNATURE_INVALID", ctx.exception.reasons)

    def test_security_time_is_server_clock_not_client_created_at(self):
        from datetime import timedelta
        stale = replace(intent(), intent_id="__mint__", created_at=NOW - timedelta(days=30))
        bound = self.ingress.bind_intent(self.principal, stale)
        self.assertEqual(NOW, bound.created_at)

    def test_expired_token_is_rejected(self):
        from datetime import timedelta
        expired = self.issuer.issue(PRINCIPAL, IngressRole.PRINCIPAL, now=NOW - timedelta(seconds=120), ttl_seconds=60)
        with self.assertRaises(IngressDenied) as ctx:
            self.ingress.bind_intent(expired, replace(intent(), intent_id="__mint__"))
        self.assertIn("INGRESS_TOKEN_EXPIRED", ctx.exception.reasons)

    def test_revoked_ingress_key_is_rejected(self):
        self.ingress.key_lifecycle.revoke("ingress-issuer", at=NOW)
        with self.assertRaises(IngressDenied) as ctx:
            self.ingress.bind_intent(self.principal, replace(intent(), intent_id="__mint__"))
        self.assertTrue(any("REVOKED" in r for r in ctx.exception.reasons))


if __name__ == "__main__":
    unittest.main()
