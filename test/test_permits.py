from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from decimal import Decimal

from faar.adapters import DeterministicFailure, MockVenue
from faar.canonical import canonical_hash
from faar.models import ExecutionRequest
from faar.permits import (
    ConstrainedPermitAuthority,
    Ed25519PermitSignature,
    ExecutionPermitVerifier,
    HMACPermitSignature,
    PermitIssuanceError,
)
from faar.store import SQLiteIntentStore

from support import AUTH, NOW, PRINCIPAL, attest_pair, grant, intent, risk, trust, verification_trust


class PermitBoundaryTests(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        self.store = SQLiteIntentStore(f.name)
        self.trust = trust()
        self.grant = grant()
        self.store.provision_grant(self.grant, canonical_hash(self.grant))
        self.sig = Ed25519PermitSignature("permit-test")
        self.authority = ConstrainedPermitAuthority(self.store, verification_trust(self.trust), self.sig)
        self.verifier = ExecutionPermitVerifier(self.sig.public_verifier(), self.store)
        self.venue = MockVenue(self.verifier, name="mock-dex", clock=lambda: NOW)

    def tearDown(self):
        self.store.close()

    def issue(self, i=None, rs=None):
        i = i or intent()
        rs = rs or risk()
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

    def test_permit_authority_rejects_signing_capable_upstream_trust(self):
        with self.assertRaisesRegex(ValueError, "verify-only upstream attestation"):
            ConstrainedPermitAuthority(self.store, self.trust, Ed25519PermitSignature("bad-boundary"))

    def test_transport_cannot_broaden_signed_request(self):
        i, req, permit = self.issue()
        broadened = replace(req, payload={**req.payload, "amount_usd": "500"})
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_REQUEST_HASH_MISMATCH"):
            self.venue.execute(broadened, permit)
        self.assertEqual(0, self.venue.successful_effect_count(i.intent_id, principal_id=PRINCIPAL))

    def test_revocation_invalidates_already_issued_permit(self):
        i, req, permit = self.issue()
        # A second store object models an independent process changing lifecycle state.
        other = SQLiteIntentStore(self.store.path)
        try:
            other.set_grant_status(PRINCIPAL, self.grant.grant_id, self.grant.version, "REVOKED")
        finally:
            other.close()
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_GRANT"):
            self.venue.execute(req, permit)
        self.assertEqual(0, self.venue.successful_effect_count(i.intent_id, principal_id=PRINCIPAL))

    def test_signer_refuses_request_without_atomic_usage_reservation(self):
        i = intent(intent_id="permit_no_reservation_0001")
        self.store.register(i, canonical_hash(i))
        rs = risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        with self.assertRaises(PermitIssuanceError) as ctx:
            self.authority.issue(
                ExecutionRequest.from_intent(i), intent=i, authority=AUTH, grant=self.grant, risk=rs,
                authority_attestation=aa, risk_attestation=ra, now=NOW,
            )
        self.assertIn("PERMIT_USAGE_RESERVATION_NOT_HELD", ctx.exception.reasons)

    def test_signer_rechecks_risk_instead_of_trusting_runtime(self):
        i = intent(intent_id="permit_bad_risk_000000001")
        rs = risk(daily_loss_usd=Decimal("1000"))
        self.store.register(i, canonical_hash(i))
        # Simulate a compromised coordinator planting a reservation directly.
        # The permit authority still independently runs the deterministic risk gate.
        self.store._conn.execute(
            "INSERT INTO usage_reservations(intent_id,principal_id,grant_id,grant_version,day_key,velocity_bucket,amount_usd,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (i.intent_id, i.principal_id, self.grant.grant_id, self.grant.version, "2026-08-30", 1, "50", "HELD", NOW.isoformat(), NOW.isoformat()),
        )
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        with self.assertRaises(PermitIssuanceError) as ctx:
            self.authority.issue(
                ExecutionRequest.from_intent(i), intent=i, authority=AUTH, grant=self.grant, risk=rs,
                authority_attestation=aa, risk_attestation=ra, now=NOW,
            )
        self.assertTrue(any("MAX_DAILY_LOSS" in r for r in ctx.exception.reasons))

    def test_principal_is_cryptographically_bound(self):
        i, req, permit = self.issue()
        other = replace(req, principal_id="principal:attacker")
        ok, reasons = self.verifier.verify(permit, other, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_REQUEST_IDENTITY_MISMATCH", reasons)

    def test_permit_is_single_use_at_capability_gateway(self):
        i, req, permit = self.issue(i=intent(intent_id="permit_single_use_00000001"), rs=risk(state_version=30))
        ok, reasons = self.verifier.consume(permit, req, now=NOW)
        self.assertTrue(ok, reasons)
        ok2, reasons2 = self.verifier.consume(permit, req, now=NOW)
        self.assertFalse(ok2)
        self.assertIn("PERMIT_ALREADY_CONSUMED", reasons2)

    def test_pause_invalidates_already_issued_permit(self):
        i, req, permit = self.issue(i=intent(intent_id="permit_pause_000000000001"), rs=risk(state_version=10))
        other = SQLiteIntentStore(self.store.path)
        try:
            other.set_grant_status(PRINCIPAL, self.grant.grant_id, self.grant.version, "PAUSED")
        finally:
            other.close()
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_GRANT"):
            self.venue.execute(req, permit)
        self.assertEqual(0, self.venue.successful_effect_count(i.intent_id, principal_id=PRINCIPAL))

    def test_fresh_retry_risk_state_cannot_be_reused_by_different_intent(self):
        i1, req1, _ = self.issue(
            i=intent(intent_id="permit_risk_owner_000000001"), rs=risk(state_version=20)
        )
        fresh = risk(state_version=21)
        aa1, ra1 = attest_pair(self.trust, i1, AUTH, fresh, NOW)
        self.authority.issue(
            req1, intent=i1, authority=AUTH, grant=self.grant, risk=fresh,
            authority_attestation=aa1, risk_attestation=ra1, now=NOW,
        )

        i2 = intent(intent_id="permit_risk_thief_000000001")
        self.store.register(i2, canonical_hash(i2))
        # The legacy reservation ledger has not seen risk v21, so reservation can
        # succeed; the permit-time risk ledger must still block cross-intent reuse.
        ok, reasons = self.store.reserve_usage(i2, self.grant, fresh, NOW)
        self.assertTrue(ok, reasons)
        aa2, ra2 = attest_pair(self.trust, i2, AUTH, fresh, NOW)
        with self.assertRaises(PermitIssuanceError) as ctx:
            self.authority.issue(
                ExecutionRequest.from_intent(i2), intent=i2, authority=AUTH, grant=self.grant, risk=fresh,
                authority_attestation=aa2, risk_attestation=ra2, now=NOW,
            )
        self.assertIn("PERMIT_RISK_STATE_VERSION_ALREADY_CLAIMED", ctx.exception.reasons)

    def test_execution_gateway_rejects_symmetric_signing_material(self):
        symmetric = HMACPermitSignature("unsafe-hmac", b"symmetric-key-material-32-bytes!!!")
        with self.assertRaisesRegex(ValueError, "verify-only"):
            ExecutionPermitVerifier(symmetric, self.store)

    def test_ed25519_public_side_verifies_but_cannot_sign(self):
        signer = Ed25519PermitSignature("permit-ed25519")
        verifier = signer.public_verifier()
        payload = b"FAAR permit test"
        signature = signer.sign(payload)
        self.assertTrue(verifier.verify(payload, signature))
        with self.assertRaises(PermissionError):
            verifier.sign(payload)
        self.assertFalse(verifier.verify(payload + b"tampered", signature))


if __name__ == "__main__":
    unittest.main()
