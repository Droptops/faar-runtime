from __future__ import annotations

import ast
import json
import multiprocessing as mp
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

from faar.canonical import canonical_hash, canonical_json
from faar.descriptors import VerifierDescriptor, load_descriptor_bundle
from faar.executor import VerifyOnlyExecutor
from faar.gateway import GatewayDenial
from faar.ledger import SQLiteAuthorityLedger
from faar.models import (
    AuthorityDecision,
    AuthorityPosture,
    AuthorityPrimitive,
    CapabilityGrant,
    CapabilityLimits,
    EconomicPrimitive,
    ExecutionRequest,
    GrantStatus,
    Intent,
    RiskSnapshot,
)
from faar.parsing import parse_execution_request, parse_signed_permit
from faar.signing import FileBackedEd25519Provider, InMemoryEd25519Provider, KMSHSMProvider
from faar.authority_service import AuthorityService
from faar.store import SQLiteIntentStore
from support import NOW, PRINCIPAL


def _pay_intent(**changes):
    base = Intent(
        principal_id=PRINCIPAL,
        intent_id="intent_pay_000000000001",
        actor_id="agent:quant",
        grant_id="grant:treasury",
        grant_version=1,
        primitive=EconomicPrimitive.PAY,
        venue="mock-treasury",
        created_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=14),
        payload={
            "asset": "USDC",
            "amount_usd": "25",
            "target": "beneficiary:approved",
            "payment_reference": "payroll-001",
        },
    )
    return replace(base, **changes)


def _pay_grant(**changes):
    base = CapabilityGrant(
        principal_id=PRINCIPAL,
        grant_id="grant:treasury",
        version=1,
        actor_id="agent:quant",
        status=GrantStatus.ACTIVE,
        allowed_primitives=frozenset({EconomicPrimitive.PAY}),
        allowed_venues=frozenset({"mock-treasury"}),
        allowed_assets=frozenset({"USDC"}),
        allowed_targets=frozenset({"beneficiary:approved"}),
        limits=CapabilityLimits(
            max_order_usd=Decimal("75"),
            max_position_usd=Decimal("250"),
            max_daily_turnover_usd=Decimal("1500"),
            max_daily_loss_usd=Decimal("100"),
            max_market_data_age_seconds=10,
            max_risk_snapshot_age_seconds=5,
            max_intent_ttl_seconds=15,
            max_clock_skew_seconds=2,
            max_actions_per_window=10,
            action_window_seconds=60,
            max_submission_attempts=2,
        ),
    )
    return replace(base, **changes)


def _pay_risk(**changes):
    base = RiskSnapshot(
        observed_at=NOW,
        state_version=1,
        scope="portfolio",
        position_after_usd=Decimal("150"),
        daily_turnover_after_usd=Decimal("600"),
        daily_loss_usd=Decimal("20"),
        market_data_age_seconds=2,
        requested_slippage_bps=0,
        price_impact_bps=0,
        actions_in_window=1,
        circuit_breaker_active=False,
        data_complete=True,
        source_count=2,
        sources_agree=True,
    )
    return replace(base, **changes)


AUTH = AuthorityDecision(AuthorityPosture.EXECUTE, AuthorityPrimitive.EXECUTE_ACTION, source="test")


def _payload(intent=None, grant=None, risk=None, **extra):
    body = {
        "intent": json.loads(canonical_json(intent or _pay_intent())),
        "grant": json.loads(canonical_json(grant or _pay_grant())),
        "authority": json.loads(canonical_json(AUTH)),
        "risk": json.loads(canonical_json(risk or _pay_risk())),
        "now": NOW.isoformat(),
    }
    body.update(extra)
    return body


def _world(*, treasury_mode="SUCCESS"):
    tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
    tmp.close()
    store = SQLiteIntentStore(tmp.name)
    ledger = SQLiteAuthorityLedger(store)
    provider = InMemoryEd25519Provider.generate()
    grant = _pay_grant()
    store.provision_grant(grant, canonical_hash(grant))
    ledger.bind_account(PRINCIPAL, "account:treasury-a")
    ledger.set_balance("account:treasury-a", Decimal("1000"))
    ledger.set_balance("beneficiary:approved", Decimal("0"))
    ledger.allow_beneficiary("account:treasury-a", "beneficiary:approved")
    service = AuthorityService(store, provider, allow_test_time_override=True, ledger=ledger)
    descriptors = load_descriptor_bundle(provider.export_descriptors())
    executor = VerifyOnlyExecutor(
        ledger, descriptors, daily_budget_usd=Decimal("500"),
        clock=lambda: NOW, allow_test_time_override=True, treasury_mode=treasury_mode,
    )
    return store, ledger, provider, service, executor


class DescriptorTests(unittest.TestCase):
    def test_descriptor_rejects_revoked_and_private_material(self):
        provider = InMemoryEd25519Provider.generate()
        raw = provider.export_descriptors()[0]
        with self.assertRaisesRegex(ValueError, "DESCRIPTOR_REVOKED"):
            VerifierDescriptor.from_dict({**raw, "status": "REVOKED"})
        with self.assertRaisesRegex(ValueError, "DESCRIPTOR_PRIVATE_MATERIAL"):
            VerifierDescriptor.from_dict({**raw, "private_key": "aaaa"})
        with self.assertRaisesRegex(ValueError, "DESCRIPTOR_SCHEME_UNSUPPORTED"):
            VerifierDescriptor.from_dict({**raw, "scheme": "hmac-sha256"})
        with self.assertRaisesRegex(ValueError, "DESCRIPTOR_MATERIAL_MISMATCH"):
            VerifierDescriptor.from_dict({**raw, "material_hash": "0" * 64})
        with self.assertRaisesRegex(ValueError, "DESCRIPTOR_PRIVATE_MATERIAL"):
            VerifierDescriptor.from_dict({**raw, "public_key": "-----BEGIN PRIVATE KEY-----"})

    def test_file_backed_descriptors_contain_no_secrets(self):
        d = tempfile.TemporaryDirectory()
        FileBackedEd25519Provider.create(d.name)
        text = Path(d.name, "descriptors.json").read_text()
        self.assertNotIn("private", text.lower())
        self.assertNotIn("BEGIN", text)
        bundle = load_descriptor_bundle(json.loads(text))
        self.assertTrue(any(item.purpose.value == "permit" for item in bundle))
        d.cleanup()

    def test_kms_interface_is_unimplemented(self):
        kms = KMSHSMProvider()
        with self.assertRaises(NotImplementedError):
            kms.sign("k", b"x")
        with self.assertRaises(NotImplementedError):
            kms.public_descriptor("k")


class ExecutorImportGraphTests(unittest.TestCase):
    def test_executor_modules_do_not_import_signers(self):
        banned = {"faar.signing", "faar.authority_service"}
        for rel in ("faar/executor.py", "faar/gateway.py", "faar/treasury.py", "faar/descriptors.py"):
            tree = ast.parse(Path(rel).read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    self.assertNotIn(node.module, banned, rel)
                    self.assertFalse(node.module.startswith("faar.signing"), rel)
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self.assertNotIn(alias.name, banned, rel)
            source = Path(rel).read_text()
            self.assertNotIn("Ed25519PermitSigner", source)
            self.assertNotIn("Ed25519AttestationSigner", source)
            self.assertNotIn("ConstrainedPermitAuthority", source)
            self.assertNotIn("IsolatedPermitSigner", source)


class TreasuryGatewayTests(unittest.TestCase):
    def tearDown(self):
        if getattr(self, "store", None):
            self.store.close()

    def _setup(self, **kwargs):
        self.store, self.ledger, self.provider, self.service, self.executor = _world(**kwargs)
        return self.store, self.ledger, self.service, self.executor

    def _authorize(self, **changes):
        result = self.service.authorize(_payload(**changes))
        self.assertTrue(result.get("ok"), result)
        permit = parse_signed_permit(result["permit"])
        request = parse_execution_request(result["request"])
        return permit, request

    def test_authorized_pay_executes_exactly_once(self):
        self._setup()
        permit, request = self._authorize()
        first = self.executor.submit(request, permit, now=NOW)
        self.assertEqual(Decimal("25"), first.amount_usd)
        self.assertEqual("beneficiary:approved", first.beneficiary)
        self.assertEqual(Decimal("975"), self.ledger.get_balance("account:treasury-a"))
        self.assertEqual(Decimal("25"), self.ledger.get_balance("beneficiary:approved"))
        replay = self.executor.submit(request, permit, now=NOW)
        self.assertEqual(first.effect_id, replay.effect_id)
        self.assertEqual(Decimal("975"), self.ledger.get_balance("account:treasury-a"))
        self.assertEqual(1, self.executor.adapter.execute_call_count(request.intent_id, principal_id=PRINCIPAL))

    def test_amount_mutation_is_denied(self):
        self._setup()
        permit, request = self._authorize()
        mutated = ExecutionRequest(
            principal_id=request.principal_id,
            intent_id=request.intent_id,
            primitive=request.primitive,
            venue=request.venue,
            payload={**dict(request.payload), "amount_usd": "75"},
        )
        with self.assertRaises(GatewayDenial) as ctx:
            self.executor.submit(mutated, permit, now=NOW)
        self.assertTrue(any("PERMIT_REQUEST" in r or "HASH" in r for r in ctx.exception.reasons))
        self.assertEqual(Decimal("1000"), self.ledger.get_balance("account:treasury-a"))

    def test_beneficiary_substitution_is_denied(self):
        self._setup()
        self.ledger.set_balance("beneficiary:attacker", Decimal("0"))
        permit, request = self._authorize()
        mutated = ExecutionRequest(
            principal_id=request.principal_id,
            intent_id=request.intent_id,
            primitive=request.primitive,
            venue=request.venue,
            payload={**dict(request.payload), "target": "beneficiary:attacker"},
        )
        with self.assertRaises(GatewayDenial):
            self.executor.submit(mutated, permit, now=NOW)
        self.assertEqual(Decimal("0"), self.ledger.get_balance("beneficiary:attacker"))

    def test_delayed_execution_after_expiry_is_denied(self):
        self._setup()
        permit, request = self._authorize()
        with self.assertRaises(GatewayDenial) as ctx:
            self.executor.submit(request, permit, now=NOW + timedelta(seconds=30))
        self.assertTrue(any("EXPIRED" in r for r in ctx.exception.reasons))
        self.assertEqual(Decimal("1000"), self.ledger.get_balance("account:treasury-a"))

    def test_confused_deputy_wrong_venue_is_denied(self):
        self._setup()
        permit, request = self._authorize()
        mutated = ExecutionRequest(
            principal_id=request.principal_id,
            intent_id=request.intent_id,
            primitive=request.primitive,
            venue="mock-dex",
            payload=request.payload,
        )
        with self.assertRaises(GatewayDenial) as ctx:
            self.executor.submit(mutated, permit, now=NOW)
        self.assertIn("GATEWAY_VENUE_MISMATCH", ctx.exception.reasons)

    def test_crash_after_effect_before_receipt_recovers_once(self):
        self._setup(treasury_mode="TIMEOUT_AFTER_EFFECT")
        permit, request = self._authorize()
        first = self.executor.submit(request, permit, now=NOW)
        self.assertEqual(Decimal("25"), first.amount_usd)
        replay = self.executor.submit(request, permit, now=NOW)
        self.assertEqual(first.effect_id, replay.effect_id)
        self.assertEqual(Decimal("25"), self.ledger.get_balance("beneficiary:approved"))

    def test_daily_budget_is_enforced(self):
        self._setup()
        self.executor.gateway.limits = replace(self.executor.gateway.limits, daily_budget_usd=Decimal("10"))
        permit, request = self._authorize()
        with self.assertRaises(GatewayDenial) as ctx:
            self.executor.submit(request, permit, now=NOW)
        self.assertIn("GATEWAY_DAILY_BUDGET_EXCEEDED", ctx.exception.reasons)

    def test_malicious_verifier_descriptor_cannot_construct_executor(self):
        self._setup()
        raw = self.provider.export_descriptors()
        raw[0]["public_key"] = raw[0]["public_key"][:-2] + "AA"
        with self.assertRaises(ValueError):
            load_descriptor_bundle(raw)

    def test_stale_revoked_descriptor_is_rejected(self):
        provider = InMemoryEd25519Provider.generate()
        raw = [d for d in provider.export_descriptors() if d["purpose"] == "permit"][0]
        with self.assertRaisesRegex(ValueError, "DESCRIPTOR_REVOKED"):
            VerifierDescriptor.from_dict({**raw, "status": "REVOKED"})


class ExecutorProcessIsolationTests(unittest.TestCase):
    def test_spawned_executor_has_zero_private_keys_and_executes_once(self):
        tmp = tempfile.TemporaryDirectory()
        db = str(Path(tmp.name) / "faar.sqlite")
        keys = str(Path(tmp.name) / "keys")
        store = SQLiteIntentStore(db)
        ledger = SQLiteAuthorityLedger(store)
        provider = FileBackedEd25519Provider.create(keys)
        grant = _pay_grant()
        from faar.canonical import canonical_hash
        store.provision_grant(grant, canonical_hash(grant))
        ledger.bind_account(PRINCIPAL, "account:treasury-a")
        ledger.set_balance("account:treasury-a", Decimal("1000"))
        ledger.set_balance("beneficiary:approved", Decimal("0"))
        ledger.allow_beneficiary("account:treasury-a", "beneficiary:approved")
        service = AuthorityService(store, provider, allow_test_time_override=True, ledger=ledger)
        result = service.authorize(_payload())
        self.assertTrue(result["ok"], result)
        permit_path = Path(tmp.name) / "permit.json"
        request_path = Path(tmp.name) / "request.json"
        desc_path = Path(keys) / "descriptors.json"
        permit_path.write_text(json.dumps(result["permit"]))
        request_path.write_text(json.dumps(result["request"]))
        store.close()

        from v05_executor_worker import run
        ctx = mp.get_context("spawn")
        parent, child = ctx.Pipe()
        proc = ctx.Process(
            target=run,
            args=({
                "db": db,
                "descriptors": str(desc_path),
                "permit": str(permit_path),
                "request": str(request_path),
            }, child),
        )
        proc.start()
        proc.join(15)
        self.assertEqual(0, proc.exitcode)
        self.assertTrue(parent.poll())
        payload = parent.recv()
        self.assertEqual("25", payload["amount"])
        self.assertEqual(0, payload["private_key_objects"])
        self.assertFalse(payload["signing_imported"])
        self.assertFalse(payload["authority_imported"])
        tmp.cleanup()


if __name__ == "__main__":
    unittest.main()
