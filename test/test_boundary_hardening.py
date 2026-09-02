from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from decimal import Decimal

from faar.adapters import DeterministicFailure, MockVenue
from faar.attestation import decode_ed25519_signature
from faar.canonical import canonical_hash, parse_bounded_decimal
from faar.gates import evaluate_capability, evaluate_risk
from faar.models import (
    Attestation,
    AttestationKind,
    EconomicPrimitive,
    ExecutionPermit,
    ExecutionRequest,
    Intent,
    OutcomeCriterion,
    OutcomeVerdict,
    SettlementRecord,
    SettlementStatus,
    SignedExecutionPermit,
    TaskContract,
    Verdict,
)
from faar.outcomes import verify_attested_task_outcome, verify_task_outcome
from faar.paper import PaperTradingVenue
from faar.parsing import parse_attestation, parse_grant, parse_intent, parse_risk
from faar.permits import ExecutionPermitVerifier
from faar.settlement import QuorumSettlementVerifier, REFERENCE_SETTLEMENT_PROFILE
from faar.store import SQLiteIntentStore
from support import AUTH, NOW, PRINCIPAL, attest_pair, grant, intent, permit_stack, risk, trust, verification_trust


def _payload(**changes):
    base = {"from_asset": "USDC", "to_asset": "MEME", "amount_usd": "50", "target": "router:approved"}
    base.update(changes)
    return base


class AmountGrammarTests(unittest.TestCase):
    def test_extreme_exponent_amount_is_denied_at_the_gate_not_reserved(self):
        # '1e-999999999' is finite and below every ceiling; formatting it as a
        # fixed-point string would allocate ~1 GB. It must never reach the store.
        for raw in ("1e-999999999", "1E+5", "1e-150", "5e1", "0.5e2"):
            decision = evaluate_capability(intent(payload=_payload(amount_usd=raw)), grant(), NOW)
            self.assertEqual(Verdict.DENY, decision.verdict, raw)
            self.assertIn("AMOUNT_INVALID_OR_NONFINITE", decision.reason_codes, raw)
        self.assertIsNone(parse_bounded_decimal("1e-999999999"))
        self.assertIsNone(parse_bounded_decimal(Decimal("1e-999999999")))
        self.assertIsNone(parse_bounded_decimal(10**5000))

    def test_non_canonical_numeric_strings_are_denied(self):
        for raw in (" 50 ", "50\n", "+50", "-50", "5_0", "٥٠", "50.", ".5", "1_000", "0050", ""):
            decision = evaluate_capability(intent(payload=_payload(amount_usd=raw)), grant(), NOW)
            self.assertEqual(Verdict.DENY, decision.verdict, repr(raw))

    def test_plain_decimal_strings_and_numbers_are_accepted(self):
        for raw in ("50", "50.00", "0.5", 50, 50.0, Decimal("50")):
            self.assertEqual(Decimal("50") if raw != "0.5" else Decimal("0.5"), parse_bounded_decimal(raw), repr(raw))
        self.assertIsNone(parse_bounded_decimal(True))
        self.assertIsNone(parse_bounded_decimal(float("nan")))
        self.assertIsNone(parse_bounded_decimal([50]))

    def test_dual_amount_fields_are_ambiguous_and_denied(self):
        g = grant(allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_assets=frozenset({"BTC", "USD"}), allowed_targets=frozenset())
        i = intent(primitive=EconomicPrimitive.BUY, payload={"base_asset": "BTC", "quote_asset": "USD", "amount_usd": "1", "notional_usd": "1000"})
        decision = evaluate_capability(i, g, NOW)
        self.assertEqual(Verdict.DENY, decision.verdict)
        self.assertIn("AMOUNT_FIELDS_AMBIGUOUS", decision.reason_codes)
        ok = intent(primitive=EconomicPrimitive.BUY, payload={"base_asset": "BTC", "quote_asset": "USD", "notional_usd": "10"})
        self.assertEqual(Verdict.ALLOW, evaluate_capability(ok, g, NOW).verdict)

    def test_swap_identical_assets_detected_on_normalised_value(self):
        g = grant(allowed_assets=frozenset({"0", "USDC"}))
        for from_asset, to_asset in ((0, 0), (0, "0"), ("USDC", "USDC")):
            decision = evaluate_capability(intent(payload=_payload(from_asset=from_asset, to_asset=to_asset)), g, NOW)
            self.assertIn("SWAP_ASSETS_IDENTICAL", decision.reason_codes, (from_asset, to_asset))

    def test_only_target_key_names_the_counterparty(self):
        decision = evaluate_capability(intent(payload={**_payload(), "counterparty": "router:approved"}), grant(), NOW)
        self.assertEqual(Verdict.DENY, decision.verdict)
        self.assertTrue(any(r.startswith("UNKNOWN_EXECUTION_FIELDS") for r in decision.reason_codes))


class RiskVerdictTests(unittest.TestCase):
    def test_limit_breach_is_a_deny_while_missing_or_stale_data_defers(self):
        breach = evaluate_risk(intent(), grant(), risk(daily_loss_usd=Decimal("500")), NOW)
        self.assertEqual(Verdict.DENY, breach.verdict)
        self.assertIn("MAX_DAILY_LOSS_USD_EXCEEDED", breach.reason_codes)
        stale = evaluate_risk(intent(), grant(), risk(market_data_age_seconds=999), NOW)
        self.assertEqual(Verdict.DEFER, stale.verdict)
        missing = evaluate_risk(intent(), grant(), risk(position_after_usd=None), NOW)
        self.assertEqual(Verdict.DEFER, missing.verdict)


class ModelBoundaryTests(unittest.TestCase):
    def test_payload_must_be_a_json_object(self):
        for bad in (["from_asset"], "text", 5, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                intent(payload=bad)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            intent(metadata=["x"])  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            ExecutionRequest(PRINCIPAL, "intent_test_000000000001", EconomicPrimitive.SWAP, "v", ["x"])  # type: ignore[arg-type]

    def test_identifiers_are_bounded_and_schema_version_is_checked(self):
        with self.assertRaises(ValueError):
            intent(intent_id="x" * 5_000_000)
        with self.assertRaises(ValueError):
            intent(intent_id="short")
        with self.assertRaises(ValueError):
            intent(venue="v" * 129)
        with self.assertRaises(ValueError):
            intent(schema_version="0.2")
        with self.assertRaises(ValueError):
            grant(grant_id="")

    def test_huge_ints_and_naive_datetimes_fail_at_construction(self):
        with self.assertRaises(ValueError):
            intent(grant_version=10**5000)
        with self.assertRaises(ValueError):
            intent(payload=_payload(limit_price=datetime(2026, 1, 1)))

    def test_attestation_kind_string_is_coerced(self):
        i = intent()
        aa, _ = attest_pair(trust(), i, AUTH, risk(), NOW)
        as_str = Attestation("AUTHORITY", aa.key_id, aa.algorithm, aa.subject_hash, aa.intent_hash, aa.issued_at, aa.expires_at, aa.signature)  # type: ignore[arg-type]
        self.assertIs(AttestationKind.AUTHORITY, as_str.kind)
        with self.assertRaises(ValueError):
            Attestation("BOGUS", aa.key_id, aa.algorithm, aa.subject_hash, aa.intent_hash, aa.issued_at, aa.expires_at, aa.signature)  # type: ignore[arg-type]


class ParsingBoundaryTests(unittest.TestCase):
    GRANT = {
        "schema_version": "0.3", "principal_id": "p", "grant_id": "g", "version": 1, "actor_id": "a", "status": "ACTIVE",
        "allowed_primitives": ["SWAP"], "allowed_venues": ["v"], "allowed_assets": ["USDC", "MEME"], "allowed_targets": ["r"],
        "limits": {"max_order_usd": "75", "max_daily_turnover_usd": "1500", "max_actions_per_window": 10, "action_window_seconds": 60},
    }

    def test_misspelled_limit_or_top_level_key_is_rejected(self):
        parse_grant(self.GRANT)
        with self.assertRaises(ValueError):
            parse_grant({**self.GRANT, "limits": {**self.GRANT["limits"], "max_daily_lose_usd": "5"}})
        with self.assertRaises(ValueError):
            parse_grant({**self.GRANT, "denied_target": ["evil"]})
        with self.assertRaises(ValueError):
            parse_risk({"observed_at": NOW.isoformat(), "state_version": 1, "scope": "portfolio", "circuit_breaker": True})

    def test_falsy_timestamps_are_not_none(self):
        with self.assertRaises(ValueError):
            parse_grant({**self.GRANT, "valid_until": ""})
        with self.assertRaises(ValueError):
            parse_grant({**self.GRANT, "valid_until": 0})
        base = {
            "schema_version": "0.3", "principal_id": "p", "intent_id": "intent_parse_000000001", "actor_id": "a", "grant_id": "g",
            "grant_version": 1, "primitive": "SWAP", "venue": "v", "created_at": "", "expires_at": NOW.isoformat(), "payload": _payload(),
        }
        with self.assertRaises(ValueError):
            parse_intent(base)
        with self.assertRaises(ValueError):
            parse_intent({**base, "created_at": NOW.isoformat(), "payload": []})
        with self.assertRaises(ValueError):
            parse_attestation({
                "kind": "AUTHORITY", "key_id": "k", "algorithm": "ED25519", "subject_hash": "a" * 64, "intent_hash": "b" * 64,
                "issued_at": "", "expires_at": NOW.isoformat(), "signature": "x",
            })


class AttestationLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self.store = SQLiteIntentStore(self.tmp.name)
        self.store.provision_grant(grant(), canonical_hash(grant()))
        self.trust = trust()

    def tearDown(self):
        self.store.close()

    def test_attestation_expiry_is_exact_not_extended_by_skew(self):
        i = intent()
        aa = self.trust.sign("authority-test", AttestationKind.AUTHORITY, AUTH, i, issued_at=NOW, ttl_seconds=1)
        verifier = verification_trust(self.trust)
        ok, _ = verifier.verify(aa, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=i, now=NOW + timedelta(seconds=1))
        self.assertTrue(ok)
        ok, reasons = verifier.verify(aa, kind=AttestationKind.AUTHORITY, subject=AUTH, intent=i, now=NOW + timedelta(seconds=1, microseconds=1))
        self.assertFalse(ok)
        self.assertIn("ATTESTATION_EXPIRED", reasons)

    def test_permit_never_outlives_the_attestations_it_derives_from(self):
        i = intent()
        rs = risk()
        aa = self.trust.sign("authority-test", AttestationKind.AUTHORITY, AUTH, i, issued_at=NOW, ttl_seconds=2)
        ra = self.trust.sign("risk-test", AttestationKind.RISK, rs, i, issued_at=NOW, ttl_seconds=30)
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), rs, NOW)[0])
        authority, _ = permit_stack(self.store, self.trust)
        signed = authority.issue(
            ExecutionRequest.from_intent(i), intent=i, authority=AUTH, grant=grant(), risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )
        self.assertLessEqual(signed.permit.expires_at, aa.expires_at)

    def test_non_canonical_signature_encodings_are_rejected(self):
        i = intent()
        rs = risk()
        aa, _ = attest_pair(self.trust, i, AUTH, rs, NOW)
        verifier = verification_trust(self.trust)
        self.assertIsNotNone(decode_ed25519_signature(aa.signature))
        last = aa.signature[-1]
        alternates = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" if c != last]
        variants = [aa.signature + "==", aa.signature + "!!!!", aa.signature.replace("-", "+").replace("_", "/") + "=="]
        variants += [aa.signature[:-1] + c for c in alternates[:8]]
        rejected = 0
        for variant in variants:
            if variant == aa.signature:
                continue
            ok, reasons = verifier.verify(replace(aa, signature=variant), kind=AttestationKind.AUTHORITY, subject=AUTH, intent=i, now=NOW)
            if not ok and "ATTESTATION_SIGNATURE_INVALID" in reasons:
                rejected += 1
        self.assertEqual(len([v for v in variants if v != aa.signature]), rejected)


class PermitVerifierBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self.tmp.close()
        self.store = SQLiteIntentStore(self.tmp.name)
        self.store.provision_grant(grant(), canonical_hash(grant()))
        self.trust = trust()
        self.authority, self.verifier = permit_stack(self.store, self.trust)

    def tearDown(self):
        self.store.close()

    def _issue(self, i=None):
        i = i or intent()
        rs = risk()
        aa, ra = attest_pair(self.trust, i, AUTH, rs, NOW)
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        return request, self.authority.issue(
            request, intent=i, authority=AUTH, grant=grant(), risk=rs,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )

    def test_relabelled_signer_or_algorithm_breaks_the_signature(self):
        from faar.permits import Ed25519PermitSigner, ExecutionPermitVerifier
        request, signed = self._issue()
        ok, reasons = self.verifier.verify(replace(signed, signer_id="someone-else"), request, now=NOW)
        self.assertFalse(ok)
        self.assertEqual(("PERMIT_SIGNER_UNKNOWN",), reasons)
        # With a second trusted signer, relabelling a permit to that signer must
        # fail the signature itself: signer_id is inside the signed payload.
        other = Ed25519PermitSigner("other-trusted-signer")
        gateway = ExecutionPermitVerifier(
            {self.verifier.signature.signer_id: self.verifier.signature, other.signer_id: other.public_verifier()}, self.store,
        )
        self.assertTrue(gateway.verify(signed, request, now=NOW)[0])
        ok, reasons = gateway.verify(replace(signed, signer_id=other.signer_id), request, now=NOW)
        self.assertFalse(ok)
        self.assertIn("PERMIT_SIGNATURE_INVALID", reasons)

    def test_malformed_permit_is_a_deterministic_rejection_not_an_exception(self):
        request, signed = self._issue()
        with self.assertRaises(ValueError):
            SignedExecutionPermit({"not": "a permit"}, signed.signer_id, signed.algorithm, signed.signature)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            replace(signed.permit, max_amount_usd=Decimal("1E-150"))
        bogus = object.__new__(SignedExecutionPermit)
        object.__setattr__(bogus, "permit", {"not": "a permit"})
        object.__setattr__(bogus, "signer_id", signed.signer_id)
        object.__setattr__(bogus, "algorithm", signed.algorithm)
        object.__setattr__(bogus, "signature", signed.signature)
        ok, reasons = self.verifier.verify(bogus, request, now=NOW)
        self.assertFalse(ok)
        self.assertEqual(("PERMIT_MALFORMED",), reasons)
        venue = MockVenue(permit_verifier=self.verifier, name="mock-dex", clock=lambda: NOW)
        with self.assertRaises(DeterministicFailure):
            venue.execute(request, bogus)


def _src(name, record):
    class Source:
        security_profile = REFERENCE_SETTLEMENT_PROFILE

        def __init__(self):
            self.name = name

        def verify(self, request):
            if isinstance(record, BaseException):
                raise record
            return record(request) if callable(record) else record
    return Source()


class SettlementHardeningTests(unittest.TestCase):
    def setUp(self):
        self.request = ExecutionRequest.from_intent(intent())
        self.hash = canonical_hash(self.request)

    def _final(self, amount, evidence=None):
        return SettlementRecord(
            SettlementStatus.FINALIZED, "fx-1", Decimal(amount), evidence=evidence or {"fill": {"to_quantity": "100"}},
            authoritative=True, verified_request_hash=self.hash,
        )

    def test_agreeing_sources_at_different_decimal_scales_reach_quorum(self):
        record = QuorumSettlementVerifier([_src("a", self._final("50")), _src("b", self._final("50.00"))], quorum=2).verify(self.request)
        self.assertEqual(SettlementStatus.FINALIZED, record.status)
        disagree = QuorumSettlementVerifier([_src("a", self._final("50")), _src("b", self._final("50.01"))], quorum=2).verify(self.request)
        self.assertEqual(SettlementStatus.CONTRADICTORY, disagree.status)

    def test_one_raising_minority_source_does_not_wedge_the_quorum(self):
        record = QuorumSettlementVerifier(
            [_src("a", self._final("50")), _src("b", self._final("50")), _src("c", TimeoutError("down"))], quorum=2,
        ).verify(self.request)
        self.assertEqual(SettlementStatus.FINALIZED, record.status)
        self.assertEqual({"c": "TimeoutError"}, dict(record.evidence["errors"]))
        short = QuorumSettlementVerifier(
            [_src("a", self._final("50")), _src("b", TimeoutError("down")), _src("c", TimeoutError("down"))], quorum=2,
        ).verify(self.request)
        self.assertEqual(SettlementStatus.CONTRADICTORY, short.status, "one authoritative vote below quorum stays contested")

    def test_quorum_carries_agreeing_evidence_for_definition_of_done(self):
        record = QuorumSettlementVerifier([_src("a", self._final("50")), _src("b", self._final("50"))], quorum=2).verify(self.request)
        contract = TaskContract("task-q", self.request.intent_id, "filled", (OutcomeCriterion("fill.to_quantity", "gte", "100"),), NOW, NOW + timedelta(hours=1))
        self.assertEqual(OutcomeVerdict.MET, verify_task_outcome(contract, record).verdict)
        self.assertIn("a", record.evidence["source_evidence"])

    def test_paper_reconcile_binds_effect_to_the_executing_request(self):
        store = SQLiteIntentStore(":memory:")
        store.provision_grant(grant(allowed_venues=frozenset({"paper-dex"})), canonical_hash(grant(allowed_venues=frozenset({"paper-dex"}))))
        t = trust()
        authority, verifier = permit_stack(store, t)
        venue = PaperTradingVenue("paper-dex", {"MEME": Decimal("0.5")}, verifier, balances={"USDC": Decimal("1000")}, clock=lambda: NOW)
        i = intent(venue="paper-dex")
        rs = risk()
        aa, ra = attest_pair(t, i, AUTH, rs, NOW)
        store.register(i, canonical_hash(i))
        g = grant(allowed_venues=frozenset({"paper-dex"}))
        self.assertTrue(store.reserve_usage(i, g, rs, NOW)[0])
        request = ExecutionRequest.from_intent(i)
        permit = authority.issue(request, intent=i, authority=AUTH, grant=g, risk=rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
        venue.execute(request, permit)
        self.assertEqual(SettlementStatus.FINALIZED, venue.reconcile(request).status)
        forged = ExecutionRequest(i.principal_id, i.intent_id, EconomicPrimitive.SWAP, "paper-dex", _payload(amount_usd="5000", target="attacker"))
        self.assertEqual(SettlementStatus.CONTRADICTORY, venue.reconcile(forged).status)


class OutcomeBindingTests(unittest.TestCase):
    def test_settlement_of_another_intent_cannot_satisfy_the_contract(self):
        t = trust()
        i = intent(intent_id="intent_test_0000000000AA")
        other = intent(intent_id="intent_test_0000000000BB", payload=_payload(amount_usd="70"))
        contract = TaskContract("task-bind", i.intent_id, "settled swap", (OutcomeCriterion("effect_id", "present"),), NOW, NOW + timedelta(hours=1))
        attestation = t.sign("task-test", AttestationKind.TASK, contract, i, issued_at=NOW, ttl_seconds=60)
        foreign = SettlementRecord(
            SettlementStatus.FINALIZED, "fx-other", Decimal("70"), authoritative=True,
            verified_request_hash=canonical_hash(ExecutionRequest.from_intent(other)),
        )
        result = verify_attested_task_outcome(contract, foreign, attestation=attestation, intent=i, trust=verification_trust(t), now=NOW)
        self.assertEqual(OutcomeVerdict.UNKNOWN, result.verdict)
        self.assertIn("TASK_SETTLEMENT_INTENT_MISMATCH", result.reason_codes)
        own = replace(foreign, verified_request_hash=canonical_hash(ExecutionRequest.from_intent(i)))
        self.assertEqual(OutcomeVerdict.MET, verify_attested_task_outcome(contract, own, attestation=attestation, intent=i, trust=verification_trust(t), now=NOW).verdict)

    def test_equality_is_numeric_for_numbers_and_never_conflates_booleans(self):
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED, "fx", Decimal("50"), evidence={"flag": True, "count": 1, "qty": "100.0"},
            authoritative=True, verified_request_hash="h",
        )

        def verdict(path, op, value):
            contract = TaskContract("task-eq", "intent_test_000000000001", "o", (OutcomeCriterion(path, op, value),), NOW, NOW + timedelta(hours=1))
            return verify_task_outcome(contract, settlement).verdict

        self.assertEqual(OutcomeVerdict.MET, verdict("amount_usd", "eq", "50"))
        self.assertEqual(OutcomeVerdict.MET, verdict("amount_usd", "eq", "50.00"))
        self.assertEqual(OutcomeVerdict.MET, verdict("qty", "eq", "100"))
        self.assertEqual(OutcomeVerdict.NOT_MET, verdict("count", "eq", True))
        self.assertEqual(OutcomeVerdict.NOT_MET, verdict("flag", "eq", 1))
        self.assertEqual(OutcomeVerdict.MET, verdict("flag", "eq", True))

    def test_contract_issued_within_skew_is_accepted_but_far_future_is_not(self):
        t = trust()
        i = intent()
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED, "fx", Decimal("50"), authoritative=True,
            verified_request_hash=canonical_hash(ExecutionRequest.from_intent(i)),
        )
        near = TaskContract("task-near", i.intent_id, "o", (OutcomeCriterion("effect_id", "present"),), NOW + timedelta(seconds=1), NOW + timedelta(minutes=5))
        att = t.sign("task-test", AttestationKind.TASK, near, i, issued_at=NOW + timedelta(seconds=1), ttl_seconds=60)
        self.assertEqual(OutcomeVerdict.MET, verify_attested_task_outcome(near, settlement, attestation=att, intent=i, trust=verification_trust(t), now=NOW).verdict)
        far = replace(near, issued_at=NOW + timedelta(seconds=60))
        att_far = t.sign("task-test", AttestationKind.TASK, far, i, issued_at=NOW + timedelta(seconds=1), ttl_seconds=60)
        result = verify_attested_task_outcome(far, settlement, attestation=att_far, intent=i, trust=verification_trust(t), now=NOW)
        self.assertEqual(OutcomeVerdict.UNKNOWN, result.verdict)
        self.assertIn("TASK_CONTRACT_FROM_FUTURE", result.reason_codes)


if __name__ == "__main__":
    unittest.main()
