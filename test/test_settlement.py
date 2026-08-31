from __future__ import annotations

import unittest
from dataclasses import dataclass
from decimal import Decimal

from faar.canonical import canonical_hash
from faar.models import ExecutionReceipt, ExecutionRequest, EconomicPrimitive, SettlementRecord, SettlementStatus
from faar.settlement import MockSettlementVerifier, QuorumSettlementVerifier, REFERENCE_SETTLEMENT_PROFILE


@dataclass
class Source:
    record: SettlementRecord
    name: str
    security_profile = REFERENCE_SETTLEMENT_PROFILE
    def verify(self, request):
        return self.record


REQ = ExecutionRequest(
    principal_id="principal:test", intent_id="settlement-quorum-1", primitive=EconomicPrimitive.SWAP,
    venue="v", payload={"from_asset": "USDC", "to_asset": "MEME", "amount_usd": "50", "target": "r"},
)

REQ_HASH = canonical_hash(REQ)


class SettlementQuorumTests(unittest.TestCase):
    def test_two_source_positive_quorum(self):
        record = SettlementRecord(SettlementStatus.FINALIZED, "fx-1", Decimal("50"), authoritative=True, verified_request_hash=REQ_HASH)
        q = QuorumSettlementVerifier([Source(record, "a"), Source(record, "b")], quorum=2)
        result = q.verify(REQ)
        self.assertTrue(result.authoritative)
        self.assertEqual(SettlementStatus.FINALIZED, result.status)
        self.assertEqual("fx-1", result.effect_id)

    def test_disagreement_is_contradictory_not_majority_guess(self):
        a = SettlementRecord(SettlementStatus.FINALIZED, "fx-1", Decimal("50"), authoritative=True, verified_request_hash=REQ_HASH)
        b = SettlementRecord(SettlementStatus.NONE, authoritative=True, verified_request_hash=REQ_HASH)
        q = QuorumSettlementVerifier([Source(a, "a"), Source(b, "b")], quorum=2)
        result = q.verify(REQ)
        self.assertEqual(SettlementStatus.CONTRADICTORY, result.status)
        self.assertTrue(result.authoritative)

    def test_non_authoritative_source_cannot_form_quorum(self):
        good = SettlementRecord(SettlementStatus.FINALIZED, "fx-1", Decimal("50"), authoritative=True, verified_request_hash=REQ_HASH)
        weak = SettlementRecord(SettlementStatus.FINALIZED, "fx-1", Decimal("50"), authoritative=False)
        q = QuorumSettlementVerifier([Source(good, "a"), Source(weak, "b")], quorum=2)
        result = q.verify(REQ)
        self.assertEqual(SettlementStatus.CONTRADICTORY, result.status)
    def test_authoritative_source_for_different_request_is_not_counted(self):
        wrong = SettlementRecord(
            SettlementStatus.FINALIZED, "fx-wrong", Decimal("50"), authoritative=True,
            verified_request_hash="not-the-request-hash",
        )
        q = QuorumSettlementVerifier([Source(wrong, "a"), Source(wrong, "b")], quorum=2)
        result = q.verify(REQ)
        self.assertEqual(SettlementStatus.CONTRADICTORY, result.status)
        self.assertTrue(result.authoritative)
        self.assertEqual(REQ_HASH, result.verified_request_hash)


    def test_duplicate_source_identity_is_rejected(self):
        record = SettlementRecord(
            SettlementStatus.FINALIZED, "fx-1", Decimal("50"),
            authoritative=True, verified_request_hash=REQ_HASH,
        )
        with self.assertRaisesRegex(ValueError, "unique identities"):
            QuorumSettlementVerifier([Source(record, "same"), Source(record, "same")], quorum=2)

    def test_same_verifier_object_cannot_count_twice(self):
        record = SettlementRecord(
            SettlementStatus.FINALIZED, "fx-1", Decimal("50"),
            authoritative=True, verified_request_hash=REQ_HASH,
        )
        source = Source(record, "only-one")
        with self.assertRaisesRegex(ValueError, "same settlement verifier object"):
            QuorumSettlementVerifier([source, source], quorum=2)

    def test_observed_effect_must_bind_exact_execution_request(self):
        class WronglyBoundVenue:
            mode = "SUCCESS"
            def lookup_effect(self, request):
                return ExecutionReceipt(
                    "fx-rebound", SettlementStatus.FINALIZED,
                    {"request_hash": "hash-for-a-different-request"}, Decimal("50"),
                )
        result = MockSettlementVerifier(WronglyBoundVenue()).verify(REQ)
        self.assertTrue(result.authoritative)
        self.assertEqual(SettlementStatus.CONTRADICTORY, result.status)
        self.assertEqual(REQ_HASH, result.verified_request_hash)
        self.assertEqual("observed-effect-request-binding-mismatch", result.evidence["reason"])


if __name__ == "__main__":
    unittest.main()
