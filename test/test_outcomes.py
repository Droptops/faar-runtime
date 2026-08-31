from __future__ import annotations

import unittest
from dataclasses import replace
from decimal import Decimal

from faar.models import (
    AttestationKind,
    OutcomeCriterion,
    OutcomeVerdict,
    SettlementRecord,
    SettlementStatus,
    TaskContract,
)
from faar.outcomes import verify_attested_task_outcome, verify_task_outcome
from support import NOW, intent, trust, verification_trust


class OutcomeTests(unittest.TestCase):
    def test_finalized_effect_is_not_automatically_done(self):
        contract = TaskContract(
            task_id="task-1",
            intent_id="intent_test_000000000001",
            objective="Receive at least 100 MEME for no more than the authorized notional",
            criteria=(OutcomeCriterion("fill.to_quantity", "gte", "100"),),
            issued_at=NOW,
            expires_at=NOW.replace(hour=19),
        )
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED,
            effect_id="fx-1",
            evidence={"fill": {"to_quantity": "90"}},
            authoritative=True, verified_request_hash="outcome-test-request",
        )
        result = verify_task_outcome(contract, settlement)
        self.assertEqual(OutcomeVerdict.NOT_MET, result.verdict)

    def test_attested_definition_of_done_can_pass(self):
        i = intent()
        contract = TaskContract(
            task_id="task-2",
            intent_id=i.intent_id,
            objective="Receive at least 100 MEME",
            criteria=(
                OutcomeCriterion("fill.to_quantity", "gte", "100"),
                OutcomeCriterion("fill.to_asset", "eq", "MEME"),
            ),
            issued_at=NOW,
            expires_at=NOW.replace(hour=19),
        )
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED,
            effect_id="fx-2",
            evidence={"fill": {"to_quantity": "100", "to_asset": "MEME"}},
            authoritative=True, verified_request_hash="outcome-test-request",
        )
        t = trust()
        att = t.sign("task-test", AttestationKind.TASK, contract, i, issued_at=NOW, ttl_seconds=30)
        result = verify_attested_task_outcome(contract, settlement, attestation=att, intent=i, trust=verification_trust(t), now=NOW)
        self.assertEqual(OutcomeVerdict.MET, result.verdict)

    def test_agent_cannot_rewrite_attested_done_criteria(self):
        i = intent()
        contract = TaskContract(
            task_id="task-3",
            intent_id=i.intent_id,
            objective="Receive at least 100 MEME",
            criteria=(OutcomeCriterion("fill.to_quantity", "gte", "100"),),
            issued_at=NOW,
            expires_at=NOW.replace(hour=19),
        )
        t = trust()
        att = t.sign("task-test", AttestationKind.TASK, contract, i, issued_at=NOW, ttl_seconds=30)
        weakened = replace(contract, criteria=(OutcomeCriterion("fill.to_quantity", "gte", "1"),))
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED,
            effect_id="fx-3",
            evidence={"fill": {"to_quantity": "1"}},
            authoritative=True, verified_request_hash="outcome-test-request",
        )
        result = verify_attested_task_outcome(weakened, settlement, attestation=att, intent=i, trust=verification_trust(t), now=NOW)
        self.assertEqual(OutcomeVerdict.UNKNOWN, result.verdict)
        self.assertIn("TASK_ATTESTATION_SUBJECT_MISMATCH", result.reason_codes)

    def test_outcome_requires_authoritative_final_settlement(self):
        contract = TaskContract(
            task_id="task-4", intent_id="intent_test_000000000001", objective="settled",
            criteria=(OutcomeCriterion("effect_id", "present"),),
            issued_at=NOW, expires_at=NOW.replace(hour=19),
        )
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED, effect_id="fx-weak", amount_usd=Decimal("50"),
            evidence={}, authoritative=False,
        )
        result = verify_task_outcome(contract, settlement)
        self.assertEqual(OutcomeVerdict.UNKNOWN, result.verdict)
        self.assertIn("SETTLEMENT_NOT_AUTHORITATIVE", result.reason_codes)

    def test_standard_settlement_fields_are_definition_of_done_inputs(self):
        contract = TaskContract(
            task_id="task-5", intent_id="intent_test_000000000001", objective="bounded effect",
            criteria=(
                OutcomeCriterion("effect_id", "present"),
                OutcomeCriterion("amount_usd", "lte", "50"),
                OutcomeCriterion("status", "eq", "FINALIZED"),
            ),
            issued_at=NOW, expires_at=NOW.replace(hour=19),
        )
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED, effect_id="fx-standard", amount_usd=Decimal("50"),
            evidence={"effect_id": "attacker-shadow-value", "amount_usd": "9999"}, authoritative=True, verified_request_hash="outcome-test-request",
        )
        result = verify_task_outcome(contract, settlement)
        self.assertEqual(OutcomeVerdict.MET, result.verdict)
        self.assertEqual("fx-standard", result.evaluated["effect_id"])
        self.assertEqual(Decimal("50"), result.evaluated["amount_usd"])

    def test_expired_task_contract_cannot_be_reused(self):
        i = intent(intent_id="intent_test_000000000049")
        contract = TaskContract(
            task_id="task-6", intent_id=i.intent_id, objective="settled",
            criteria=(OutcomeCriterion("effect_id", "present"),),
            issued_at=NOW, expires_at=NOW.replace(minute=1),
        )
        t = trust()
        att = t.sign("task-test", AttestationKind.TASK, contract, i, issued_at=NOW, ttl_seconds=3600)
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED, effect_id="fx-old-task", amount_usd=Decimal("50"),
            authoritative=True, verified_request_hash="outcome-test-request",
        )
        result = verify_attested_task_outcome(
            contract, settlement, attestation=att, intent=i, trust=verification_trust(t), now=NOW.replace(minute=2)
        )
        self.assertEqual(OutcomeVerdict.UNKNOWN, result.verdict)
        self.assertIn("TASK_CONTRACT_EXPIRED", result.reason_codes)

    def test_future_dated_task_contract_cannot_be_used(self):
        i = intent(intent_id="intent_test_000000000051")
        contract = TaskContract(
            task_id="task-7", intent_id=i.intent_id, objective="settled",
            criteria=(OutcomeCriterion("effect_id", "present"),),
            issued_at=NOW.replace(minute=1), expires_at=NOW.replace(minute=3),
        )
        t = trust()
        att = t.sign(
            "task-test", AttestationKind.TASK, contract, i,
            issued_at=NOW, ttl_seconds=180,
        )
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED, effect_id="fx-future-task", amount_usd=Decimal("50"),
            authoritative=True, verified_request_hash="outcome-test-request",
        )
        result = verify_attested_task_outcome(
            contract, settlement, attestation=att, intent=i, trust=verification_trust(t), now=NOW
        )
        self.assertEqual(OutcomeVerdict.UNKNOWN, result.verdict)
        self.assertIn("TASK_CONTRACT_FROM_FUTURE", result.reason_codes)


if __name__ == "__main__":
    unittest.main()
