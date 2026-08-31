from __future__ import annotations

import unittest
from decimal import Decimal
from dataclasses import replace

from faar.canonical import canonical_hash
from faar.models import OutcomeCriterion, TaskContract
from support import NOW, intent


class CanonicalizationTests(unittest.TestCase):
    def test_tuple_order_is_preserved_in_hash(self):
        a = TaskContract(
            "task-a",
            intent().intent_id,
            "ordered criteria test",
            (OutcomeCriterion("a", "eq", 1), OutcomeCriterion("b", "eq", 2)),
            NOW,
            NOW.replace(hour=19),
        )
        b = replace(a, criteria=tuple(reversed(a.criteria)))
        self.assertNotEqual(canonical_hash(a), canonical_hash(b))

    def test_intent_payload_is_deep_frozen_against_source_mutation(self):
        raw = {"target": "router-A", "nested": {"amount": "25"}, "route": ["A", "B"]}
        i = intent(payload=raw)
        before = canonical_hash(i)
        raw["target"] = "router-B"
        raw["nested"]["amount"] = "99999"
        raw["route"].append("EVIL")
        self.assertEqual("router-A", i.payload["target"])
        self.assertEqual("25", i.payload["nested"]["amount"])
        self.assertEqual(("A", "B"), i.payload["route"])
        self.assertEqual(before, canonical_hash(i))
        with self.assertRaises(TypeError):
            i.payload["target"] = "router-B"

    def test_extreme_decimal_exponent_is_rejected_before_serialization(self):
        from faar.canonical import canonical_json
        with self.assertRaisesRegex(ValueError, "Decimal .* bounds"):
            canonical_json({"amount": Decimal("1e100000000")})


if __name__ == "__main__":
    unittest.main()
