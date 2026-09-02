from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
EXAMPLES = ROOT / "examples"

try:  # jsonschema is an optional dev dependency; the structural checks below never need it.
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - exercised only when the dev extra is absent
    Draft202012Validator = None


PAIRS = {
    "intent.schema.json": "intent.json",
    "capability.schema.json": "grant.json",
    "risk-snapshot.schema.json": "risk.json",
    "authority-decision.schema.json": "authority.json",
    "task-contract.schema.json": "task-contract.json",
}


class SchemaExampleConsistencyTests(unittest.TestCase):
    def test_every_schema_is_valid_json_with_draft_2020_12(self):
        for path in sorted(SCHEMAS.glob("*.schema.json")):
            schema = json.loads(path.read_text())
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema.get("$schema"), path.name)
            self.assertFalse(schema.get("additionalProperties", True), f"{path.name} must close its top-level object")

    def test_examples_validate_against_their_schemas(self):
        if Draft202012Validator is None:
            self.skipTest("jsonschema not installed")
        for schema_name, example_name in PAIRS.items():
            schema = json.loads((SCHEMAS / schema_name).read_text())
            document = json.loads((EXAMPLES / example_name).read_text())
            errors = list(Draft202012Validator(schema).iter_errors(document))
            self.assertEqual([], [e.message for e in errors], f"{example_name} vs {schema_name}")


if __name__ == "__main__":
    unittest.main()
