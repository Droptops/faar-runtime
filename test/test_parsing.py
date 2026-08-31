from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from faar.cli import _load
from faar.parsing import parse_risk
from support import NOW


class ParsingTests(unittest.TestCase):
    def _base(self):
        return {
            "observed_at": NOW.isoformat(),
            "state_version": 1,
            "scope": "portfolio",
            "actions_in_window": 0,
            "circuit_breaker_active": False,
            "data_complete": True,
            "source_count": 2,
            "sources_agree": True,
        }

    def test_string_false_cannot_bypass_data_complete(self):
        data = self._base()
        data["data_complete"] = "false"
        with self.assertRaises(ValueError):
            parse_risk(data)

    def test_string_integer_is_rejected_at_typed_boundary(self):
        data = self._base()
        data["market_data_age_seconds"] = "0"
        with self.assertRaises(ValueError):
            parse_risk(data)

    def test_cli_json_loader_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text('{"state_version":1,"state_version":2}')
            with self.assertRaises(ValueError):
                _load(str(p))

    def test_cli_json_loader_rejects_nonfinite_constants(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad.json"
            p.write_text('{"amount":NaN}')
            with self.assertRaises(ValueError):
                _load(str(p))


if __name__ == "__main__":
    unittest.main()
