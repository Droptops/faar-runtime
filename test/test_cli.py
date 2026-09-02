"""Operator CLI smoke tests: every command produces JSON and the dangerous ones fail closed."""
from __future__ import annotations

import io
import json
import os
import sqlite3
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from faar import cli
from faar.canonical import canonical_hash
from faar.store import SQLiteIntentStore
from support import PRINCIPAL, grant, intent, temp_path

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "examples"


class OperatorCliTests(unittest.TestCase):
    def setUp(self):
        self.db = temp_path(self)
        self.anchor = temp_path(self, ".anchor.json")

    def run_cli(self, *argv, expect_exit=None):
        out = io.StringIO()
        with redirect_stdout(out):
            if expect_exit is None:
                cli.main(list(argv))
            else:
                with self.assertRaises(SystemExit) as ctx:
                    cli.main(list(argv))
                self.assertEqual(expect_exit, ctx.exception.code)
        text = out.getvalue().strip()
        return json.loads(text) if text else None

    def test_demo_flow_and_operator_commands(self):
        provisioned = self.run_cli("provision-grant", "--grant", str(EX / "grant.json"), "--db", self.db, "--anchor", self.anchor)
        self.assertEqual("grant:demo", provisioned["grant_id"])
        result = self.run_cli(
            "mock-run", "--intent", str(EX / "intent.json"), "--grant", str(EX / "grant.json"),
            "--risk", str(EX / "risk.json"), "--authority", str(EX / "authority.json"), "--db", self.db, "--anchor", self.anchor,
        )
        self.assertEqual("FINALIZED", result["state"])
        self.assertEqual(1, result["successful_effect_count"])

        grants = self.run_cli("list-grants", "--db", self.db, "--anchor", self.anchor)
        self.assertEqual(["ACTIVE"], [g["effective_status"] for g in grants])
        intents = self.run_cli("list-intents", "--state", "FINALIZED", "--db", self.db)
        self.assertEqual(["intent_demo_000000000001"], [i["intent_id"] for i in intents])
        self.assertEqual([], self.run_cli("held-usage", "--db", self.db))
        self.assertEqual([], self.run_cli("list-leases", "--db", self.db))

        keyed = self.run_cli("verify-evidence", "--intent-id", "intent_demo_000000000001", "--db", self.db, "--demo-evidence-key", expect_exit=0)
        self.assertEqual({"evidence_chain_valid": True, "keyed": True, "status": "ok"}, {k: keyed[k] for k in ("evidence_chain_valid", "keyed", "status")})
        missing = self.run_cli("verify-evidence", "--intent-id", "intent_that_never_existed", "--db", self.db, expect_exit=2)
        self.assertEqual("unknown_intent", missing["status"])

        halted = self.run_cli("halt", "--scope", "global", "--reason", "drill", "--db", self.db, "--anchor", self.anchor)
        self.assertEqual(1, halted["grant_versions_fenced"])
        self.assertEqual("HALTED", self.run_cli("list-grants", "--db", self.db, "--anchor", self.anchor)[0]["effective_status"])
        self.assertEqual(1, self.run_cli("controls", "--db", self.db)[0]["halted"])
        self.run_cli("resume", "--scope", "global", "--db", self.db, "--anchor", self.anchor)
        self.assertEqual("ACTIVE", self.run_cli("list-grants", "--db", self.db, "--anchor", self.anchor)[0]["effective_status"])
        self.assertTrue(self.run_cli("checkpoint", "--db", self.db)["checkpointed"])

    def test_clear_lease_requires_the_exact_owner_token(self):
        store = SQLiteIntentStore(self.db)
        i = intent(intent_id="intent_cli_lease_000000001")
        store.register(i, canonical_hash(i))
        with store.intent_guard(i.intent_id):
            lease = store.intent_lease(i.intent_id)
            token = lease["owner_token"]
            self.assertEqual(os.getpid(), lease["pid"])
            self.run_cli("clear-lease", "--intent-id", i.intent_id, "--owner-token", "wrong", "--db", self.db, expect_exit=2)
            # The owner is this very process: refused unless forced.
            refused = self.run_cli("clear-lease", "--intent-id", i.intent_id, "--owner-token", token, "--db", self.db, expect_exit=2)
            self.assertEqual("LeaseOwnerAlive", refused["error"])
            cleared = self.run_cli("clear-lease", "--intent-id", i.intent_id, "--owner-token", token, "--db", self.db, "--force")
            self.assertTrue(cleared["cleared"])
        store.close()

    def test_revoke_after_restore_closes_the_version(self):
        self.run_cli("provision-grant", "--grant", str(EX / "grant.json"), "--db", self.db, "--anchor", self.anchor)
        closed = self.run_cli("revoke-after-restore", "--grant-id", "grant:demo", "--grant-version", "1", "--db", self.db, "--anchor", self.anchor)
        self.assertEqual("REVOKED", closed["runtime_status"])
        self.assertEqual("REVOKED", self.run_cli("list-grants", "--db", self.db, "--anchor", self.anchor)[0]["effective_status"])

    def test_evidence_key_comes_from_the_environment(self):
        store = SQLiteIntentStore(self.db, evidence_key=b"test-evidence-key-32-bytes-long!!!!")
        i = intent(intent_id="intent_cli_key_00000000001")
        store.register(i, canonical_hash(i))
        store.close()
        with mock.patch.dict(os.environ, {"FAAR_TEST_EVIDENCE_KEY": "test-evidence-key-32-bytes-long!!!!"}):
            ok = self.run_cli("verify-evidence", "--intent-id", i.intent_id, "--db", self.db, "--evidence-key-env", "FAAR_TEST_EVIDENCE_KEY", expect_exit=0)
            self.assertTrue(ok["keyed"])
        # The wrong key must not verify.
        with mock.patch.dict(os.environ, {"FAAR_TEST_EVIDENCE_KEY": "another-key-that-is-also-32-bytes!!"}):
            wrong = self.run_cli("verify-evidence", "--intent-id", i.intent_id, "--db", self.db, "--evidence-key-env", "FAAR_TEST_EVIDENCE_KEY", expect_exit=2)
        self.assertEqual("chain_invalid", wrong["status"])

    def test_unanchored_command_on_an_anchored_database_exits_with_a_typed_error(self):
        self.run_cli("provision-grant", "--grant", str(EX / "grant.json"), "--db", self.db, "--anchor", self.anchor)
        refused = self.run_cli("halt", "--scope", "global", "--reason", "forgot the anchor", "--db", self.db, expect_exit=2)
        self.assertEqual("AuthorityAnchorRequired", refused["error"])
        self.assertEqual([], self.run_cli("controls", "--db", self.db))
        self.assertEqual("ANCHOR_REQUIRED", self.run_cli("list-grants", "--db", self.db)[0]["effective_status"])
        halted = self.run_cli("halt", "--scope", "global", "--reason", "drill", "--db", self.db, "--anchor", self.anchor)
        self.assertEqual(1, halted["grant_versions_fenced"])

    def test_rebuild_evidence_heads_for_a_legacy_database(self):
        key = "test-evidence-key-32-bytes-long!!!!"
        store = SQLiteIntentStore(self.db, evidence_key=key.encode())
        legacy = intent(intent_id="intent_cli_legacy_000000001")
        empty = intent(intent_id="intent_cli_empty_0000000001")
        for i in (legacy, empty):
            store.register(i, canonical_hash(i))
        store.close()
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM evidence_head")
        conn.execute("DELETE FROM evidence WHERE intent_id=?", (empty.intent_id,))
        conn.execute("DELETE FROM store_settings WHERE key='heads_since'")  # a pre-head database
        conn.commit()
        conn.close()
        with mock.patch.dict(os.environ, {"FAAR_TEST_EVIDENCE_KEY": key}):
            before = self.run_cli("verify-evidence", "--intent-id", legacy.intent_id, "--db", self.db, "--evidence-key-env", "FAAR_TEST_EVIDENCE_KEY", expect_exit=2)
            self.assertEqual("head_missing", before["status"])
            outcomes = self.run_cli("rebuild-evidence-head", "--all", "--db", self.db, "--evidence-key-env", "FAAR_TEST_EVIDENCE_KEY")["outcomes"]
            self.assertEqual({legacy.intent_id: "committed", empty.intent_id: "skipped_empty"}, outcomes)
            adopted = self.run_cli("rebuild-evidence-head", "--all", "--adopt-empty", "--db", self.db, "--evidence-key-env", "FAAR_TEST_EVIDENCE_KEY")["outcomes"]
            self.assertEqual({empty.intent_id: "adopted_empty"}, adopted)
            for i in (legacy, empty):
                after = self.run_cli("verify-evidence", "--intent-id", i.intent_id, "--db", self.db, "--evidence-key-env", "FAAR_TEST_EVIDENCE_KEY", expect_exit=0)
                self.assertEqual("ok", after["status"])
            with self.assertRaises(SystemExit):
                self.run_cli("rebuild-evidence-head", "--db", self.db, "--evidence-key-env", "FAAR_TEST_EVIDENCE_KEY")


if __name__ == "__main__":
    unittest.main()
