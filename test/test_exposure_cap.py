"""Scope exposure caps (release gate 9: capped first exposure)."""
from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout
from datetime import timedelta
from decimal import Decimal

from faar import cli
from faar.anchor import FileAuthorityAnchor
from faar.canonical import canonical_hash
from faar.models import IntentState
from faar.store import AuthorityAnchorRequired, SQLiteIntentStore
from support import AUTH, NOW, PRINCIPAL, attest_pair, build_mock_runtime, grant, intent, risk, temp_path, trust


class ExposureCapTests(unittest.TestCase):
    def setUp(self):
        self.path = temp_path(self)
        self.store = SQLiteIntentStore(self.path)
        self.store.provision_grant(grant(), canonical_hash(grant()))
        other = grant(principal_id="principal:other", grant_id="grant:other")
        self.store.provision_grant(other, canonical_hash(other))
        self.other = other

    def tearDown(self):
        self.store.close()

    def reserve(self, iid, amount="50", *, principal=PRINCIPAL, g=None, version=1, now=NOW):
        i = intent(intent_id=iid, principal_id=principal, grant_id=(g or grant()).grant_id, payload={
            "from_asset": "USDC", "to_asset": "MEME", "amount_usd": amount, "target": "router:approved",
        })
        self.store.register(i, canonical_hash(i))
        return self.store.reserve_usage(i, g or grant(), risk(state_version=version), now)

    def test_global_cap_bounds_the_whole_fleet_across_grants_and_principals(self):
        self.store.set_exposure_cap("global", Decimal("100"))
        self.assertEqual([{"scope": "global", "max_turnover_usd": "100"}], [{k: c[k] for k in ("scope", "max_turnover_usd")} for c in self.store.exposure_caps()])
        self.assertTrue(self.reserve("intent_cap_000000000001", version=1)[0])
        self.assertTrue(self.reserve("intent_cap_000000000002", principal="principal:other", g=self.other, version=1)[0])
        ok, reasons = self.reserve("intent_cap_000000000003", version=2)
        self.assertFalse(ok)
        self.assertEqual(("EXPOSURE_CAP_EXCEEDED",), reasons)
        # A released reservation stops counting; a committed one keeps counting.
        self.store.release_usage("intent_cap_000000000001")
        self.assertTrue(self.reserve("intent_cap_000000000004", version=3)[0])
        self.store.commit_usage("intent_cap_000000000004")
        self.assertFalse(self.reserve("intent_cap_000000000005", version=4)[0])
        # The trailing window ages the exposure out.
        self.assertTrue(self.reserve("intent_cap_000000000006", version=5, now=NOW + timedelta(hours=24, seconds=1))[0])

    def test_principal_cap_isolates_principals_and_can_be_cleared(self):
        self.store.set_exposure_cap("principal:" + PRINCIPAL, Decimal("60"))
        self.assertTrue(self.reserve("intent_cap_000000000011", version=1)[0])
        ok, reasons = self.reserve("intent_cap_000000000012", version=2)
        self.assertEqual((False, ("EXPOSURE_CAP_EXCEEDED",)), (ok, reasons))
        self.assertTrue(self.reserve("intent_cap_000000000013", principal="principal:other", g=self.other, version=1)[0])
        self.store.set_exposure_cap("principal:" + PRINCIPAL, None)
        self.assertEqual([], self.store.exposure_caps())
        self.assertTrue(self.reserve("intent_cap_000000000014", version=3)[0])

    def test_cap_values_and_scopes_are_validated(self):
        for bad in (Decimal("0"), Decimal("-1"), "abc", Decimal("NaN"), 1e400):
            with self.assertRaises(ValueError):
                self.store.set_exposure_cap("global", bad)
        with self.assertRaises(ValueError):
            self.store.set_exposure_cap("everything", Decimal("1"))

    def test_runtime_defers_an_intent_over_the_cap_before_any_permit(self):
        t = trust()
        runtime, venue, *_ = build_mock_runtime(self.store, t)
        self.store.set_exposure_cap("global", Decimal("60"))
        for n, expected in ((1, IntentState.FINALIZED), (2, IntentState.DEFERRED)):
            i = intent(intent_id=f"intent_cap_00000000002{n}")
            aa, ra = attest_pair(t, i, AUTH, risk(state_version=n), NOW)
            result = runtime.process(i, AUTH, grant(), risk(state_version=n), authority_attestation=aa, risk_attestation=ra, now=NOW)
            self.assertEqual(expected, result.state)
        self.assertEqual(("EXPOSURE_CAP_EXCEEDED",), result.reason_codes)
        self.assertEqual(0, venue.execute_call_count("intent_cap_000000000022"))
        self.assertEqual((0, 0), self.store.permit_counts("intent_cap_000000000022"))

    def test_caps_are_authority_changes_on_an_anchored_database(self):
        anchor_path = temp_path(self, ".anchor.json")
        anchored_path = temp_path(self)
        anchored = SQLiteIntentStore(anchored_path, authority_anchor=FileAuthorityAnchor(anchor_path))
        anchored.set_exposure_cap("global", Decimal("10"))
        anchored.close()
        unanchored = SQLiteIntentStore(anchored_path)
        with self.assertRaises(AuthorityAnchorRequired):
            unanchored.set_exposure_cap("global", None)
        self.assertEqual("10", unanchored.exposure_caps()[0]["max_turnover_usd"])
        unanchored.close()

    def test_cli_sets_lists_and_clears_caps(self):
        def run(*argv, expect_exit=None):
            buf = io.StringIO()
            with redirect_stdout(buf):
                try:
                    cli.main(list(argv))
                    code = 0
                except SystemExit as exc:
                    code = exc.code if isinstance(exc.code, int) else 1
            if expect_exit is not None:
                self.assertEqual(expect_exit, code, buf.getvalue())
            return json.loads(buf.getvalue()) if buf.getvalue().strip() else None

        self.assertEqual({"scope": "global", "max_turnover_usd": "250"}, run("set-exposure-cap", "--scope", "global", "--max-usd", "250", "--db", self.path))
        self.assertEqual("250", run("exposure-caps", "--db", self.path)[0]["max_turnover_usd"])
        bad = run("set-exposure-cap", "--scope", "global", "--max-usd", "-5", "--db", self.path, expect_exit=2)
        self.assertEqual("ValueError", bad["error"])
        self.assertEqual({"scope": "global", "max_turnover_usd": None}, run("set-exposure-cap", "--scope", "global", "--clear", "--db", self.path))
        self.assertEqual([], run("exposure-caps", "--db", self.path))


if __name__ == "__main__":
    unittest.main()
