"""Abandoned adapter calls are bounded (residual risk R-09)."""
from __future__ import annotations

import threading
import time
import unittest

from faar.adapters import MockVenue, REFERENCE_SAFE_PROFILE
from faar.canonical import canonical_hash
from faar.models import IntentState
from faar.runtime import FAARRuntime
from faar.settlement import MockSettlementVerifier
from faar.store import SQLiteIntentStore
from support import AUTH, NOW, attest_pair, grant, intent, permit_stack, risk, temp_path, trust, verification_trust


class OrphanedAdapterCallCapTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self))
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))

    def tearDown(self):
        self.store.close()

    def usage_status(self, intent_id):
        rows = [r for r in self.store.usage("grant:test", 1) if r["intent_id"] == intent_id]
        return rows[0]["status"] if rows else None

    def test_process_stops_submitting_while_too_many_abandoned_calls_are_running(self):
        permit_authority, permit_verifier = permit_stack(self.store, self.trust)
        inner = MockVenue(permit_verifier=permit_verifier, name="mock-dex", clock=lambda: NOW)
        gate = threading.Event()
        calls = []

        class HangingVenue:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE

            def execute(self, request, permit):
                calls.append(request.intent_id)
                if not gate.wait(10):
                    raise AssertionError("test never released the hanging venue")
                return inner.execute(request, permit)

        runtime = FAARRuntime(
            self.store, {"mock-dex": HangingVenue()}, verification_trust(self.trust), permit_authority,
            {"mock-dex": MockSettlementVerifier(inner)}, clock=lambda: NOW, allow_test_time_override=True,
            adapter_deadline_seconds=0.05, max_orphaned_adapter_calls=2,
        )
        with self.assertRaises(ValueError):
            FAARRuntime(
                self.store, {"mock-dex": HangingVenue()}, verification_trust(self.trust), permit_authority,
                {"mock-dex": MockSettlementVerifier(inner)}, max_orphaned_adapter_calls=0,
            )

        def run(n):
            i = intent(intent_id=f"intent_orphan_0000000000{n}")
            aa, ra = attest_pair(self.trust, i, AUTH, risk(state_version=n), NOW)
            return i, runtime.process(i, AUTH, grant(), risk(state_version=n), authority_attestation=aa, risk_attestation=ra, now=NOW)

        for n in (1, 2):
            i, result = run(n)
            self.assertEqual(IntentState.UNKNOWN, result.state)
            self.assertIn("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", result.reason_codes)
            self.assertEqual("HELD", self.usage_status(i.intent_id))
        self.assertEqual(2, runtime.orphaned_adapter_calls)

        # The third intent is refused before any permit is minted or the adapter is
        # touched; its reservation is released because nothing was transported.
        i3, third = run(3)
        self.assertEqual(IntentState.STOPPED, third.state)
        self.assertEqual(("ADAPTER_ORPHAN_LIMIT_REACHED",), third.reason_codes)
        self.assertEqual("RELEASED", self.usage_status(i3.intent_id))
        self.assertEqual((0, 0), self.store.permit_counts(i3.intent_id))
        self.assertEqual(2, len(calls))

        # Once the abandoned calls drain, submission resumes.
        gate.set()
        deadline = time.monotonic() + 5
        while runtime.orphaned_adapter_calls and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(0, runtime.orphaned_adapter_calls)
        i4, fourth = run(4)
        self.assertEqual(IntentState.FINALIZED, fourth.state)
        self.assertEqual(1, inner.successful_effect_count(i4.intent_id))


if __name__ == "__main__":
    unittest.main()
