from __future__ import annotations

import threading
import time
import unittest
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

from faar.adapters import AmbiguousExecution, DeterministicFailure, MockMode, MockVenue, REFERENCE_SAFE_PROFILE
from faar.canonical import canonical_hash
from faar.models import ExecutionReceipt, ExecutionRequest, IntentState, SettlementRecord, SettlementStatus
from faar.runtime import FAARRuntime
from faar.settlement import MockSettlementVerifier, REFERENCE_SETTLEMENT_PROFILE
from faar.store import PermitConflict, SQLiteIntentStore, UnknownIntent
from support import AUTH, NOW, Clock, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, temp_path, trust, verification_trust


def _auth(status, effect_id=None, amount="50"):
    def make(request):
        return SettlementRecord(
            status, effect_id=effect_id, amount_usd=None if amount is None else Decimal(amount),
            evidence={"source": "independent"}, authoritative=True, verified_request_hash=canonical_hash(request),
        )
    return make


def _weak(status, effect_id=None, amount="50"):
    def make(request):
        return SettlementRecord(
            status, effect_id=effect_id, amount_usd=None if amount is None else Decimal(amount),
            evidence={"source": "single-rpc"}, authoritative=False,
        )
    return make


class ScriptedAdapter:
    """Test-only submitter whose behaviour and settlement observations are scripted.

    `behaviours` are consumed once each (exceptions are raised, receipts returned);
    `settlements` are consumed once each except the last, which repeats.
    """

    name = "mock-dex"
    security_profile = REFERENCE_SAFE_PROFILE

    def __init__(self, behaviours, settlements):
        self.behaviours = list(behaviours)
        self.settlements = list(settlements)
        self.calls = 0

    def execute(self, request, permit):
        self.calls += 1
        behaviour = self.behaviours.pop(0)
        if isinstance(behaviour, BaseException):
            raise behaviour
        return behaviour

    def reconcile(self, request):
        record = self.settlements.pop(0) if len(self.settlements) > 1 else self.settlements[0]
        return record(request) if callable(record) else record


class ScriptedVerifier:
    name = "test-scripted-verifier"
    security_profile = REFERENCE_SETTLEMENT_PROFILE

    def __init__(self, adapter):
        self.adapter = adapter

    def verify(self, request):
        return self.adapter.reconcile(request)


class RuntimeHardeningTests(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self), evidence_key=b"evidence-test-key-32-bytes-long!!!!")
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))

    def tearDown(self):
        self.store.close()

    def runtime_for(self, adapter):
        permit_authority, _ = permit_stack(self.store, self.trust)
        return FAARRuntime(
            self.store, {"mock-dex": adapter}, verification_trust(self.trust), permit_authority,
            {"mock-dex": ScriptedVerifier(adapter)}, clock=lambda: NOW, allow_test_time_override=True,
        )

    def run_case(self, runtime, i, g=None, rs=None, now=NOW):
        g = g or grant()
        rs = rs or risk(observed_at=now)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, now)
        return runtime.process(i, AUTH, g, rs, authority_attestation=aa, risk_attestation=ra, now=now)

    # Past the default 5 s permit TTL plus the grant's 2 s clock-skew allowance.
    AFTER_WINDOW = NOW + timedelta(seconds=10)

    def usage_status(self, iid):
        return next(r["status"] for r in self.store.usage("grant:test", 1) if r["intent_id"] == iid)

    def event_types(self, iid):
        return [e["event_type"] for e in self.store.evidence(iid)]

    # --- non-authoritative observations carry no weight in either direction -------

    def test_weak_none_after_confirmed_does_not_lose_the_effect(self):
        adapter = ScriptedAdapter(
            [ExecutionReceipt("effect-A", SettlementStatus.CONFIRMED, {}, Decimal("50"))],
            [_auth(SettlementStatus.CONFIRMED, "effect-A"), _weak(SettlementStatus.NONE), _auth(SettlementStatus.FINALIZED, "effect-A")],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000001")
        self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i).state)
        second = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, second.state)
        self.assertIn("SETTLEMENT_NONE_NOT_AUTHORITATIVE", second.reason_codes)
        third = self.run_case(runtime, i)
        self.assertEqual(IntentState.FINALIZED, third.state)
        self.assertEqual("effect-A", self.store.get(i.intent_id).effect_id)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))
        self.assertEqual(1, adapter.calls)

    def test_weak_positive_with_different_or_missing_effect_id_stays_unknown(self):
        for n, weak in enumerate((
            _weak(SettlementStatus.CONFIRMED, "effect-B"),
            _weak(SettlementStatus.FINALIZED, None),
        )):
            confirmed = f"effect-A{n}"  # distinct per intent: the same venue effect may back one intent only
            adapter = ScriptedAdapter(
                [ExecutionReceipt(confirmed, SettlementStatus.CONFIRMED, {}, Decimal("50"))],
                [_auth(SettlementStatus.CONFIRMED, confirmed), weak],
            )
            runtime = self.runtime_for(adapter)
            i = intent(intent_id=f"intent_hard_00000000001{n}")
            self.assertEqual(IntentState.CONFIRMED, self.run_case(runtime, i, rs=risk(state_version=n + 2)).state)
            result = self.run_case(runtime, i, rs=risk(state_version=n + 2))
            self.assertEqual(IntentState.UNKNOWN, result.state)
            self.assertIn("SETTLEMENT_POSITIVE_NOT_AUTHORITATIVE", result.reason_codes)
            self.assertEqual(confirmed, self.store.get(i.intent_id).effect_id)
            self.assertEqual("HELD", self.usage_status(i.intent_id))

    # --- deterministic-failure block is durable ------------------------------------

    def test_deterministic_failure_block_survives_across_calls(self):
        adapter = ScriptedAdapter(
            [DeterministicFailure("permit rejected"), ExecutionReceipt("effect-Z", SettlementStatus.FINALIZED, {}, Decimal("50"))],
            [_auth(SettlementStatus.UNKNOWN), _auth(SettlementStatus.NONE)],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000020")
        first = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, first.state)
        self.assertIn("EXECUTION_DETERMINISTIC_FAILURE", self.store.get(i.intent_id).reason_codes)
        second = self.run_case(runtime, i, now=self.AFTER_WINDOW)
        self.assertEqual(IntentState.FAILED_SAFE, second.state)
        self.assertEqual(("EXECUTION_DETERMINISTIC_FAILURE",), second.reason_codes)
        self.assertEqual(1, adapter.calls, "a persisted block must not be forgotten by the next worker")
        self.assertEqual(1, self.store.get(i.intent_id).submission_count)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    def test_deterministic_failure_block_survives_a_halt_and_resume(self):
        adapter = ScriptedAdapter(
            [DeterministicFailure("permit rejected"), ExecutionReceipt("effect-Y", SettlementStatus.FINALIZED, {}, Decimal("50"))],
            [_auth(SettlementStatus.NONE)],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000021")
        self.assertEqual(IntentState.UNKNOWN, self.run_case(runtime, i).state)
        # An emergency halt while the intent is parked must not overwrite the
        # durable block with the status block; otherwise the adapter is called
        # again as soon as the halt is lifted.
        self.store.halt("global", reason="drill")
        halted = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, halted.state)
        self.assertIn("EXECUTION_DETERMINISTIC_FAILURE", self.store.get(i.intent_id).reason_codes)
        self.store.resume("global")
        after = self.run_case(runtime, i, now=self.AFTER_WINDOW)
        self.assertEqual(IntentState.FAILED_SAFE, after.state)
        self.assertEqual(("EXECUTION_DETERMINISTIC_FAILURE",), after.reason_codes)
        self.assertEqual(1, adapter.calls)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    # --- the permit window covers every adapter outcome ------------------------------

    def test_receipt_without_effect_does_not_close_the_permit_window(self):
        # The adapter reports a receipt but the venue has not processed the request
        # (accepted-and-queued). An authoritative NONE inside the permit window must
        # not authorize a retry: the queued request can still consume permit #1.
        adapter = ScriptedAdapter(
            [
                ExecutionReceipt("fx_pending", SettlementStatus.CONFIRMED, {"note": "accepted-not-processed"}, Decimal("50")),
                ExecutionReceipt("fx_final", SettlementStatus.FINALIZED, {}, Decimal("50")),
            ],
            [_auth(SettlementStatus.NONE), _auth(SettlementStatus.NONE), _auth(SettlementStatus.FINALIZED, "fx_final")],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000030")
        first = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, first.state)
        self.assertIn("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", first.reason_codes)
        self.assertEqual(1, adapter.calls)
        self.assertEqual((1, 0), self.store.permit_counts(i.intent_id))
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        self.assertIsNotNone(self.store.get(i.intent_id).ambiguity_until)
        # Once the permit can no longer be honoured, the retry budget applies.
        second = self.run_case(runtime, i, now=self.AFTER_WINDOW)
        self.assertEqual(IntentState.FINALIZED, second.state)
        self.assertEqual(2, adapter.calls)
        self.assertEqual(2, self.store.get(i.intent_id).submission_count)

    def test_deterministic_failure_keeps_budget_until_the_permit_window_closes(self):
        # The adapter raises DeterministicFailure without the venue having consumed
        # the permit (e.g. a transport error after the request was queued). The
        # venue then executes inside the permit lifetime. Releasing budget on the
        # rejection would have orphaned that effect.
        permit_authority, permit_verifier = permit_stack(self.store, self.trust)
        inner = MockVenue(permit_verifier=permit_verifier, name="mock-dex", clock=lambda: NOW)
        calls: list = []

        class FailsWithoutConsuming:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE

            def execute(self, request, permit):
                calls.append((request, permit))
                raise DeterministicFailure("venue returned 502 (request was actually queued)")

        runtime = FAARRuntime(
            self.store, {"mock-dex": FailsWithoutConsuming()}, verification_trust(self.trust), permit_authority,
            {"mock-dex": MockSettlementVerifier(inner)}, clock=lambda: NOW, allow_test_time_override=True,
        )
        i = intent(intent_id="intent_hard_000000000031")
        first = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, first.state)
        self.assertIn("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", first.reason_codes)
        self.assertIn("EXECUTION_DETERMINISTIC_FAILURE", first.reason_codes)
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        request, permit = calls[0]
        self.assertEqual(permit.permit.expires_at.isoformat(), self.store.get(i.intent_id).ambiguity_until)
        # The queued request lands at the venue while the permit is live.
        receipt = inner.execute(request, permit)
        self.assertEqual(1, inner.successful_effect_count(i.intent_id))
        later = self.run_case(runtime, i, now=self.AFTER_WINDOW)
        self.assertEqual(IntentState.FINALIZED, later.state)
        self.assertEqual(receipt.effect_id, later.effect_id)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))
        self.assertEqual(1, len(calls))

    def test_non_receipt_adapter_return_is_ambiguous_not_a_crash(self):
        adapter = ScriptedAdapter([{"status": "ok"}], [_auth(SettlementStatus.NONE)])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000032")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, result.state)
        self.assertIn("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", result.reason_codes)
        self.assertIn("execution_ambiguous", self.event_types(i.intent_id))
        self.assertEqual("HELD", self.usage_status(i.intent_id))

    def test_store_refuses_a_second_live_permit_and_the_runtime_keeps_the_budget(self):
        # Store-level backstop for I-30, exercised directly.
        i = intent(intent_id="intent_hard_000000000033")
        self.store.register(i, canonical_hash(i))
        g = grant()
        self.store.record_execution_permit("permit_a", i, g, 1, 1, "h1", expires_at=NOW + timedelta(seconds=5), now=NOW)
        with self.assertRaises(PermitConflict):
            self.store.record_execution_permit("permit_b", i, g, 1, 2, "h2", expires_at=NOW + timedelta(seconds=5), now=NOW + timedelta(seconds=6))
        self.store.record_execution_permit("permit_c", i, g, 1, 3, "h3", expires_at=NOW + timedelta(seconds=20), now=NOW + timedelta(seconds=8))
        self.assertEqual((NOW + timedelta(seconds=20)).isoformat(), self.store.get(i.intent_id).ambiguity_until)

    # --- finalize and commit are one transaction --------------------------------------

    def test_finalize_and_commit_are_one_transaction_and_replay_repairs_older_rows(self):
        i = intent(intent_id="intent_hard_000000000040")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        for a, b in ((IntentState.PROPOSED, IntentState.AUTHORIZED), (IntentState.AUTHORIZED, IntentState.RESERVED),
                     (IntentState.RESERVED, IntentState.RECONCILING)):
            self.assertTrue(self.store.transition(i.intent_id, a, b))
        with self.assertRaises(ValueError):
            self.store.transition(i.intent_id, IntentState.RECONCILING, IntentState.FINALIZED, effect_id="fx-a", release_usage=True, commit_usage=True)
        self.assertTrue(self.store.transition(i.intent_id, IntentState.RECONCILING, IntentState.FINALIZED, effect_id="fx-a", commit_usage=True))
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))
        # A FINALIZED row whose commit never happened (older version, crash between
        # the two statements) is repaired by the first replay.
        j = intent(intent_id="intent_hard_000000000041")
        self.store.register(j, canonical_hash(j))
        self.assertTrue(self.store.reserve_usage(j, grant(), risk(state_version=2), NOW)[0])
        for a, b in ((IntentState.PROPOSED, IntentState.AUTHORIZED), (IntentState.AUTHORIZED, IntentState.RESERVED),
                     (IntentState.RESERVED, IntentState.RECONCILING)):
            self.assertTrue(self.store.transition(j.intent_id, a, b))
        self.assertTrue(self.store.transition(j.intent_id, IntentState.RECONCILING, IntentState.FINALIZED, effect_id="fx-b"))
        self.assertEqual("HELD", self.usage_status(j.intent_id))
        runtime = self.runtime_for(ScriptedAdapter([], [_auth(SettlementStatus.NONE)]))
        replay = self.run_case(runtime, j)
        self.assertEqual(IntentState.FINALIZED, replay.state)
        self.assertTrue(replay.replayed)
        self.assertEqual("COMMITTED", self.usage_status(j.intent_id))

    # --- a settlement-derived stop is not an orphaned hold ------------------------

    def test_replay_keeps_the_hold_of_a_never_submitted_intent_stopped_on_settlement_evidence(self):
        over = ScriptedAdapter([], [_auth(SettlementStatus.FINALIZED, "fx_external", amount="60")])
        runtime = self.runtime_for(over)
        i = intent(intent_id="intent_hard_000000000034")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.assertTrue(self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED))
        self.assertTrue(self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED))
        first = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, first.state)
        self.assertEqual(("SETTLED_AMOUNT_EXCEEDS_AUTHORIZED",), first.reason_codes)
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        replay = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, replay.state)
        self.assertTrue(replay.replayed)
        self.assertEqual("HELD", self.usage_status(i.intent_id), "an effect the verifier attributed to this intent needs a human")
        self.assertEqual(0, over.calls)

    # --- revocation fence covers submission only ------------------------------------

    def test_revocation_completes_while_verifier_runs_after_ambiguous_submission(self):
        entered = threading.Event()
        release = threading.Event()

        def blocking_none(request):
            entered.set()
            release.wait(5)
            return _auth(SettlementStatus.NONE)(request)

        adapter = ScriptedAdapter([AmbiguousExecution("timeout")], [blocking_none, _auth(SettlementStatus.NONE)])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000030")
        results = []
        worker = threading.Thread(target=lambda: results.append(self.run_case(runtime, i)))
        worker.start()
        self.assertTrue(entered.wait(5))
        revoked = threading.Event()

        def revoke():
            self.store.set_grant_status(grant().principal_id, "grant:test", 1, "REVOKED")
            revoked.set()

        threading.Thread(target=revoke).start()
        self.assertTrue(revoked.wait(2), "settlement verification must not hold the revocation fence")
        release.set()
        worker.join(10)
        # The in-flight attempt's permit is still live, so absence is not yet
        # authoritative: the intent parks in UNKNOWN until the window closes.
        self.assertEqual(IntentState.UNKNOWN, results[0].state)
        self.assertIn("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", results[0].reason_codes)
        self.assertEqual(1, adapter.calls)
        # Past the permit window the authoritative NONE is trusted, and the retry is
        # refused because the grant was revoked in the meantime.
        aa, ra = attest_pair(self.trust, i, AUTH, risk(), NOW)
        later = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=NOW + timedelta(seconds=10))
        self.assertEqual(IntentState.STOPPED, later.state)
        self.assertIn("GRANT_RUNTIME_REVOKED", later.reason_codes)
        self.assertEqual(1, adapter.calls)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    # --- budget release only when no submission can have begun ---------------------

    def test_reconcile_releases_hold_for_reserved_intent_when_adapter_missing(self):
        i = intent(intent_id="intent_hard_000000000040")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        runtime, *_ = build_mock_runtime(self.store, self.trust, name="other-venue")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("ADAPTER_NOT_CONFIGURED", result.reason_codes)
        self.assertEqual(0, self.store.get(i.intent_id).submission_count)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    def test_replay_of_never_submitted_terminal_intent_releases_orphaned_hold(self):
        i = intent(intent_id="intent_hard_000000000041")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        # Simulated crash: terminal transition committed, release never ran.
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.STOPPED, reason_codes=("X",))
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        runtime, *_ = build_mock_runtime(self.store, self.trust)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertTrue(result.replayed)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    # --- every terminal decision leaves evidence ------------------------------------

    def test_grant_rejection_and_inactive_grant_are_recorded_in_evidence(self):
        runtime, *_ = build_mock_runtime(self.store, self.trust)
        broader = grant(limits=replace(grant().limits, max_order_usd=Decimal("1000000")))
        i = intent(intent_id="intent_hard_000000000050")
        result = self.run_case(runtime, i, g=broader)
        self.assertEqual(("GRANT_ENVELOPE_MISMATCH",), result.reason_codes)
        self.assertIn("grant_rejected", self.event_types(i.intent_id))
        self.assertTrue(self.store.verify_evidence_chain(i.intent_id))

        self.store.set_grant_status(grant().principal_id, "grant:test", 1, "PAUSED")
        j = intent(intent_id="intent_hard_000000000051")
        result = self.run_case(runtime, j)
        self.assertEqual(("GRANT_RUNTIME_PAUSED",), result.reason_codes)
        self.assertIn("grant_runtime_inactive", self.event_types(j.intent_id))

    def test_recovered_authorization_records_the_authorized_event(self):
        i = intent(intent_id="intent_hard_000000000052")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        runtime, venue, *_ = build_mock_runtime(self.store, self.trust)
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        authorized = [e for e in self.store.evidence(i.intent_id) if e["event_type"] == "authorized"]
        self.assertEqual(1, len(authorized))
        self.assertTrue(authorized[0]["payload"]["recovered"])
        self.assertEqual(1, venue.successful_effect_count(i.intent_id))

    # --- malformed effect identity is machine-readable, never a crash ---------------

    def test_malformed_receipt_effect_id_is_recorded_not_raised(self):
        adapter = ScriptedAdapter(
            [ExecutionReceipt(b"binary-effect-id", SettlementStatus.FINALIZED, {}, Decimal("50"))],  # type: ignore[arg-type]
            [_auth(SettlementStatus.FINALIZED, "independent-effect")],
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000060")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual("independent-effect", result.effect_id)
        receipt_events = [e for e in self.store.evidence(i.intent_id) if e["event_type"] == "adapter_receipt_untrusted"]
        self.assertFalse(receipt_events[0]["payload"]["reported_effect_id_well_formed"])

    def test_malformed_verifier_effect_id_stops_with_held_budget(self):
        adapter = ScriptedAdapter(
            [ExecutionReceipt("effect-A", SettlementStatus.FINALIZED, {}, Decimal("50"))],
            [_auth(SettlementStatus.FINALIZED, b"binary-effect-id")],  # type: ignore[arg-type]
        )
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_hard_000000000061")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertIn("SETTLED_EFFECT_ID_INVALID", result.reason_codes)
        self.assertIsNone(self.store.get(i.intent_id).effect_id)
        self.assertEqual("HELD", self.usage_status(i.intent_id))

    # --- in-flight ambiguity is bounded by the permit window -------------------------

    def test_absence_is_not_authoritative_while_an_in_flight_permit_is_live(self):
        clock = Clock()
        runtime, venue, *_ = build_mock_runtime(
            self.store, self.trust, mode=MockMode.TIMEOUT_BEFORE_EFFECT,
            runtime_clock=clock, venue_clock=clock, max_permit_ttl_seconds=1,
        )
        i = intent(intent_id="intent_hard_000000000080")

        def run():
            # A retry is a new authorization: fresh risk evidence and attestations.
            rs = risk(observed_at=clock())
            aa, ra = attest_pair(self.trust, i, AUTH, rs, clock())
            return runtime.process(i, AUTH, grant(), rs, authority_attestation=aa, risk_attestation=ra, now=clock())

        first = run()
        self.assertEqual(IntentState.UNKNOWN, first.state)
        self.assertIn("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", first.reason_codes)
        self.assertEqual(1, venue.execute_call_count(i.intent_id))
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        # Still inside the permit window (1s TTL + 2s grant skew): no retry.
        clock.advance(2)
        self.assertEqual(1, venue.execute_call_count(i.intent_id))
        self.assertEqual(IntentState.UNKNOWN, run().state)
        self.assertEqual(1, venue.execute_call_count(i.intent_id))
        # Once the venue can no longer consume the permit, authoritative NONE is
        # trusted and the durable retry budget admits exactly one more attempt.
        clock.advance(2)
        second = run()
        self.assertEqual(IntentState.UNKNOWN, second.state)
        self.assertEqual(2, venue.execute_call_count(i.intent_id))
        clock.advance(4)
        final = run()
        self.assertEqual(IntentState.STOPPED, final.state)
        self.assertIn("MAX_SUBMISSION_ATTEMPTS_REACHED", final.reason_codes)
        self.assertEqual(2, venue.execute_call_count(i.intent_id))
        self.assertEqual(0, venue.successful_effect_count(i.intent_id))
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))

    def test_adapter_deadline_releases_the_fence_and_never_duplicates_a_late_effect(self):
        clock = Clock()
        permit_authority, permit_verifier = permit_stack(self.store, self.trust, max_permit_ttl_seconds=1)
        inner = MockVenue(permit_verifier=permit_verifier, name="mock-dex", clock=clock)
        proceed = threading.Event()
        arrived = threading.Event()

        class SlowVenue:
            """Hangs past the runtime deadline, then completes the venue call."""
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE

            def execute(self, request, permit):
                if not proceed.wait(5):
                    raise AssertionError("test never released the slow venue")
                try:
                    return inner.execute(request, permit)
                finally:
                    arrived.set()

        runtime = FAARRuntime(
            self.store, {"mock-dex": SlowVenue()}, verification_trust(self.trust), permit_authority,
            {"mock-dex": MockSettlementVerifier(inner)}, clock=clock, allow_test_time_override=True,
            adapter_deadline_seconds=0.2,
        )
        i = intent(intent_id="intent_hard_000000000081")
        aa, ra = attest_pair(self.trust, i, AUTH, risk(), NOW)
        started = time.monotonic()
        result = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=clock())
        self.assertLess(time.monotonic() - started, 3.0, "the runtime must stop waiting at the deadline")
        self.assertEqual(IntentState.UNKNOWN, result.state)
        self.assertIn("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", result.reason_codes)
        self.assertIn("execution_ambiguous", self.event_types(i.intent_id))
        # The orphaned call lands late, while the permit is still live: exactly one effect.
        proceed.set()
        self.assertTrue(arrived.wait(5), "late venue call must complete")
        self.assertEqual(1, inner.successful_effect_count(i.intent_id))
        clock.advance(4)
        later = runtime.process(i, AUTH, grant(), risk(), authority_attestation=aa, risk_attestation=ra, now=clock())
        self.assertEqual(IntentState.FINALIZED, later.state)
        self.assertEqual(1, inner.successful_effect_count(i.intent_id))
        self.assertEqual(1, self.store.get(i.intent_id).submission_count)

    def test_late_effect_after_permit_expiry_is_refused_by_the_venue(self):
        clock = Clock()
        permit_authority, permit_verifier = permit_stack(self.store, self.trust, max_permit_ttl_seconds=1)
        inner = MockVenue(permit_verifier=permit_verifier, name="mock-dex", clock=clock)
        gates = [threading.Event(), threading.Event()]
        outcomes: dict[int, object] = {}
        arrived: list[threading.Event] = [threading.Event(), threading.Event()]

        class SlowVenue:
            """Each attempt hangs on its own gate so the test controls arrival order."""
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE
            attempt = 0

            def execute(self, request, permit):
                n = SlowVenue.attempt
                SlowVenue.attempt += 1
                gates[n].wait(5)
                try:
                    outcomes[n] = inner.execute(request, permit)
                except Exception as exc:  # the venue's own rejection of a stale permit
                    outcomes[n] = exc
                    raise
                finally:
                    arrived[n].set()
                return outcomes[n]

        runtime = FAARRuntime(
            self.store, {"mock-dex": SlowVenue()}, verification_trust(self.trust), permit_authority,
            {"mock-dex": MockSettlementVerifier(inner)}, clock=clock, allow_test_time_override=True,
            adapter_deadline_seconds=0.2,
        )
        i = intent(intent_id="intent_hard_000000000082")

        def run():
            rs = risk(observed_at=clock())
            aa, ra = attest_pair(self.trust, i, AUTH, rs, clock())
            return runtime.process(i, AUTH, grant(), rs, authority_attestation=aa, risk_attestation=ra, now=clock())

        self.assertEqual(IntentState.UNKNOWN, run().state)
        # Window closes; the runtime may now trust NONE and retry once.
        clock.advance(4)
        self.assertEqual(IntentState.UNKNOWN, run().state)
        self.assertEqual(2, self.store.get(i.intent_id).submission_count)
        # The first (stale) call finally reaches the venue: its permit has expired,
        # so the venue refuses it and no effect exists.
        gates[0].set()
        self.assertTrue(arrived[0].wait(5))
        self.assertIsInstance(outcomes[0], Exception)
        self.assertIn("PERMIT_EXPIRED", str(outcomes[0]))
        self.assertEqual(0, inner.successful_effect_count(i.intent_id))
        # The second attempt's permit is still live: exactly one effect, then FINALIZED.
        gates[1].set()
        self.assertTrue(arrived[1].wait(5))
        self.assertEqual(1, inner.successful_effect_count(i.intent_id))
        clock.advance(4)
        self.assertEqual(IntentState.FINALIZED, run().state)
        self.assertEqual(1, inner.successful_effect_count(i.intent_id))

    # --- public reconcile() is defensive --------------------------------------------

    def test_public_reconcile_rejects_unknown_intent_and_wrong_grant_without_mutation(self):
        runtime, *_ = build_mock_runtime(self.store, self.trust)
        with self.assertRaises(UnknownIntent):
            runtime.reconcile(intent(intent_id="intent_never_registered1"), grant=grant())

        i = intent(intent_id="intent_hard_000000000070")
        self.store.register(i, canonical_hash(i))
        self.assertTrue(self.store.reserve_usage(i, grant(), risk(), NOW)[0])
        self.store.transition(i.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED)
        self.store.transition(i.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED)
        self.store.begin_submission(i.intent_id, [IntentState.RESERVED], max_attempts=2)
        result = runtime.reconcile(i, grant=grant(grant_id="grant:unprovisioned"))
        self.assertEqual(("GRANT_NOT_PROVISIONED",), result.reason_codes)
        self.assertEqual(IntentState.SUBMITTED, result.state)
        self.assertEqual(IntentState.SUBMITTED, self.store.get(i.intent_id).state)
        self.assertIsNone(self.store.intent_lease(i.intent_id))


if __name__ == "__main__":
    unittest.main()
