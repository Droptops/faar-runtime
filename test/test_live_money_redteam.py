"""Regressions from the live-money red-team pass (compromised adapter, malicious
settlement source): every case here once let money move outside authority, get
lost from the ledger, or wedge an intent without a reason code."""
from __future__ import annotations

import time
import unittest
from datetime import timedelta
from decimal import Decimal

from faar.adapters import AmbiguousExecution, DeterministicFailure, MockMode, MockVenue, REFERENCE_SAFE_PROFILE
from faar.canonical import canonical_hash
from faar.models import (
    AttestationKind, ExecutionReceipt, ExecutionRequest, IntentState, OutcomeCriterion, SettlementRecord,
    SettlementStatus, TaskContract,
)
from faar.outcomes import OutcomeVerdict, verify_attested_task_outcome
from faar.permits import ExecutionPermitVerifier
from faar.runtime import FAARRuntime
from faar.settlement import MockSettlementVerifier, QuorumSettlementVerifier, REFERENCE_SETTLEMENT_PROFILE
from faar.store import SQLiteIntentStore
from support import AUTH, NOW, Clock, attest_pair, build_mock_runtime, grant, intent, permit_stack, risk, temp_path, trust, verification_trust
from test_runtime_hardening import ScriptedAdapter, ScriptedVerifier, _auth

AFTER_WINDOW = NOW + timedelta(seconds=10)


def _src(name, produce):
    class Source:
        security_profile = REFERENCE_SETTLEMENT_PROFILE

        def __init__(self):
            self.name = name

        def verify(self, request):
            return produce(request)
    return Source()


class _Base(unittest.TestCase):
    def setUp(self):
        self.store = SQLiteIntentStore(temp_path(self), evidence_key=b"evidence-test-key-32-bytes-long!!!!")
        self.trust = trust()
        self.store.provision_grant(grant(), canonical_hash(grant()))
        self.n = 0

    def tearDown(self):
        self.store.close()

    def runtime_for(self, adapter, verifier=None, **kwargs):
        permit_authority, _ = permit_stack(self.store, self.trust)
        return FAARRuntime(
            self.store, {"mock-dex": adapter}, verification_trust(self.trust), permit_authority,
            {"mock-dex": verifier or ScriptedVerifier(adapter)}, clock=lambda: NOW, allow_test_time_override=True, **kwargs,
        )

    def run_case(self, runtime, i, now=NOW, g=None):
        self.n += 1
        rs = risk(state_version=self.n, observed_at=now)
        aa, ra = attest_pair(self.trust, i, AUTH, rs, now)
        return runtime.process(i, AUTH, g or grant(), rs, authority_attestation=aa, risk_attestation=ra, now=now)

    def usage_status(self, intent_id):
        rows = [r for r in self.store.usage("grant:test", 1) if r["intent_id"] == intent_id]
        return rows[0]["status"] if rows else None

    def events(self, intent_id):
        return [e["event_type"] for e in self.store.evidence(intent_id)]


class CompromisedAdapterTests(_Base):
    def test_permit_for_one_venue_is_refused_by_another_venues_gateway(self):
        # Two venues share the control store (epoch fencing) and the permit signer.
        # A compromised mock-dex adapter forwards its (request, permit) pair to the
        # mock-cex gateway: the grant never allowed mock-cex, and the request hash
        # matches because nothing was mutated. The gateway must know who it is.
        permit_authority, permit_verifier = permit_stack(self.store, self.trust)
        dex = MockVenue(permit_verifier=permit_verifier, name="mock-dex", clock=lambda: NOW)
        cex = MockVenue(permit_verifier=permit_verifier, name="mock-cex", clock=lambda: NOW)
        forwarded = []

        class ForwardingAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE

            def execute(self, request, permit):
                forwarded.append((request, permit))
                return cex.execute(request, permit)

        runtime = FAARRuntime(
            self.store, {"mock-dex": ForwardingAdapter()}, verification_trust(self.trust), permit_authority,
            {"mock-dex": MockSettlementVerifier(dex)}, clock=lambda: NOW, allow_test_time_override=True,
        )
        i = intent(intent_id="intent_redteam_000000000001")
        result = self.run_case(runtime, i)
        self.assertEqual(0, cex.successful_effect_count(i.intent_id), "no effect on the unauthorized venue")
        self.assertEqual(0, dex.successful_effect_count(i.intent_id))
        self.assertEqual((1, 0), self.store.permit_counts(i.intent_id), "the permit was not consumed")
        self.assertEqual(IntentState.UNKNOWN, result.state)
        request, permit = forwarded[0]
        ok, reasons = permit_verifier.verify(permit, request, now=NOW, venue="mock-cex")
        self.assertEqual((False, ("PERMIT_VENUE_MISMATCH",)), (ok, reasons))
        # A gateway bound at construction refuses the same way; the right venue accepts.
        bound = ExecutionPermitVerifier(permit_verifier.signature, self.store, venue="mock-cex")
        self.assertEqual(("PERMIT_VENUE_MISMATCH",), bound.verify(permit, request, now=NOW)[1])
        self.assertEqual(("PERMIT_VENUE_MISMATCH",), bound.with_key_validity({}).verify(permit, request, now=NOW)[1])
        self.assertTrue(ExecutionPermitVerifier(permit_verifier.signature, self.store, venue="mock-dex").verify(permit, request, now=NOW)[0])

    def test_adapter_content_cannot_crash_the_state_machine(self):
        class RaisingRepr(str):
            def __repr__(self):
                raise RuntimeError("repr bomb")

        class Spoofed:
            """Not a receipt; claims to be one."""
            @property
            def __class__(self):
                return ExecutionReceipt

        class Shout(Exception):
            def __str__(self):
                raise RuntimeError("str bomb")

        cases = (
            (ExecutionReceipt(RaisingRepr("fx-1"), SettlementStatus.CONFIRMED, {}, Decimal("50")), "adapter_receipt_untrusted"),
            (Spoofed(), "execution_ambiguous"),
            ({"status": "ok"}, "execution_ambiguous"),
            (Shout("boom"), "adapter_execution_exception"),
        )
        for n, (behaviour, event) in enumerate(cases):
            adapter = ScriptedAdapter([behaviour], [_auth(SettlementStatus.NONE)])
            runtime = self.runtime_for(adapter)
            i = intent(intent_id=f"intent_redteam_00000000001{n}")
            result = self.run_case(runtime, i)
            self.assertEqual(IntentState.UNKNOWN, result.state, event)
            self.assertIn("SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW", result.reason_codes)
            self.assertIn(event, self.events(i.intent_id), event)
            self.assertEqual("HELD", self.usage_status(i.intent_id))
            self.assertIsNotNone(self.store.get(i.intent_id).ambiguity_until)

    def test_base_exception_from_the_adapter_is_recorded_before_it_propagates(self):
        class SdkAbort(BaseException):
            pass

        for deadline in (None, 1.0):
            adapter = ScriptedAdapter([SdkAbort("sdk aborted")], [_auth(SettlementStatus.NONE)])
            runtime = self.runtime_for(adapter, adapter_deadline_seconds=deadline)
            i = intent(intent_id=f"intent_redteam_00000000002{0 if deadline is None else 1}")
            result = self.run_case(runtime, i)
            self.assertEqual(IntentState.UNKNOWN, result.state)
            self.assertIn("adapter_execution_exception", self.events(i.intent_id))
            self.assertEqual("HELD", self.usage_status(i.intent_id))
        # Interpreter-level signals still propagate, but only after the state is durable.
        adapter = ScriptedAdapter([SystemExit(3)], [_auth(SettlementStatus.NONE)])
        runtime = self.runtime_for(adapter)
        i = intent(intent_id="intent_redteam_000000000022")
        with self.assertRaises(SystemExit):
            self.run_case(runtime, i)
        stored = self.store.get(i.intent_id)
        self.assertEqual(IntentState.UNKNOWN, stored.state)
        self.assertEqual(("ADAPTER_EXECUTION_EXCEPTION",), stored.reason_codes)
        self.assertIsNotNone(stored.ambiguity_until)

    def test_consumed_permit_with_authoritative_absence_stops_instead_of_releasing(self):
        # The venue admitted the request (consumed the permit) and then timed out
        # without any record. Absence after the window is a contradiction between
        # the ledger and the verifier, never a release or a retry.
        clock = Clock()
        runtime, venue, *_ = build_mock_runtime(
            self.store, self.trust, mode=MockMode.TIMEOUT_AFTER_ADMISSION, runtime_clock=clock, venue_clock=clock,
        )
        i = intent(intent_id="intent_redteam_000000000030")
        first = self.run_case(runtime, i)
        self.assertEqual(IntentState.UNKNOWN, first.state)
        self.assertEqual((1, 1), self.store.permit_counts(i.intent_id))
        clock.advance(10)
        later = self.run_case(runtime, i, now=clock())
        self.assertEqual(IntentState.STOPPED, later.state)
        self.assertEqual(("SETTLEMENT_NONE_AFTER_PERMIT_CONSUMED",), later.reason_codes)
        self.assertEqual("HELD", self.usage_status(i.intent_id))
        self.assertEqual(1, venue.execute_call_count(i.intent_id), "no retry after admission")
        # A transport timeout before admission (permit never consumed) still retries.
        clock2 = Clock()
        runtime2, venue2, *_ = build_mock_runtime(
            self.store, self.trust, mode=MockMode.TIMEOUT_BEFORE_EFFECT, runtime_clock=clock2, venue_clock=clock2,
        )
        j = intent(intent_id="intent_redteam_000000000031")
        self.assertEqual(IntentState.UNKNOWN, self.run_case(runtime2, j).state)
        self.assertEqual((1, 0), self.store.permit_counts(j.intent_id))
        venue2.set_mode(MockMode.SUCCESS)
        clock2.advance(10)
        done = self.run_case(runtime2, j, now=clock2())
        self.assertEqual(IntentState.FINALIZED, done.state)
        self.assertEqual(2, venue2.execute_call_count(j.intent_id))
        self.assertEqual(1, venue2.successful_effect_count(j.intent_id))
        self.assertEqual(1, self.store.voided_permit_count(j.intent_id), "the first permit was voided before the retry")

    def test_permit_is_voided_when_absence_is_acted_on_whatever_the_venue_clock_says(self):
        # The adapter times out before the venue admitted the request and keeps the
        # permit. After the window the runtime releases the budget (deterministic
        # block) or retries; a venue whose clock still considers the old permit live
        # must be refused regardless.
        permit_authority, permit_verifier = permit_stack(self.store, self.trust)
        lagging = MockVenue(permit_verifier=permit_verifier, name="mock-dex", clock=lambda: NOW)  # clock 10 s behind
        kept = []

        class DropsAfterQueueing:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE

            def execute(self, request, permit):
                kept.append((request, permit))
                raise DeterministicFailure("502 after queueing")

        runtime = FAARRuntime(
            self.store, {"mock-dex": DropsAfterQueueing()}, verification_trust(self.trust), permit_authority,
            {"mock-dex": MockSettlementVerifier(lagging)}, clock=lambda: NOW, allow_test_time_override=True,
        )
        i = intent(intent_id="intent_redteam_000000000032")
        self.assertEqual(IntentState.UNKNOWN, self.run_case(runtime, i).state)
        later = self.run_case(runtime, i, now=AFTER_WINDOW)
        self.assertEqual(IntentState.FAILED_SAFE, later.state)
        self.assertEqual("RELEASED", self.usage_status(i.intent_id))
        request, permit = kept[0]
        with self.assertRaisesRegex(DeterministicFailure, "PERMIT_VOIDED"):
            lagging.execute(request, permit)
        self.assertEqual(0, lagging.successful_effect_count(i.intent_id))
        self.assertIn("permits_voided", self.events(i.intent_id))


class MaliciousSettlementSourceTests(_Base):
    def test_malformed_settlement_content_fails_in_the_verifier_not_after_reconciling(self):
        def auth(**over):
            def make(request):
                fields = dict(status=SettlementStatus.FINALIZED, effect_id="fx-1", amount_usd=Decimal("50"),
                              evidence={"ok": True}, authoritative=True, verified_request_hash=canonical_hash(request))
                fields.update(over)
                return SettlementRecord(**fields)
            return make
        poison = (
            auth(evidence={"x": Decimal("1e-150")}),
            auth(evidence={"x": "lone surrogate \udcff"}),
            auth(verified_request_hash=b"bytes"),
            auth(amount_usd=Decimal("1e-100000000")),
            auth(amount_usd=Decimal("1e1000000")),
            auth(effect_id=["fx-1"]),
            auth(evidence={"big": "x" * 8192, **{f"k{n}": "y" * 8000 for n in range(12)}}),
        )
        for n, record in enumerate(poison):
            with self.assertRaises(ValueError, msg=str(n)):
                record(ExecutionRequest.from_intent(intent()))
            adapter = ScriptedAdapter([ExecutionReceipt("fx-1", SettlementStatus.CONFIRMED, {}, Decimal("50"))], [record])
            runtime = self.runtime_for(adapter)
            i = intent(intent_id=f"intent_redteam_0000000001{n:02d}"[:27].ljust(27, "0"))
            started = time.monotonic()
            result = self.run_case(runtime, i)
            self.assertLess(time.monotonic() - started, 5.0)
            self.assertEqual(IntentState.UNKNOWN, result.state, str(n))
            self.assertIn("RECONCILIATION_EXCEPTION", result.reason_codes)
            self.assertEqual("HELD", self.usage_status(i.intent_id))
        # A verifier returning something that is not a record at all.
        class NoneVerifier:
            name = "none"
            security_profile = REFERENCE_SETTLEMENT_PROFILE

            def verify(self, request):
                return None
        runtime = self.runtime_for(ScriptedAdapter([ExecutionReceipt("fx-1", SettlementStatus.CONFIRMED, {}, Decimal("50"))], []), verifier=NoneVerifier())
        i = intent(intent_id="intent_redteam_000000000199")
        result = self.run_case(runtime, i)
        self.assertEqual(IntentState.STOPPED, result.state)
        self.assertEqual(("SETTLEMENT_RECORD_MALFORMED",), result.reason_codes)
        self.assertEqual("HELD", self.usage_status(i.intent_id))

    def test_dag_shaped_evidence_is_bounded_by_the_node_budget(self):
        leaf = {"v": "x" * 100}
        level = leaf
        for _ in range(6):
            level = {f"k{n}": level for n in range(20)}  # 20^6 nodes if fully expanded
        started = time.monotonic()
        with self.assertRaises(ValueError):
            SettlementRecord(SettlementStatus.NONE, evidence=level)
        with self.assertRaises(ValueError):
            ExecutionReceipt("fx", SettlementStatus.FINALIZED, level, Decimal("1"))
        self.assertLess(time.monotonic() - started, 2.0)

    def test_finality_lag_between_sources_is_not_a_contest(self):
        request = ExecutionRequest.from_intent(intent())
        fin = _auth(SettlementStatus.FINALIZED, "fx-1", "50")
        conf = _auth(SettlementStatus.CONFIRMED, "fx-1", "50")
        none = _auth(SettlementStatus.NONE)
        reached = QuorumSettlementVerifier([_src("a", fin), _src("b", fin), _src("c", conf)], quorum=2).verify(request)
        self.assertEqual(SettlementStatus.FINALIZED, reached.status)
        self.assertTrue(reached.authoritative)
        self.assertEqual({"a", "b"}, set(reached.evidence["source_evidence"]))
        lagging = QuorumSettlementVerifier([_src("a", fin), _src("b", conf)], quorum=2).verify(request)
        self.assertEqual(SettlementStatus.CONFIRMED, lagging.status)
        self.assertEqual("fx-1", lagging.effect_id)
        self.assertTrue(lagging.authoritative)
        self.assertEqual({"a", "b"}, set(lagging.evidence["source_evidence"]))
        # Still contested: positive versus negative, different effect ids, different amounts.
        for other in (none, _auth(SettlementStatus.CONFIRMED, "fx-2", "50"), _auth(SettlementStatus.CONFIRMED, "fx-1", "40")):
            self.assertEqual(SettlementStatus.CONTRADICTORY, QuorumSettlementVerifier([_src("a", fin), _src("b", other)], quorum=2).verify(request).status)
        # End to end: the intent confirms, then finalizes when the lagging source catches up.
        sources = {"b": conf}
        quorum = QuorumSettlementVerifier([_src("a", fin), _src("b", lambda req: sources["b"](req))], quorum=2)
        adapter = ScriptedAdapter([ExecutionReceipt("fx-1", SettlementStatus.CONFIRMED, {}, Decimal("50"))], [])
        runtime = self.runtime_for(adapter, verifier=quorum)
        i = intent(intent_id="intent_redteam_000000000200")
        first = self.run_case(runtime, i)
        self.assertEqual(IntentState.CONFIRMED, first.state)
        sources["b"] = fin
        self.assertEqual(IntentState.FINALIZED, self.run_case(runtime, i).state)
        self.assertEqual("COMMITTED", self.usage_status(i.intent_id))

    def test_a_garbage_returning_minority_member_cannot_wedge_the_quorum(self):
        request = ExecutionRequest.from_intent(intent())
        fin = _auth(SettlementStatus.FINALIZED, "fx-1", "50")
        for bad in (lambda req: None, lambda req: {"status": "FINALIZED"}, lambda req: "FINALIZED"):
            record = QuorumSettlementVerifier([_src("a", fin), _src("b", fin), _src("c", bad)], quorum=2).verify(request)
            self.assertEqual(SettlementStatus.FINALIZED, record.status)
            self.assertIn("c", record.evidence["errors"])

    def test_outcome_verifier_follows_the_runtime_verdict(self):
        i = intent()
        request = ExecutionRequest.from_intent(i)
        settlement = SettlementRecord(
            SettlementStatus.FINALIZED, "fx-1", Decimal("50"), evidence={"fill": {"to_quantity": "100"}},
            authoritative=True, verified_request_hash=canonical_hash(request),
        )
        contract = TaskContract("task-1", i.intent_id, "filled", (OutcomeCriterion("fill.to_quantity", "gte", "100"),), NOW, NOW + timedelta(hours=1))
        att = self.trust.sign("task-test", AttestationKind.TASK, contract, i, issued_at=NOW, ttl_seconds=3600)
        verifier = verification_trust(self.trust)
        met = verify_attested_task_outcome(contract, settlement, attestation=att, intent=i, trust=verifier, now=NOW, runtime_state=IntentState.FINALIZED, runtime_effect_id="fx-1")
        self.assertEqual(OutcomeVerdict.MET, met.verdict)
        stopped = verify_attested_task_outcome(contract, settlement, attestation=att, intent=i, trust=verifier, now=NOW, runtime_state=IntentState.STOPPED, runtime_effect_id=None)
        self.assertEqual((OutcomeVerdict.UNKNOWN, ("TASK_INTENT_NOT_FINALIZED",)), (stopped.verdict, stopped.reason_codes))
        other = verify_attested_task_outcome(contract, settlement, attestation=att, intent=i, trust=verifier, now=NOW, runtime_state=IntentState.FINALIZED, runtime_effect_id="fx-9")
        self.assertEqual((OutcomeVerdict.UNKNOWN, ("TASK_EFFECT_ID_MISMATCH",)), (other.verdict, other.reason_codes))


if __name__ == "__main__":
    unittest.main()
