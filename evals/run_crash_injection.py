#!/usr/bin/env python3
"""Crash a worker at every persistence boundary, recover as the runbook says, check invariants.

A worker process runs `process()` for one intent against a file-backed store and a
file-backed mock venue. A proxy around the store kills the process (`os._exit`)
right before its N-th store call, for every N up to the number of store calls a
clean run makes. That leaves exactly what a real crash leaves: committed rows, a
durable lease, permits the venue may have consumed, and no in-memory state.

The parent then does what docs/OPERATIONS.md §2 prescribes (clear the dead
worker's lease with its owner token) and calls `process()` again with fresh
attestations, advancing the clock past the permit window, until the intent is
terminal. For every crash point it asserts:

- at most one successful economic effect and at most two adapter calls;
- an effect exists  =>  FINALIZED with usage COMMITTED;
- terminal without effect  =>  usage RELEASED (unless the stop is settlement-derived);
- the recovery never raises and never ends non-terminal.

This is regression evidence for the reference store and mock venue, not a proof.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import sys
import tempfile
from datetime import timedelta
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "test"))

from faar.adapters import DeterministicFailure, MockMode, MockVenue  # noqa: E402
from faar.canonical import canonical_hash  # noqa: E402
from faar.models import ExecutionReceipt, IntentState, SettlementStatus  # noqa: E402
from faar.runtime import FAARRuntime  # noqa: E402
from faar.settlement import MockSettlementVerifier  # noqa: E402
from faar.store import SQLiteIntentStore, TERMINAL_STATES  # noqa: E402
from support import AUTH, NOW, attest_pair, grant, intent, permit_stack, risk, trust, verification_trust  # noqa: E402

EVIDENCE_KEY = b"crash-injection-evidence-key-32b!!"
INTENT_ID = "intent_crash_000000000001"
SETTLEMENT_DERIVED = ("SETTLED_", "SETTLEMENT_", "EFFECT_ID_", "PAYMENT_", "UNHANDLED_SETTLEMENT")

# (name, worker venue mode, recovery venue mode, adapter wrapper)
SCENARIOS = (
    ("success", MockMode.SUCCESS, MockMode.SUCCESS, None),
    ("timeout_before_effect", MockMode.TIMEOUT_BEFORE_EFFECT, MockMode.SUCCESS, None),
    ("timeout_after_effect", MockMode.TIMEOUT_AFTER_EFFECT, MockMode.SUCCESS, None),
    ("ambiguous_then_recovered", MockMode.AMBIGUOUS, MockMode.SUCCESS, None),
    ("deterministic_rejection", MockMode.SUCCESS, MockMode.SUCCESS, "reject"),
    ("partial_fill_then_cancel", MockMode.PARTIAL_FILL, MockMode.PARTIAL_FILL, None),
)


class PersistentMockVenue(MockVenue):
    """MockVenue whose ledger survives the worker process: effects and call counts
    are written to a JSON file after every change and reloaded on construction."""

    def __init__(self, path: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._path = path
        self._load()

    def _load(self) -> None:
        try:
            data = json.loads(Path(self._path).read_text())
        except (FileNotFoundError, ValueError):
            return
        for key, r in data.get("effects", {}).items():
            self._effects[key] = ExecutionReceipt(
                effect_id=r["effect_id"], status=SettlementStatus(r["status"]), evidence=r["evidence"],
                amount_usd=None if r["amount_usd"] is None else Decimal(r["amount_usd"]),
            )
        self._execute_calls.update(data.get("calls", {}))

    def _save(self) -> None:
        data = {
            "effects": {
                key: {
                    "effect_id": r.effect_id, "status": r.status.value, "evidence": dict(r.evidence),
                    "amount_usd": None if r.amount_usd is None else format(r.amount_usd, "f"),
                } for key, r in self._effects.items()
            },
            "calls": dict(self._execute_calls),
        }
        tmp = self._path + ".tmp"
        Path(tmp).write_text(json.dumps(data, sort_keys=True))
        os.replace(tmp, self._path)

    def execute(self, request, permit):
        try:
            return super().execute(request, permit)
        finally:
            self._save()

    def complete_fill(self, request):
        receipt = super().complete_fill(request)
        self._save()
        return receipt

    def cancel_order(self, request):
        receipt = super().cancel_order(request)
        self._save()
        return receipt


class RejectingAdapter:
    """Transport that reports a deterministic rejection without consuming the permit."""

    name = "mock-dex"

    def __init__(self, venue):
        self.venue = venue
        self.security_profile = venue.security_profile

    def execute(self, request, permit):
        raise DeterministicFailure("venue rejected the order (transport error)")


class CrashingStore:
    """Counts store calls made by the runtime and kills the process before call N."""

    def __init__(self, inner: SQLiteIntentStore, crash_at: int | None, counter_path: str) -> None:
        self._inner = inner
        self._crash_at = crash_at
        self._counter_path = counter_path
        self.calls = 0

    def __getattr__(self, name):
        attr = getattr(self._inner, name)
        if not callable(attr) or name.startswith("_"):
            return attr

        def wrapped(*args, **kwargs):
            self.calls += 1
            Path(self._counter_path).write_text(str(self.calls))
            if self._crash_at is not None and self.calls == self._crash_at:
                os._exit(3)  # a real crash: no lease release, no rollback of committed rows
            return attr(*args, **kwargs)
        return wrapped


def _build(store, venue_path: str, mode: MockMode, wrapper: str | None, clock):
    t = trust()
    permit_authority, permit_verifier = permit_stack(store, t)
    venue = PersistentMockVenue(venue_path, permit_verifier=permit_verifier, name="mock-dex", mode=mode, clock=clock)
    adapter = RejectingAdapter(venue) if wrapper == "reject" else venue
    runtime = FAARRuntime(
        store, {"mock-dex": adapter}, verification_trust(t), permit_authority,
        {"mock-dex": MockSettlementVerifier(venue)}, clock=clock, allow_test_time_override=True,
    )
    return t, runtime, venue


def worker(db: str, venue_path: str, counter_path: str, result_path: str, scenario: str, crash_at: int | None) -> None:
    _, mode, _, wrapper = next(s for s in SCENARIOS if s[0] == scenario)
    inner = SQLiteIntentStore(db, evidence_key=EVIDENCE_KEY)
    store = CrashingStore(inner, crash_at, counter_path)
    t, runtime, _ = _build(store, venue_path, mode, wrapper, lambda: NOW)
    i = intent(intent_id=INTENT_ID)
    rs = risk()
    aa, ra = attest_pair(t, i, AUTH, rs, NOW)
    result = runtime.process(i, AUTH, grant(), rs, authority_attestation=aa, risk_attestation=ra, now=NOW)
    Path(result_path).write_text(json.dumps({"state": result.state.value, "reason_codes": list(result.reason_codes), "calls": store.calls}))
    inner.close()


def _run_worker(ctx, db, venue_path, counter_path, result_path, scenario, crash_at):
    p = ctx.Process(target=worker, args=(db, venue_path, counter_path, result_path, scenario, crash_at))
    p.start()
    p.join(120)
    if p.is_alive():
        p.kill()
        raise RuntimeError(f"worker hung: {scenario} crash_at={crash_at}")
    return p.exitcode


def _usage_status(store, intent_id):
    rows = [r for r in store.usage("grant:test", 1) if r["intent_id"] == intent_id]
    return rows[0]["status"] if rows else None


def _recover(db: str, venue_path: str, scenario: str) -> dict:
    """The runbook: clear the dead worker's lease, then process with fresh attestations
    while advancing the clock past the permit window until the intent is terminal."""
    _, _, recovery_mode, wrapper = next(s for s in SCENARIOS if s[0] == scenario)
    store = SQLiteIntentStore(db, evidence_key=EVIDENCE_KEY)
    clock = {"now": NOW}
    t, runtime, venue = _build(store, venue_path, recovery_mode, None if wrapper == "reject" else wrapper, lambda: clock["now"])
    if wrapper == "reject":
        # The rejecting transport is replaced by the venue itself on recovery: a
        # persisted deterministic block must still prevent a second submission.
        pass
    i = intent(intent_id=INTENT_ID)
    request_effects_before = venue.successful_effect_count(INTENT_ID)
    cleared = []
    for lease in store.list_leases():
        if lease["intent_id"] == INTENT_ID:
            cleared.append(store.clear_stale_intent_lease(INTENT_ID, expected_owner_token=lease["owner_token"]))
    results = []
    for round_no in range(1, 5):
        clock["now"] = NOW + timedelta(seconds=10 * round_no)
        rs = risk(state_version=round_no + 1, observed_at=clock["now"])
        aa, ra = attest_pair(t, i, AUTH, rs, clock["now"])
        result = runtime.process(i, AUTH, grant(), rs, authority_attestation=aa, risk_attestation=ra, now=clock["now"])
        results.append({"state": result.state.value, "reason_codes": list(result.reason_codes)})
        if scenario == "partial_fill_then_cancel" and result.state == IntentState.CONFIRMED:
            venue.cancel_order(__import__("faar.models", fromlist=["ExecutionRequest"]).ExecutionRequest.from_intent(i))
        if result.state in TERMINAL_STATES:
            break
    stored = store.get(INTENT_ID)
    out = {
        "leases_cleared": cleared,
        "rounds": results,
        "final_state": stored.state.value,
        "final_reason_codes": list(stored.reason_codes),
        "effect_id": stored.effect_id,
        "usage": _usage_status(store, INTENT_ID),
        "effects": venue.successful_effect_count(INTENT_ID),
        "effects_before_recovery": request_effects_before,
        "adapter_calls": venue.execute_call_count(INTENT_ID),
        "permits": store.permit_counts(INTENT_ID),
        "evidence_valid": store.verify_evidence_chain(INTENT_ID),
    }
    store.close()
    return out


def _violations(case: dict) -> list[str]:
    v = []
    state = case["final_state"]
    if case["effects"] > 1:
        v.append("DUPLICATE_EFFECT")
    if case["adapter_calls"] > 2:
        v.append("EXCESS_ADAPTER_CALLS")
    if state not in {s.value for s in TERMINAL_STATES}:
        v.append("NOT_TERMINAL_AFTER_RECOVERY")
    if case["effects"] == 1 and (state != "FINALIZED" or case["usage"] != "COMMITTED"):
        v.append("EFFECT_NOT_FINALIZED_OR_NOT_COMMITTED")
    if state == "FINALIZED" and case["effects"] != 1:
        v.append("FINALIZED_WITHOUT_EFFECT")
    settlement_derived = any(r.startswith(SETTLEMENT_DERIVED) for r in case["final_reason_codes"])
    if state in {"STOPPED", "FAILED_SAFE", "DENIED", "DEFERRED"} and case["usage"] == "HELD" and not settlement_derived:
        v.append("HELD_BUDGET_ON_TERMINAL_INTENT")
    if state in {"STOPPED", "FAILED_SAFE"} and case["effects"] != 0:
        v.append("EFFECT_ON_NON_FINALIZED_TERMINAL")
    if not case["evidence_valid"]:
        v.append("EVIDENCE_CHAIN_INVALID")
    return v


def main() -> None:
    ctx = mp.get_context("spawn")
    report = {"suite": "FAAR v0.4 crash-injection recovery", "scenarios": {}, "cases": 0, "violations": []}
    with tempfile.TemporaryDirectory(prefix="faar-crash-") as td:
        for scenario, *_ in SCENARIOS:
            # A clean run measures how many store calls one process() makes.
            base = os.path.join(td, scenario)
            os.makedirs(base)
            db = os.path.join(base, "clean.sqlite")
            store = SQLiteIntentStore(db, evidence_key=EVIDENCE_KEY)
            store.provision_grant(grant(), canonical_hash(grant()))
            store.close()
            counter = os.path.join(base, "clean.count")
            code = _run_worker(ctx, db, os.path.join(base, "clean.venue.json"), counter, os.path.join(base, "clean.result"), scenario, None)
            if code != 0:
                raise SystemExit(f"clean worker failed for {scenario}: exit {code}")
            total_calls = int(Path(counter).read_text())
            outcomes = []
            for crash_at in range(1, total_calls + 1):
                case_dir = os.path.join(base, f"crash-{crash_at:03d}")
                os.makedirs(case_dir)
                db = os.path.join(case_dir, "faar.sqlite")
                store = SQLiteIntentStore(db, evidence_key=EVIDENCE_KEY)
                store.provision_grant(grant(), canonical_hash(grant()))
                store.close()
                venue_path = os.path.join(case_dir, "venue.json")
                code = _run_worker(ctx, db, venue_path, os.path.join(case_dir, "count"), os.path.join(case_dir, "result"), scenario, crash_at)
                if code != 3:
                    raise SystemExit(f"worker did not crash where injected: {scenario} crash_at={crash_at} exit={code}")
                case = _recover(db, venue_path, scenario)
                case["crash_at"] = crash_at
                case["violations"] = _violations(case)
                outcomes.append(case)
                report["cases"] += 1
                for name in case["violations"]:
                    report["violations"].append({"scenario": scenario, "crash_at": crash_at, "violation": name, "case": case})
            report["scenarios"][scenario] = {
                "store_calls_in_clean_run": total_calls,
                "crash_points": len(outcomes),
                "final_states": sorted({c["final_state"] for c in outcomes}),
                "leases_cleared": sum(len(c["leases_cleared"]) for c in outcomes),
                "max_effects": max(c["effects"] for c in outcomes),
                "max_adapter_calls": max(c["adapter_calls"] for c in outcomes),
            }
    report["pass"] = not report["violations"]
    report["claim_boundary"] = (
        "Process kill at every store-call boundary of the reference runtime with the mock venue; "
        "recovery follows the documented runbook. Not a proof and not a statement about a real venue."
    )
    print(json.dumps(report, indent=2, default=str))
    if not report["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
