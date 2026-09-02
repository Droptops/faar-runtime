#!/usr/bin/env python3
"""Small exhaustive model of the FAAR permit / revocation / settlement protocol.

This is deliberately tiny and explicit. It is not a proof of the Python runtime or
of any external venue. It exhaustively explores a bounded abstract state space to
catch contradictions in the protocol rules themselves.

v0.4 models up to two permits per intent (the reference retry budget), the venue
side of an in-flight submission, permit expiry and voiding, the emergency halt,
settlement lag (the venue consumed a permit and created the effect, but the
independent verifier has not observed it yet), and the two rules the runtime
enforces:

- quiescence: a new permit is issued only once every earlier permit is consumed,
  expired or voided (the ambiguity window);
- ledger check: absence reported by the verifier is never acted on (no release,
  no retry) while the ledger shows a consumed permit for the intent.

The checker runs with both rules, then without each rule in turn, so the report
shows that the protocol is safe with them and unsafe without either.
"""
from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, replace

MAX_PERMITS = 2


@dataclass(frozen=True)
class Permit:
    epoch: int
    in_flight: bool = False
    consumed: bool = False
    expired: bool = False
    voided: bool = False

    @property
    def live(self) -> bool:
        return not self.consumed and not self.expired and not self.voided


@dataclass(frozen=True)
class S:
    grant_epoch: int = 1
    grant_active: bool = True
    halted: bool = False
    permits: tuple[Permit, ...] = ()
    effect_count: int = 0            # ground truth at the venue
    observed: str = "NONE"           # what the independent verifier has reported: NONE | FINALIZED
    finalized: bool = False


def _with_permit(s: S, idx: int, permit: Permit) -> S:
    permits = list(s.permits)
    permits[idx] = permit
    return replace(s, permits=tuple(permits))


def actions(s: S, *, require_quiescence: bool, require_ledger_check: bool):
    # The runtime acts on what the verifier reported, never on ground truth. It may
    # issue another permit while the verifier still says NONE, provided (with the
    # rules) no earlier permit can still be acted on and none was consumed.
    quiescent = all(not p.live for p in s.permits)
    ledger_clean = not any(p.consumed for p in s.permits)
    if (
        s.grant_active and not s.halted and s.observed == "NONE" and not s.finalized
        and len(s.permits) < MAX_PERMITS
        and (quiescent or not require_quiescence)
        and (ledger_clean or not require_ledger_check)
    ):
        yield "issue", replace(s, permits=s.permits + (Permit(epoch=s.grant_epoch),))

    for idx, p in enumerate(s.permits):
        # The runtime hands the permit to the venue. From here the runtime may
        # observe a receipt, an error, or nothing at all (timeout): the model does
        # not distinguish, because the venue's options are the same in every case.
        if p.live and not p.in_flight:
            yield f"submit{idx}", _with_permit(s, idx, replace(p, in_flight=True))
        # Consumption is the authorization linearization point at the venue; the
        # effect exists from here on, whether or not the verifier has seen it.
        if p.live and p.in_flight and s.grant_active and not s.halted and p.epoch == s.grant_epoch:
            yield f"consume{idx}", replace(_with_permit(s, idx, replace(p, consumed=True)), effect_count=s.effect_count + 1)
        # Time passes: an unconsumed permit expires and the venue will refuse it.
        if p.live:
            yield f"expire{idx}", _with_permit(s, idx, replace(p, expired=True))

    # Before acting on absence the runtime voids every unconsumed permit.
    if any(p.live for p in s.permits) and s.observed == "NONE":
        yield "void", replace(s, permits=tuple(replace(p, voided=True) if p.live else p for p in s.permits))

    # Pause/revoke and the kill switch each advance the epoch; old permits die.
    if s.grant_active:
        yield "revoke", replace(s, grant_active=False, grant_epoch=s.grant_epoch + 1)
    if not s.halted:
        yield "halt", replace(s, halted=True, grant_epoch=s.grant_epoch + 1)
    else:
        yield "resume", replace(s, halted=False)

    # Independent settlement eventually observes the effect (settlement lag is the
    # gap between consume and verify_final); submitter receipts are absent from the
    # model because they have no authority to finalize.
    if s.effect_count >= 1 and s.observed != "FINALIZED":
        yield "verify_final", replace(s, observed="FINALIZED")
    if s.observed == "FINALIZED" and not s.finalized:
        yield "finalize", replace(s, finalized=True)


def invariant_failures(s: S) -> list[str]:
    failures: list[str] = []
    if s.effect_count > 1:
        failures.append("DUPLICATE_EFFECT")
    if s.effect_count > sum(1 for p in s.permits if p.consumed):
        failures.append("EFFECT_WITHOUT_CONSUMED_PERMIT")
    if s.finalized and (s.effect_count != 1 or s.observed != "FINALIZED"):
        failures.append("FINALIZED_WITHOUT_AUTHORITATIVE_EFFECT")
    if any(p.consumed and (p.expired or p.voided) for p in s.permits):
        failures.append("DEAD_PERMIT_CONSUMED")
    return failures


def explore(*, require_quiescence: bool, require_ledger_check: bool, max_depth: int) -> dict:
    initial = S()
    queue = deque([(initial, ())])
    seen = {initial}
    transitions = 0
    violations: list[dict] = []
    while queue:
        state, path = queue.popleft()
        for name, nxt in actions(state, require_quiescence=require_quiescence, require_ledger_check=require_ledger_check):
            transitions += 1
            next_path = path + (name,)
            failures = invariant_failures(nxt)
            if failures:
                violations.append({"path": list(next_path), "failures": failures})
            if len(next_path) < max_depth and nxt not in seen:
                seen.add(nxt)
                queue.append((nxt, next_path))
    return {
        "unique_states": len(seen),
        "transitions_explored": transitions,
        "invariant_violations": len(violations),
        "first_violation": violations[0] if violations else None,
    }


def main(max_depth: int = 14) -> None:
    both = explore(require_quiescence=True, require_ledger_check=True, max_depth=max_depth)
    no_quiescence = explore(require_quiescence=False, require_ledger_check=True, max_depth=max_depth)
    no_ledger = explore(require_quiescence=True, require_ledger_check=False, max_depth=max_depth)

    # Explicit stale-permit properties: after revoke, or after halt + resume, a
    # permit issued under the prior epoch does not satisfy the consume guard; a
    # voided permit never does.
    def consumable(s: S) -> bool:
        return any(name.startswith("consume") for name, _ in actions(s, require_quiescence=True, require_ledger_check=True))

    stale_after_revoke = S(grant_epoch=2, grant_active=False, permits=(Permit(epoch=1, in_flight=True),))
    stale_after_halt_resume = S(grant_epoch=2, grant_active=True, halted=False, permits=(Permit(epoch=1, in_flight=True),))
    voided = S(permits=(Permit(epoch=1, in_flight=True, voided=True),))

    report = {
        "suite": "FAAR v0.4 bounded permit protocol model check",
        "max_depth": max_depth,
        "max_permits_per_intent": MAX_PERMITS,
        "unique_states": both["unique_states"],
        "transitions_explored": both["transitions_explored"],
        "invariant_violations": both["invariant_violations"],
        "stale_permit_consumable_after_revoke": consumable(stale_after_revoke),
        "stale_permit_consumable_after_halt_resume": consumable(stale_after_halt_resume),
        "voided_permit_consumable": consumable(voided),
        "without_quiescence_rule": {
            "unique_states": no_quiescence["unique_states"],
            "invariant_violations": no_quiescence["invariant_violations"],
            "first_violation": no_quiescence["first_violation"],
        },
        "without_ledger_check": {
            "unique_states": no_ledger["unique_states"],
            "invariant_violations": no_ledger["invariant_violations"],
            "first_violation": no_ledger["first_violation"],
        },
        "pass": (
            both["invariant_violations"] == 0
            and not consumable(stale_after_revoke)
            and not consumable(stale_after_halt_resume)
            and not consumable(voided)
            and no_quiescence["invariant_violations"] > 0
            and no_ledger["invariant_violations"] > 0
        ),
        "claim_boundary": (
            "Bounded abstract-state exploration; not formal verification of implementation or external venues. "
            "The without-rule runs demonstrate why reissue must wait for permit expiry or voiding and why absence "
            "is never acted on over a consumed permit; they are not bugs in the runtime."
        ),
    }
    if both["first_violation"]:
        report["first_violation"] = both["first_violation"]
    print(json.dumps(report, indent=2))
    if not report["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
