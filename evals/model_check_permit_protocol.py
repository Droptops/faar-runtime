#!/usr/bin/env python3
"""Small exhaustive model of the FAAR permit / revocation / settlement protocol.

This is deliberately tiny and explicit. It is not a proof of the Python runtime or
of any external venue. It exhaustively explores a bounded abstract state space to
catch contradictions in the protocol rules themselves.

v0.4 models up to two permits per intent (the reference retry budget), the venue
side of an in-flight submission, permit expiry, the emergency halt, and the rule
the runtime enforces since 0.4.0: a new permit may only be issued once every
earlier permit is consumed or expired (the "quiescence" rule). The checker runs
twice, with and without that rule, so the report shows both that the protocol is
safe with it and that it is unsafe without it.
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

    @property
    def live(self) -> bool:
        return not self.consumed and not self.expired


@dataclass(frozen=True)
class S:
    grant_epoch: int = 1
    grant_active: bool = True
    halted: bool = False
    permits: tuple[Permit, ...] = ()
    effect_count: int = 0
    authoritative_settlement: str = "NONE"  # NONE | FINALIZED
    finalized: bool = False


def _with_permit(s: S, idx: int, permit: Permit) -> S:
    permits = list(s.permits)
    permits[idx] = permit
    return replace(s, permits=tuple(permits))


def actions(s: S, *, require_quiescence: bool):
    # The permit authority signs a narrowly scoped permit only while the grant is
    # active and not halted, before any effect exists, and (with the rule) only when
    # no earlier permit can still be acted on by the venue.
    quiescent = all(not p.live for p in s.permits)
    if (
        s.grant_active and not s.halted and s.effect_count == 0
        and len(s.permits) < MAX_PERMITS and (quiescent or not require_quiescence)
    ):
        yield "issue", replace(s, permits=s.permits + (Permit(epoch=s.grant_epoch),))

    for idx, p in enumerate(s.permits):
        # The runtime hands the permit to the venue. From here the runtime may
        # observe a receipt, an error, or nothing at all (timeout): the model does
        # not distinguish, because the venue's options are the same in every case.
        if p.live and not p.in_flight:
            yield f"submit{idx}", _with_permit(s, idx, replace(p, in_flight=True))
        # Consumption is the authorization linearization point at the venue.
        if p.live and p.in_flight and s.grant_active and not s.halted and p.epoch == s.grant_epoch:
            yield f"consume{idx}", replace(_with_permit(s, idx, replace(p, consumed=True)), effect_count=s.effect_count + 1)
        # Time passes: an unconsumed permit expires and the venue will refuse it.
        if p.live:
            yield f"expire{idx}", _with_permit(s, idx, replace(p, expired=True))

    # Pause/revoke and the kill switch each advance the epoch; old permits die.
    if s.grant_active:
        yield "revoke", replace(s, grant_active=False, grant_epoch=s.grant_epoch + 1)
    if not s.halted:
        yield "halt", replace(s, halted=True, grant_epoch=s.grant_epoch + 1)
    else:
        yield "resume", replace(s, halted=False)

    # Independent settlement observes the effect; submitter receipts are absent
    # from the model because they have no authority to finalize.
    if s.effect_count == 1 and s.authoritative_settlement != "FINALIZED":
        yield "verify_final", replace(s, authoritative_settlement="FINALIZED")
    if s.authoritative_settlement == "FINALIZED" and not s.finalized:
        yield "finalize", replace(s, finalized=True)


def invariant_failures(s: S) -> list[str]:
    failures: list[str] = []
    if s.effect_count > 1:
        failures.append("DUPLICATE_EFFECT")
    if s.effect_count > sum(1 for p in s.permits if p.consumed):
        failures.append("EFFECT_WITHOUT_CONSUMED_PERMIT")
    if s.finalized and (s.effect_count != 1 or s.authoritative_settlement != "FINALIZED"):
        failures.append("FINALIZED_WITHOUT_AUTHORITATIVE_EFFECT")
    if any(p.consumed and p.expired for p in s.permits):
        failures.append("EXPIRED_PERMIT_CONSUMED")
    return failures


def explore(*, require_quiescence: bool, max_depth: int) -> dict:
    initial = S()
    queue = deque([(initial, ())])
    seen = {initial}
    transitions = 0
    violations: list[dict] = []
    while queue:
        state, path = queue.popleft()
        for name, nxt in actions(state, require_quiescence=require_quiescence):
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
    with_rule = explore(require_quiescence=True, max_depth=max_depth)
    without_rule = explore(require_quiescence=False, max_depth=max_depth)

    # Explicit stale-permit properties: after revoke, or after halt + resume, a
    # permit issued under the prior epoch does not satisfy the consume guard.
    stale_after_revoke = S(grant_epoch=2, grant_active=False, permits=(Permit(epoch=1, in_flight=True),))
    stale_after_halt_resume = S(grant_epoch=2, grant_active=True, halted=False, permits=(Permit(epoch=1, in_flight=True),))
    consumable = lambda s: any(name.startswith("consume") for name, _ in actions(s, require_quiescence=True))  # noqa: E731

    report = {
        "suite": "FAAR v0.4 bounded permit protocol model check",
        "max_depth": max_depth,
        "max_permits_per_intent": MAX_PERMITS,
        "unique_states": with_rule["unique_states"],
        "transitions_explored": with_rule["transitions_explored"],
        "invariant_violations": with_rule["invariant_violations"],
        "stale_permit_consumable_after_revoke": consumable(stale_after_revoke),
        "stale_permit_consumable_after_halt_resume": consumable(stale_after_halt_resume),
        "without_quiescence_rule": {
            "unique_states": without_rule["unique_states"],
            "invariant_violations": without_rule["invariant_violations"],
            "first_violation": without_rule["first_violation"],
        },
        "pass": (
            with_rule["invariant_violations"] == 0
            and not consumable(stale_after_revoke)
            and not consumable(stale_after_halt_resume)
            and without_rule["invariant_violations"] > 0
        ),
        "claim_boundary": (
            "Bounded abstract-state exploration; not formal verification of implementation or external venues. "
            "The without-rule run demonstrates why reissue must wait for permit expiry; it is not a bug in the runtime."
        ),
    }
    if with_rule["first_violation"]:
        report["first_violation"] = with_rule["first_violation"]
    print(json.dumps(report, indent=2))
    if not report["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
