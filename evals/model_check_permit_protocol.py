#!/usr/bin/env python3
"""Small exhaustive model of the FAAR v0.4 permit/key/settlement protocol.

This is deliberately tiny and explicit. It is not a proof of the Python runtime or
of any external venue. It exhaustively explores a bounded abstract state space to
catch contradictions in the protocol rules themselves.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import json


@dataclass(frozen=True)
class S:
    grant_epoch: int = 1
    grant_active: bool = True
    permit_epoch: int | None = None
    permit_consumed: bool = False
    effect_count: int = 0
    authoritative_settlement: str = "NONE"  # NONE | FINALIZED | CONTRADICTORY
    finalized: bool = False
    key_status: str = "ACTIVE"  # ACTIVE | RETIRED | REVOKED
    issued_under_active: bool = False


def actions(s: S):
    if (
        s.grant_active
        and s.key_status == "ACTIVE"
        and s.effect_count == 0
        and (s.permit_epoch is None or s.permit_consumed)
    ):
        yield "issue", S(
            grant_epoch=s.grant_epoch, grant_active=True, permit_epoch=s.grant_epoch,
            permit_consumed=False, effect_count=s.effect_count,
            authoritative_settlement=s.authoritative_settlement, finalized=s.finalized,
            key_status="ACTIVE", issued_under_active=True,
        )

    if s.key_status == "ACTIVE":
        yield "retire_key", S(
            grant_epoch=s.grant_epoch, grant_active=s.grant_active, permit_epoch=s.permit_epoch,
            permit_consumed=s.permit_consumed, effect_count=s.effect_count,
            authoritative_settlement=s.authoritative_settlement, finalized=s.finalized,
            key_status="RETIRED", issued_under_active=s.issued_under_active,
        )

    if s.key_status in {"ACTIVE", "RETIRED"}:
        yield "revoke_key", S(
            grant_epoch=s.grant_epoch, grant_active=s.grant_active, permit_epoch=s.permit_epoch,
            permit_consumed=s.permit_consumed, effect_count=s.effect_count,
            authoritative_settlement=s.authoritative_settlement, finalized=s.finalized,
            key_status="REVOKED", issued_under_active=s.issued_under_active,
        )

    if s.grant_active:
        yield "revoke", S(
            grant_epoch=s.grant_epoch + 1, grant_active=False, permit_epoch=s.permit_epoch,
            permit_consumed=s.permit_consumed, effect_count=s.effect_count,
            authoritative_settlement=s.authoritative_settlement, finalized=s.finalized,
            key_status=s.key_status, issued_under_active=s.issued_under_active,
        )

    key_allows_consume = (
        s.key_status == "ACTIVE"
        or (s.key_status == "RETIRED" and s.issued_under_active)
    )
    if (
        s.permit_epoch is not None
        and not s.permit_consumed
        and s.grant_active
        and s.permit_epoch == s.grant_epoch
        and key_allows_consume
    ):
        yield "consume", S(
            grant_epoch=s.grant_epoch, grant_active=s.grant_active, permit_epoch=s.permit_epoch,
            permit_consumed=True, effect_count=s.effect_count,
            authoritative_settlement=s.authoritative_settlement, finalized=s.finalized,
            key_status=s.key_status, issued_under_active=s.issued_under_active,
        )

    if s.permit_consumed and s.effect_count == 0:
        yield "effect", S(
            grant_epoch=s.grant_epoch, grant_active=s.grant_active, permit_epoch=s.permit_epoch,
            permit_consumed=True, effect_count=1,
            authoritative_settlement=s.authoritative_settlement, finalized=s.finalized,
            key_status=s.key_status, issued_under_active=s.issued_under_active,
        )

    if s.effect_count == 1 and s.authoritative_settlement != "FINALIZED":
        yield "verify_final", S(
            grant_epoch=s.grant_epoch, grant_active=s.grant_active, permit_epoch=s.permit_epoch,
            permit_consumed=s.permit_consumed, effect_count=1,
            authoritative_settlement="FINALIZED", finalized=s.finalized,
            key_status=s.key_status, issued_under_active=s.issued_under_active,
        )

    if s.authoritative_settlement == "FINALIZED" and not s.finalized:
        yield "finalize", S(
            grant_epoch=s.grant_epoch, grant_active=s.grant_active, permit_epoch=s.permit_epoch,
            permit_consumed=s.permit_consumed, effect_count=s.effect_count,
            authoritative_settlement=s.authoritative_settlement, finalized=True,
            key_status=s.key_status, issued_under_active=s.issued_under_active,
        )


def invariant_failures(s: S) -> list[str]:
    failures: list[str] = []
    if s.effect_count > 1:
        failures.append("DUPLICATE_EFFECT")
    if s.effect_count and not s.permit_consumed:
        failures.append("EFFECT_WITHOUT_CONSUMED_PERMIT")
    if s.finalized and (s.effect_count != 1 or s.authoritative_settlement != "FINALIZED"):
        failures.append("FINALIZED_WITHOUT_AUTHORITATIVE_EFFECT")
    if s.permit_consumed and s.permit_epoch is None:
        failures.append("CONSUMED_WITHOUT_PERMIT")
    if s.permit_consumed and s.key_status == "REVOKED" and not s.issued_under_active:
        failures.append("CONSUMED_UNDER_REVOKED_KEY")
    if s.key_status == "REVOKED" and s.effect_count and not s.issued_under_active:
        failures.append("EFFECT_UNDER_NEVER_ACTIVE_REVOKED_KEY")
    return failures


def main(max_depth: int = 10) -> None:
    initial = S()
    q = deque([(initial, ())])
    seen = {initial}
    transitions = 0
    violations: list[dict] = []
    while q:
        state, path = q.popleft()
        for name, nxt in actions(state):
            transitions += 1
            next_path = path + (name,)
            failures = invariant_failures(nxt)
            if failures:
                violations.append({"path": next_path, "state": nxt.__dict__, "failures": failures})
            if len(next_path) < max_depth and nxt not in seen:
                seen.add(nxt)
                q.append((nxt, next_path))

    stale = S(grant_epoch=2, grant_active=False, permit_epoch=1, permit_consumed=False)
    stale_can_consume = any(name == "consume" for name, _ in actions(stale))
    revoked = S(key_status="REVOKED", permit_epoch=1, permit_consumed=False, grant_active=True, issued_under_active=True)
    revoked_can_consume = any(name == "consume" for name, _ in actions(revoked))
    retired_fresh = S(key_status="RETIRED", permit_epoch=1, grant_active=True, issued_under_active=False)
    retired_fresh_can_consume = any(name == "consume" for name, _ in actions(retired_fresh))
    resurrect = any(nxt.key_status == "ACTIVE" for name, nxt in actions(S(key_status="REVOKED")) if name != "issue")

    report = {
        "suite": "FAAR v0.4 bounded permit/key protocol model check",
        "max_depth": max_depth,
        "unique_states": len(seen),
        "transitions_explored": transitions,
        "invariant_violations": len(violations),
        "stale_permit_consumable_after_revoke": stale_can_consume,
        "revoked_key_consumable": revoked_can_consume,
        "retired_key_consumable_if_issued_after_retire": retired_fresh_can_consume,
        "revoked_key_resurrectable": resurrect,
        "pass": (
            not violations
            and not stale_can_consume
            and not revoked_can_consume
            and not retired_fresh_can_consume
            and not resurrect
        ),
        "claim_boundary": "Bounded abstract-state exploration; not formal verification of implementation or external venues.",
    }
    if violations:
        report["first_violation"] = violations[0]
    print(json.dumps(report, indent=2))
    if not report["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
