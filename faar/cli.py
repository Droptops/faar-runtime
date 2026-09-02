from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .adapters import MockMode, MockVenue
from .anchor import FileAuthorityAnchor
from .attestation import Ed25519TrustStore
from .canonical import canonical_hash
from .gates import evaluate_authority, evaluate_capability, evaluate_risk
from .models import AttestationKind, IntentState, utcnow
from .parsing import parse_authority, parse_grant, parse_intent, parse_risk
from .runtime import FAARRuntime
from .permits import ConstrainedPermitAuthority, Ed25519PermitSignature, ExecutionPermitVerifier
from .settlement import MockSettlementVerifier
from .store import SQLiteIntentStore


_DEMO_KEY_KINDS = {
    "demo-authority": {AttestationKind.AUTHORITY},
    "demo-risk": {AttestationKind.RISK},
}
# Embedded in source on purpose: `mock-run` is a self-contained demo against the
# in-process mock venue and cannot be confused with a live trust domain.
_DEMO_EVIDENCE_KEY = b"demo-evidence-key-not-for-production!!"


def _reject_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key}")
        out[key] = value
    return out


def _reject_nonfinite_constant(value: str):
    raise ValueError(f"non-finite JSON constant is not allowed: {value}")


def _load(path: str) -> dict:
    return json.loads(
        Path(path).read_text(),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite_constant,
    )


def _evidence_key(args) -> bytes | None:
    """Evidence MAC key from the environment, never from the command line."""
    if getattr(args, "demo_evidence_key", False):
        return _DEMO_EVIDENCE_KEY
    name = getattr(args, "evidence_key_env", None)
    if not name:
        return None
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"environment variable {name} is not set")
    return value.encode("utf-8")


def _open_store(args, *, evidence_key: bytes | None = None) -> SQLiteIntentStore:
    anchor = FileAuthorityAnchor(args.anchor) if getattr(args, "anchor", None) else None
    return SQLiteIntentStore(args.db, evidence_key=evidence_key, authority_anchor=anchor)


def _emit(payload) -> None:
    print(json.dumps(payload, indent=2, default=str))


def _stored(row) -> dict:
    return {
        "intent_id": row.intent_id,
        "state": row.state.value,
        "effect_id": row.effect_id,
        "reason_codes": list(row.reason_codes),
        "submission_count": row.submission_count,
        "ambiguity_until": row.ambiguity_until,
        "updated_at": row.updated_at,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="faar", description="FAAR deterministic financial authority runtime")
    sub = parser.add_subparsers(dest="command", required=True)

    def with_db(p, *, anchor: bool = True):
        p.add_argument("--db", required=True, help="path to the reference SQLite store")
        if anchor:
            p.add_argument("--anchor", help="path to the external authority anchor file (keep it outside the DB backup set)")
        return p

    p_hash = sub.add_parser("hash-intent", help="print the canonical SHA-256 of an intent")
    p_hash.add_argument("intent")

    p_grant = with_db(sub.add_parser("provision-grant", help="provision an immutable grant version into a local reference store"))
    p_grant.add_argument("--grant", required=True)

    p_status = with_db(sub.add_parser("set-grant-status", help="local reference admin: set ACTIVE/PAUSED/REVOKED runtime status"))
    p_status.add_argument("--principal-id", required=True)
    p_status.add_argument("--grant-id", required=True)
    p_status.add_argument("--grant-version", required=True, type=int)
    p_status.add_argument("--status", required=True, choices=["ACTIVE", "PAUSED", "REVOKED"])

    p_eval = sub.add_parser("evaluate", help="evaluate authority, capability and risk without executing")
    for name in ("--intent", "--grant", "--risk", "--authority"):
        p_eval.add_argument(name, required=True)

    p_mock = sub.add_parser("mock-run", help="DEMO ONLY: execute against the deterministic mock venue")
    for name in ("--intent", "--grant", "--risk", "--authority"):
        p_mock.add_argument(name, required=True)
    p_mock.add_argument("--db", default="faar-demo.sqlite")
    p_mock.add_argument("--anchor")
    p_mock.add_argument("--mode", choices=[m.value for m in MockMode], default=MockMode.SUCCESS.value)
    p_mock.add_argument("--demo-auto-provision", action="store_true", help="DEMO ONLY: provision the supplied grant if absent.")

    p_inspect = with_db(sub.add_parser("inspect", help="inspect one persisted intent and its evidence"))
    p_inspect.add_argument("--intent-id", required=True)

    p_ev = with_db(sub.add_parser("verify-evidence", help="verify the per-intent evidence hash chain (and MAC/head when keyed)"), anchor=False)
    p_ev.add_argument("--intent-id", required=True)
    p_ev.add_argument("--evidence-key-env", help="name of the environment variable holding the evidence MAC key")
    p_ev.add_argument("--demo-evidence-key", action="store_true", help="DEMO ONLY: verify with the embedded demo key")

    p_rebuild = with_db(sub.add_parser("rebuild-evidence-head", help="OPERATOR: commit a signed head for a pre-0.4 chain that verifies"), anchor=False)
    p_rebuild.add_argument("--intent-id", required=True)
    p_rebuild.add_argument("--evidence-key-env", required=True)

    p_usage = with_db(sub.add_parser("usage", help="show grant-level atomic usage reservations"), anchor=False)
    p_usage.add_argument("--grant-id", required=True)
    p_usage.add_argument("--grant-version", required=True, type=int)

    p_held = with_db(sub.add_parser("held-usage", help="OPERATOR: HELD reservations joined to intent state"), anchor=False)
    p_held.add_argument("--principal-id")

    p_lg = with_db(sub.add_parser("list-grants", help="OPERATOR: grant versions with effective runtime status"))
    p_lg.add_argument("--principal-id")

    p_li = with_db(sub.add_parser("list-intents", help="OPERATOR: intents by state and/or principal"), anchor=False)
    p_li.add_argument("--state", choices=[s.value for s in IntentState])
    p_li.add_argument("--principal-id")
    p_li.add_argument("--limit", type=int, default=200)

    with_db(sub.add_parser("list-leases", help="OPERATOR: durable intent leases (a lease with no live worker is stale)"), anchor=False)

    p_cl = with_db(sub.add_parser("clear-lease", help="OPERATOR: clear a stale lease after reconciling external settlement"), anchor=False)
    p_cl.add_argument("--intent-id", required=True)
    p_cl.add_argument("--owner-token", required=True, help="exact owner_token printed by list-leases")

    p_halt = with_db(sub.add_parser("halt", help="EMERGENCY: stop every grant in scope and fence outstanding permits"))
    p_halt.add_argument("--scope", required=True, help="'global' or 'principal:<principal_id>'")
    p_halt.add_argument("--reason", required=True)

    p_resume = with_db(sub.add_parser("resume", help="lift a halt; permits issued before it stay dead"))
    p_resume.add_argument("--scope", required=True)

    with_db(sub.add_parser("controls", help="show emergency control records"), anchor=False)

    p_rar = with_db(sub.add_parser("revoke-after-restore", help="OPERATOR: close a grant version whose authority state regressed behind its anchor"))
    p_rar.add_argument("--grant-id", required=True)
    p_rar.add_argument("--grant-version", required=True, type=int)

    with_db(sub.add_parser("checkpoint", help="fold the WAL into the database file before taking a backup"), anchor=False)
    return parser


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    command = args.command

    if command == "hash-intent":
        print(canonical_hash(parse_intent(_load(args.intent))))
        return

    if command == "provision-grant":
        store = _open_store(args)
        grant = parse_grant(_load(args.grant))
        digest = canonical_hash(grant)
        store.provision_grant(grant, digest)
        _emit({"grant_id": grant.grant_id, "version": grant.version, "grant_hash": digest})
        return

    if command == "set-grant-status":
        store = _open_store(args)
        store.set_grant_status(args.principal_id, args.grant_id, args.grant_version, args.status)
        _emit({"grant_id": args.grant_id, "version": args.grant_version, "runtime_status": args.status})
        return

    if command == "inspect":
        store = _open_store(args)
        row = store.get(args.intent_id)
        payload = _stored(row)
        payload.update({"intent_hash": row.intent_hash, "created_at": row.created_at, "evidence": store.evidence(args.intent_id)})
        _emit(payload)
        return

    if command == "verify-evidence":
        key = _evidence_key(args)
        store = SQLiteIntentStore(args.db, evidence_key=key)
        ok = store.verify_evidence_chain(args.intent_id)
        _emit({"intent_id": args.intent_id, "evidence_chain_valid": ok, "keyed": key is not None})
        raise SystemExit(0 if ok else 2)

    if command == "rebuild-evidence-head":
        store = SQLiteIntentStore(args.db, evidence_key=_evidence_key(args))
        _emit({"intent_id": args.intent_id, "head_committed": store.rebuild_evidence_head(args.intent_id)})
        return

    if command == "usage":
        _emit(SQLiteIntentStore(args.db).usage(args.grant_id, args.grant_version))
        return

    if command == "held-usage":
        _emit(SQLiteIntentStore(args.db).held_usage(principal_id=args.principal_id))
        return

    if command == "list-grants":
        _emit(_open_store(args).list_grants(principal_id=args.principal_id))
        return

    if command == "list-intents":
        rows = SQLiteIntentStore(args.db).list_intents(state=args.state, principal_id=args.principal_id, limit=args.limit)
        _emit([_stored(r) for r in rows])
        return

    if command == "list-leases":
        _emit(SQLiteIntentStore(args.db).list_leases())
        return

    if command == "clear-lease":
        cleared = SQLiteIntentStore(args.db).clear_stale_intent_lease(args.intent_id, expected_owner_token=args.owner_token)
        _emit({"intent_id": args.intent_id, "cleared": cleared})
        if not cleared:
            raise SystemExit(2)
        return

    if command == "halt":
        store = _open_store(args)
        fenced = store.halt(args.scope, reason=args.reason)
        _emit({"scope": args.scope, "halted": True, "grant_versions_fenced": fenced})
        return

    if command == "resume":
        store = _open_store(args)
        store.resume(args.scope)
        _emit({"scope": args.scope, "halted": False})
        return

    if command == "controls":
        _emit(SQLiteIntentStore(args.db).controls())
        return

    if command == "revoke-after-restore":
        store = _open_store(args)
        epoch, fence = store.revoke_after_restore(args.grant_id, args.grant_version)
        _emit({"grant_id": args.grant_id, "version": args.grant_version, "runtime_status": "REVOKED", "runtime_epoch": epoch, "fence_counter": fence})
        return

    if command == "checkpoint":
        SQLiteIntentStore(args.db).checkpoint()
        _emit({"db": args.db, "checkpointed": True})
        return

    intent = parse_intent(_load(args.intent))
    grant = parse_grant(_load(args.grant))
    risk = parse_risk(_load(args.risk))
    authority = parse_authority(_load(args.authority))

    if command == "evaluate":
        now = utcnow()
        decisions = [
            evaluate_authority(authority),
            evaluate_capability(intent, grant, now),
            evaluate_risk(intent, grant, risk, now),
        ]
        _emit([{"layer": d.layer, "verdict": d.verdict.value, "reason_codes": list(d.reason_codes)} for d in decisions])
        return

    # mock-run is intentionally self-contained and cannot be confused with a live
    # trust domain: fresh Ed25519 keys are generated per invocation and the only
    # adapter available here is MockVenue.
    store = _open_store(args, evidence_key=_DEMO_EVIDENCE_KEY)
    if args.demo_auto_provision:
        store.provision_grant(grant, canonical_hash(grant))
    trust = Ed25519TrustStore.generate(_DEMO_KEY_KINDS)
    verifier_trust = trust.public_verifier()
    permit_sig = Ed25519PermitSignature("demo-permit")
    permit_authority = ConstrainedPermitAuthority(store, verifier_trust, permit_sig)
    permit_verifier = ExecutionPermitVerifier(permit_sig.public_verifier(), store)
    venue = MockVenue(permit_verifier=permit_verifier, name=intent.venue, mode=MockMode(args.mode), clock=lambda: risk.observed_at)
    settlement = MockSettlementVerifier(venue)
    aa = trust.sign("demo-authority", AttestationKind.AUTHORITY, authority, intent, issued_at=risk.observed_at, ttl_seconds=30)
    ra = trust.sign("demo-risk", AttestationKind.RISK, risk, intent, issued_at=risk.observed_at, ttl_seconds=30)
    runtime = FAARRuntime(
        store, {intent.venue: venue}, verifier_trust, permit_authority, {intent.venue: settlement},
        allow_test_time_override=True,
    )
    result = runtime.process(
        intent, authority, grant, risk,
        authority_attestation=aa,
        risk_attestation=ra,
        now=risk.observed_at,
    )
    _emit({
        "intent_id": result.intent_id,
        "state": result.state.value,
        "effect_id": result.effect_id,
        "reason_codes": list(result.reason_codes),
        "replayed": result.replayed,
        "submission_count": result.submission_count,
        "successful_effect_count": venue.successful_effect_count(intent.intent_id, principal_id=intent.principal_id),
    })


if __name__ == "__main__":
    main()
