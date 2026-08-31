from __future__ import annotations

import argparse
import json
from pathlib import Path

from .adapters import MockMode, MockVenue
from .attestation import HMACTrustStore
from .canonical import canonical_hash
from .gates import evaluate_authority, evaluate_capability, evaluate_risk
from .models import AttestationKind, utcnow
from .parsing import parse_authority, parse_grant, parse_intent, parse_risk
from .runtime import FAARRuntime
from .store import SQLiteIntentStore


_DEMO_KEYS = {
    "demo-authority": b"demo-authority-key-not-for-production",
    "demo-risk": b"demo-risk-key-material-not-production",
}
_DEMO_KEY_KINDS = {
    "demo-authority": {AttestationKind.AUTHORITY},
    "demo-risk": {AttestationKind.RISK},
}
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


def main() -> None:
    parser = argparse.ArgumentParser(prog="faar", description="FAAR deterministic financial authority runtime")
    sub = parser.add_subparsers(dest="command", required=True)

    p_hash = sub.add_parser("hash-intent", help="print the canonical SHA-256 of an intent")
    p_hash.add_argument("intent")

    p_grant = sub.add_parser("provision-grant", help="provision an immutable grant version into a local reference store")
    p_grant.add_argument("--grant", required=True)
    p_grant.add_argument("--db", required=True)

    p_status = sub.add_parser("set-grant-status", help="local reference admin: set ACTIVE/PAUSED/REVOKED runtime status")
    p_status.add_argument("--grant-id", required=True)
    p_status.add_argument("--grant-version", required=True, type=int)
    p_status.add_argument("--status", required=True, choices=["ACTIVE", "PAUSED", "REVOKED"])
    p_status.add_argument("--db", required=True)

    p_eval = sub.add_parser("evaluate", help="evaluate authority, capability and risk without executing")
    p_eval.add_argument("--intent", required=True)
    p_eval.add_argument("--grant", required=True)
    p_eval.add_argument("--risk", required=True)
    p_eval.add_argument("--authority", required=True)

    p_mock = sub.add_parser("mock-run", help="DEMO ONLY: execute against the deterministic mock venue")
    p_mock.add_argument("--intent", required=True)
    p_mock.add_argument("--grant", required=True)
    p_mock.add_argument("--risk", required=True)
    p_mock.add_argument("--authority", required=True)
    p_mock.add_argument("--db", default="faar-demo.sqlite")
    p_mock.add_argument("--mode", choices=[m.value for m in MockMode], default=MockMode.SUCCESS.value)
    p_mock.add_argument(
        "--demo-auto-provision",
        action="store_true",
        help="DEMO ONLY: provision the supplied grant if absent.",
    )

    p_inspect = sub.add_parser("inspect", help="inspect one persisted intent")
    p_inspect.add_argument("--intent-id", required=True)
    p_inspect.add_argument("--db", required=True)

    p_ev = sub.add_parser("verify-evidence", help="verify the per-intent evidence hash chain")
    p_ev.add_argument("--intent-id", required=True)
    p_ev.add_argument("--db", required=True)

    p_usage = sub.add_parser("usage", help="show grant-level atomic usage reservations")
    p_usage.add_argument("--grant-id", required=True)
    p_usage.add_argument("--grant-version", required=True, type=int)
    p_usage.add_argument("--db", required=True)

    args = parser.parse_args()

    if args.command == "hash-intent":
        print(canonical_hash(parse_intent(_load(args.intent))))
        return

    if args.command == "provision-grant":
        store = SQLiteIntentStore(args.db)
        grant = parse_grant(_load(args.grant))
        digest = canonical_hash(grant)
        store.provision_grant(grant, digest)
        print(json.dumps({"grant_id": grant.grant_id, "version": grant.version, "grant_hash": digest}, indent=2))
        return

    if args.command == "set-grant-status":
        store = SQLiteIntentStore(args.db)
        store.set_grant_status(args.grant_id, args.grant_version, args.status)
        print(json.dumps({"grant_id": args.grant_id, "version": args.grant_version, "runtime_status": args.status}, indent=2))
        return

    if args.command == "inspect":
        store = SQLiteIntentStore(args.db)
        row = store.get(args.intent_id)
        print(json.dumps({
            "intent_id": row.intent_id,
            "intent_hash": row.intent_hash,
            "state": row.state.value,
            "effect_id": row.effect_id,
            "reason_codes": list(row.reason_codes),
            "submission_count": row.submission_count,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
            "evidence": store.evidence(args.intent_id),
        }, indent=2))
        return

    if args.command == "verify-evidence":
        # The standalone verifier checks the public hash chain. Deployments using
        # evidence HMACs must provide their trusted key through application code/KMS.
        store = SQLiteIntentStore(args.db)
        ok = store.verify_evidence_chain(args.intent_id)
        print(json.dumps({"intent_id": args.intent_id, "evidence_chain_valid": ok}, indent=2))
        raise SystemExit(0 if ok else 2)

    if args.command == "usage":
        store = SQLiteIntentStore(args.db)
        print(json.dumps(store.usage(args.grant_id, args.grant_version), indent=2))
        return

    intent = parse_intent(_load(args.intent))
    grant = parse_grant(_load(args.grant))
    risk = parse_risk(_load(args.risk))
    authority = parse_authority(_load(args.authority))

    if args.command == "evaluate":
        now = utcnow()
        decisions = [
            evaluate_authority(authority),
            evaluate_capability(intent, grant, now),
            evaluate_risk(intent, grant, risk, now),
        ]
        print(json.dumps([
            {"layer": d.layer, "verdict": d.verdict.value, "reason_codes": list(d.reason_codes)} for d in decisions
        ], indent=2))
        return

    # mock-run is intentionally self-contained and cannot be confused with a live
    # trust domain: the fixed demo keys are embedded in source and the only adapter
    # available here is MockVenue.
    store = SQLiteIntentStore(args.db, evidence_key=_DEMO_EVIDENCE_KEY)
    if args.demo_auto_provision:
        store.provision_grant(grant, canonical_hash(grant))
    venue = MockVenue(name=intent.venue, mode=MockMode(args.mode))
    trust = HMACTrustStore(_DEMO_KEYS, key_kinds=_DEMO_KEY_KINDS)
    aa = trust.sign("demo-authority", AttestationKind.AUTHORITY, authority, intent, issued_at=risk.observed_at, ttl_seconds=30)
    ra = trust.sign("demo-risk", AttestationKind.RISK, risk, intent, issued_at=risk.observed_at, ttl_seconds=30)
    runtime = FAARRuntime(store, {intent.venue: venue}, trust, allow_test_time_override=True)
    result = runtime.process(
        intent, authority, grant, risk,
        authority_attestation=aa,
        risk_attestation=ra,
        now=risk.observed_at,
    )
    print(json.dumps({
        "intent_id": result.intent_id,
        "state": result.state.value,
        "effect_id": result.effect_id,
        "reason_codes": list(result.reason_codes),
        "replayed": result.replayed,
        "submission_count": result.submission_count,
        "successful_effect_count": venue.successful_effect_count(intent.intent_id),
    }, indent=2))


if __name__ == "__main__":
    main()
