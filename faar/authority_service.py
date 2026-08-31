"""Out-of-process permit authority. Holds signing keys. Intentionally boring.

The executor process must not import this module.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
from datetime import datetime
from pathlib import Path

from .attestation import Ed25519AttestationSigner
from .canonical import canonical_hash, canonical_json
from .descriptors import VerifierPurpose
from .ledger import SQLiteAuthorityLedger
from .models import AttestationKind, ExecutionRequest, utcnow
from .parsing import parse_attestation, parse_authority, parse_grant, parse_intent, parse_risk
from .permits import ConstrainedPermitAuthority, PermitIssuanceError
from .signing import (
    FileBackedEd25519Provider,
    InMemoryEd25519Provider,
    ProviderBackedAttestationKey,
    ProviderBackedPermitSigner,
)
from .store import GrantConflict, SQLiteIntentStore, UnknownGrant


class AuthorityService:
    def __init__(
        self,
        store: SQLiteIntentStore,
        provider: InMemoryEd25519Provider,
        *,
        max_permit_ttl_seconds: int = 5,
        allow_test_time_override: bool = False,
        ledger: SQLiteAuthorityLedger | None = None,
    ) -> None:
        self.store = store
        self.ledger = ledger or SQLiteAuthorityLedger(store)
        self.provider = provider
        self.allow_test_time_override = allow_test_time_override
        permit_id = provider.permit_key_id()
        attestation_keys = {}
        attestation_kinds = {}
        for key_id in provider.list_key_ids():
            desc = provider.public_descriptor(key_id)
            if desc.purpose is VerifierPurpose.ATTESTATION:
                attestation_keys[key_id] = ProviderBackedAttestationKey(provider, key_id)
                attestation_kinds[key_id] = {AttestationKind(k) for k in desc.key_kinds}
        if not attestation_keys:
            raise ValueError("authority service requires attestation signing keys")
        self.attestation_signer = Ed25519AttestationSigner(attestation_keys, key_kinds=attestation_kinds)
        trust = self.attestation_signer.public_verifier()
        signer = ProviderBackedPermitSigner(provider, permit_id)
        self.permit_authority = ConstrainedPermitAuthority(
            store, trust, signer, max_permit_ttl_seconds=max_permit_ttl_seconds
        )

    def descriptors(self) -> list[dict]:
        return self.provider.export_descriptors()

    def _now(self, payload: dict) -> datetime:
        raw = payload.get("now")
        if raw is not None and self.allow_test_time_override:
            parsed = datetime.fromisoformat(str(raw))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError("AUTHORITY_TIME_NOT_AWARE")
            return parsed
        return utcnow()

    def authorize(self, payload: dict) -> dict:
        intent = parse_intent(payload["intent"])
        grant = parse_grant(payload["grant"])
        authority = parse_authority(payload["authority"])
        risk = parse_risk(payload["risk"])
        now = self._now(payload)
        try:
            self.store.verify_grant(grant, canonical_hash(grant))
        except UnknownGrant:
            self.store.provision_grant(grant, canonical_hash(grant))
        except GrantConflict:
            return {"ok": False, "reasons": ["PERMIT_GRANT_NOT_TRUSTED"]}
        self.store.register(intent, canonical_hash(intent))
        ok, reasons = self.store.reserve_usage(intent, grant, risk, now)
        if not ok:
            return {"ok": False, "reasons": list(reasons)}
        authority_key = next(
            kid for kid, kinds in self.provider.attestation_key_ids().items() if "AUTHORITY" in kinds
        )
        risk_key = next(kid for kid, kinds in self.provider.attestation_key_ids().items() if "RISK" in kinds)
        aa = self.attestation_signer.sign(authority_key, AttestationKind.AUTHORITY, authority, intent, issued_at=now)
        ra = self.attestation_signer.sign(risk_key, AttestationKind.RISK, risk, intent, issued_at=now)
        request = ExecutionRequest.from_intent(intent)
        try:
            permit = self.permit_authority.issue(
                request,
                intent=intent,
                authority=authority,
                grant=grant,
                risk=risk,
                authority_attestation=aa,
                risk_attestation=ra,
                now=now,
            )
        except PermitIssuanceError as exc:
            return {"ok": False, "reasons": list(exc.reasons)}
        self.ledger.record_lineage(
            permit_id=permit.permit.permit_id,
            intent_id=intent.intent_id,
            grant_hash=canonical_hash(grant),
            authority_attestation_hash=canonical_hash(aa),
            risk_attestation_hash=canonical_hash(ra),
            issued_at=permit.permit.issued_at,
        )
        return {
            "ok": True,
            "permit": json.loads(canonical_json(permit)),
            "request": json.loads(canonical_json(request)),
            "descriptors": self.descriptors(),
        }

    def issue(self, payload: dict) -> dict:
        intent = parse_intent(payload["intent"])
        grant = parse_grant(payload["grant"])
        authority = parse_authority(payload["authority"])
        risk = parse_risk(payload["risk"])
        aa = parse_attestation(payload["authority_attestation"])
        ra = parse_attestation(payload["risk_attestation"])
        now = self._now(payload)
        request = ExecutionRequest.from_intent(intent)
        try:
            permit = self.permit_authority.issue(
                request,
                intent=intent,
                authority=authority,
                grant=grant,
                risk=risk,
                authority_attestation=aa,
                risk_attestation=ra,
                now=now,
            )
        except PermitIssuanceError as exc:
            return {"ok": False, "reasons": list(exc.reasons)}
        return {"ok": True, "permit": json.loads(canonical_json(permit)), "request": json.loads(canonical_json(request))}

    def handle(self, message: dict) -> dict:
        op = message.get("op")
        payload = message.get("payload") or {}
        req_id = message.get("id")
        try:
            if op == "descriptors":
                result = {"ok": True, "descriptors": self.descriptors()}
            elif op == "authorize":
                result = self.authorize(payload)
            elif op == "issue":
                result = self.issue(payload)
            else:
                result = {"ok": False, "reasons": ["AUTHORITY_OP_UNKNOWN"]}
        except Exception as exc:
            result = {"ok": False, "reasons": ["AUTHORITY_INTERNAL", type(exc).__name__]}
        result["id"] = req_id
        return result


class AuthorityClient:
    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path

    def call(self, op: str, payload: dict | None = None) -> dict:
        req = {"id": os.getpid(), "op": op, "payload": payload or {}}
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(self.socket_path)
            sock.sendall((json.dumps(req) + "\n").encode("utf-8"))
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        finally:
            sock.close()
        if not buf:
            raise RuntimeError("AUTHORITY_NO_RESPONSE")
        return json.loads(buf.decode("utf-8"))


def _serve(service: AuthorityService, socket_path: str) -> None:
    path = Path(socket_path)
    if path.exists():
        path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(socket_path)
    server.listen(16)
    while True:
        conn, _ = server.accept()
        with conn:
            buf = b""
            while b"\n" not in buf:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                continue
            message = json.loads(buf.decode("utf-8"))
            response = service.handle(message)
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="faar-authority", description="FAAR out-of-process permit authority")
    parser.add_argument("--db", required=True)
    parser.add_argument("--key-dir", required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--allow-test-time", action="store_true")
    args = parser.parse_args(argv)
    store = SQLiteIntentStore(args.db)
    if not (Path(args.key_dir) / "index.json").exists():
        provider = FileBackedEd25519Provider.create(args.key_dir)
    else:
        provider = FileBackedEd25519Provider.load(args.key_dir)
    service = AuthorityService(store, provider, allow_test_time_override=args.allow_test_time)
    _serve(service, args.socket)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
