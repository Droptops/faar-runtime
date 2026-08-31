"""Principal-bound authenticated ingress for the FAAR v0.4 authority plane.

This is a reference control plane, not an internet-facing service. It proves:

* economic intents are bound to an authenticated principal
* callers cannot substitute another principal_id
* durable intent IDs are namespaced to that principal (or server-minted)
* grant administration is a distinct role from execution submission
* security time comes from the server clock

Direct store/runtime access remains inside the TCB. Untrusted coordinators must
go through this layer.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum

from .attestation import has_signing_api
from .canonical import canonical_json
from .keys import KeyLifecycle, ed25519_public_material_hash
from .models import CapabilityGrant, Intent
from .store import GrantConflict, SQLiteIntentStore


class IngressRole(StrEnum):
    PRINCIPAL = "PRINCIPAL"
    ADMIN = "ADMIN"


class IngressDenied(RuntimeError):
    def __init__(self, reasons: tuple[str, ...]):
        super().__init__(",".join(reasons))
        self.reasons = reasons


@dataclass(frozen=True)
class IngressToken:
    principal_id: str
    role: IngressRole
    key_id: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "role", IngressRole(self.role))
        if not self.principal_id or not self.key_id or not self.signature:
            raise ValueError("ingress token identity fields are required")
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("ingress token timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("ingress token expires_at must be after issued_at")


def _token_payload(*, principal_id: str, role: IngressRole, key_id: str, issued_at: datetime, expires_at: datetime) -> bytes:
    return canonical_json({
        "principal_id": principal_id,
        "role": IngressRole(role).value,
        "key_id": key_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }).encode("utf-8")


def principal_intent_prefix(principal_id: str) -> str:
    digest = hashlib.sha256(principal_id.encode("utf-8")).hexdigest()[:20]
    return f"intent_{digest}_"


class IngressTokenIssuer:
    """Mints short-lived identity tokens. Not an execution permit signer."""

    def __init__(self, backend, *, max_ttl_seconds: int = 60) -> None:
        if not has_signing_api(backend):
            raise ValueError("ingress issuer requires a signing-capable backend")
        if max_ttl_seconds <= 0:
            raise ValueError("max_ttl_seconds must be positive")
        self.backend = backend
        self.max_ttl_seconds = max_ttl_seconds

    def issue(
        self,
        principal_id: str,
        role: IngressRole,
        *,
        now: datetime,
        ttl_seconds: int | None = None,
    ) -> IngressToken:
        ttl = ttl_seconds if ttl_seconds is not None else self.max_ttl_seconds
        if ttl <= 0 or ttl > self.max_ttl_seconds:
            raise IngressDenied(("INGRESS_TTL_INVALID",))
        expires_at = now + timedelta(seconds=ttl)
        payload = _token_payload(
            principal_id=principal_id, role=IngressRole(role), key_id=self.backend.signer_id,
            issued_at=now, expires_at=expires_at,
        )
        return IngressToken(
            principal_id=principal_id,
            role=IngressRole(role),
            key_id=self.backend.signer_id,
            issued_at=now,
            expires_at=expires_at,
            signature=self.backend.sign(payload),
        )


class IngressAuthenticator:
    """Verify-only principal authenticator. No minting API."""

    def __init__(self, verifier, *, max_clock_skew_seconds: int = 2, key_lifecycle: KeyLifecycle | None = None) -> None:
        if has_signing_api(verifier):
            raise ValueError("ingress authenticator must be verify-only")
        self.verifier = verifier
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.lifecycle = key_lifecycle

    def authenticate(self, token: IngressToken, *, now: datetime) -> IngressToken:
        reasons: list[str] = []
        if token.key_id != self.verifier.signer_id:
            reasons.append("INGRESS_KEY_UNKNOWN")
        if self.lifecycle is not None:
            ok, key_reason = self.lifecycle.accept_artifact(token.key_id, issued_at=token.issued_at)
            if not ok:
                reasons.append("INGRESS_" + (key_reason or "KEY_REJECTED"))
        payload = _token_payload(
            principal_id=token.principal_id, role=token.role, key_id=token.key_id,
            issued_at=token.issued_at, expires_at=token.expires_at,
        )
        if not self.verifier.verify(payload, token.signature):
            reasons.append("INGRESS_SIGNATURE_INVALID")
        skew = timedelta(seconds=self.max_clock_skew_seconds)
        if token.issued_at > now + skew:
            reasons.append("INGRESS_TOKEN_FROM_FUTURE")
        if now > token.expires_at + skew:
            reasons.append("INGRESS_TOKEN_EXPIRED")
        if reasons:
            raise IngressDenied(tuple(reasons))
        return token


class AuthenticatedIngress:
    """Binds untrusted proposals to an authenticated principal and server clock."""

    def __init__(
        self,
        store: SQLiteIntentStore,
        authenticator: IngressAuthenticator,
        *,
        clock,
        key_lifecycle: KeyLifecycle | None = None,
    ) -> None:
        if has_signing_api(authenticator):
            raise ValueError("authenticated ingress must not hold a signing authenticator")
        self.store = store
        self.authenticator = authenticator
        self.clock = clock
        self.key_lifecycle = key_lifecycle or KeyLifecycle(store, "INGRESS")
        if authenticator.lifecycle is None:
            authenticator.lifecycle = self.key_lifecycle
        material = getattr(authenticator.verifier, "material_hash", None)
        if material is None:
            public = getattr(authenticator.verifier, "_public_key", None)
            if public is not None:
                material = ed25519_public_material_hash(public)
        self.key_lifecycle.register_active(authenticator.verifier.signer_id, material_hash=material)

    def _caller(self, token: IngressToken, *, required: IngressRole) -> IngressToken:
        now = self.clock()
        caller = self.authenticator.authenticate(token, now=now)
        if caller.role is not required:
            raise IngressDenied(("INGRESS_ROLE_DENIED",))
        return caller

    def mint_intent_id(self, principal_id: str) -> str:
        seq = self.store.next_principal_intent_seq(principal_id)
        body = hashlib.sha256(f"{principal_id}\x1f{seq}".encode("utf-8")).hexdigest()[:16]
        return principal_intent_prefix(principal_id) + body

    def bind_intent(self, token: IngressToken, proposed: Intent) -> Intent:
        caller = self._caller(token, required=IngressRole.PRINCIPAL)
        if proposed.principal_id != caller.principal_id:
            raise IngressDenied(("INGRESS_PRINCIPAL_SUBSTITUTION",))
        prefix = principal_intent_prefix(caller.principal_id)
        intent_id = proposed.intent_id
        if intent_id == "__mint__":
            intent_id = self.mint_intent_id(caller.principal_id)
        elif not intent_id.startswith(prefix):
            raise IngressDenied(("INGRESS_INTENT_ID_NOT_PRINCIPAL_BOUND",))
        now = self.clock()
        bound = replace(
            proposed,
            principal_id=caller.principal_id,
            intent_id=intent_id,
            created_at=now,
        )
        return bound

    def provision_grant(self, token: IngressToken, grant: CapabilityGrant, grant_hash: str) -> None:
        self._caller(token, required=IngressRole.ADMIN)
        self.store.provision_grant(grant, grant_hash)

    def set_grant_status(
        self, token: IngressToken, principal_id: str, grant_id: str, version: int, status: str
    ) -> None:
        self._caller(token, required=IngressRole.ADMIN)
        self.store.set_grant_status(principal_id, grant_id, version, status)
