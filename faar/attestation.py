from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timedelta
from collections.abc import Iterable
from typing import Mapping, Protocol

from .canonical import canonical_hash, canonical_json
from .keys import KeyConflict, KeyLifecycle, KeyStatus, ed25519_public_material_hash
from .models import Attestation, AttestationAlgorithm, AttestationKind, Intent


def has_signing_api(obj: object) -> bool:
    """Defense-in-depth: True if `obj` exposes a callable `sign` minting path.

    Runtime and executor construction reject objects that expose `sign()`. This is
    not proof that an object holds no private key: an arbitrary Python object can
    retain signing material while offering only `verify()`. FAAR-provided verifier
    implementations accept public-key material only. Strong private-key isolation
    requires a separate signer process/KMS/HSM or an equivalent construction
    boundary; the long-term runtime API should take serialized public-key material
    and construct the verifier internally.
    """
    return callable(getattr(obj, "sign", None))


class AttestationVerifier(Protocol):
    def verify(
        self,
        attestation: Attestation,
        *,
        kind: AttestationKind,
        subject: object,
        intent: Intent,
        now: datetime,
    ) -> tuple[bool, tuple[str, ...]]: ...


class AttestationSigner(Protocol):
    def sign(
        self,
        key_id: str,
        kind: AttestationKind,
        subject: object,
        intent: Intent,
        *,
        issued_at: datetime,
        ttl_seconds: int = 30,
    ) -> Attestation: ...


def _normalize_kinds(
    key_ids: set[str], key_kinds: Mapping[str, Iterable[AttestationKind]]
) -> dict[str, frozenset[AttestationKind]]:
    if set(key_kinds) != key_ids:
        missing = sorted(key_ids - set(key_kinds))
        extra = sorted(set(key_kinds) - key_ids)
        raise ValueError(f"key_kinds must exactly cover keys; missing={missing}, extra={extra}")
    out: dict[str, frozenset[AttestationKind]] = {}
    for key_id, kinds in key_kinds.items():
        normalized = frozenset(AttestationKind(kind) for kind in kinds)
        if not normalized:
            raise ValueError(f"attestation key {key_id} must be scoped to at least one kind")
        out[str(key_id)] = normalized
    return out


def _payload(
    *,
    algorithm: AttestationAlgorithm,
    kind: AttestationKind,
    key_id: str,
    subject_hash: str,
    intent_hash: str,
    issued_at: datetime,
    expires_at: datetime,
) -> bytes:
    return canonical_json({
        "algorithm": algorithm.value,
        "kind": kind.value,
        "key_id": key_id,
        "subject_hash": subject_hash,
        "intent_hash": intent_hash,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }).encode("utf-8")


class HMACTrustStore:
    """Symmetric compatibility trust store.

    This remains useful for deterministic compatibility tests, but it is not a
    TCB-isolating verifier: anyone able to verify also has enough material to forge
    attestations. FAAR runtime construction rejects any trust object that exposes a
    signing API. HMAC keeps both `sign` and `verify` because the secret is shared;
    isolation is structural (Ed25519 signer vs verifier classes), not a `can_sign` flag.
    """

    algorithm = AttestationAlgorithm.HMAC_SHA256

    def __init__(
        self,
        keys: Mapping[str, bytes],
        *,
        key_kinds: Mapping[str, Iterable[AttestationKind]],
        max_clock_skew_seconds: int = 5,
    ) -> None:
        if not keys:
            raise ValueError("at least one attestation key is required")
        self._keys = {str(k): bytes(v) for k, v in keys.items()}
        if any(len(v) < 16 for v in self._keys.values()):
            raise ValueError("attestation keys must be at least 16 bytes")
        self._key_kinds = _normalize_kinds(set(self._keys), key_kinds)
        if max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds must be non-negative")
        self.max_clock_skew_seconds = max_clock_skew_seconds

    def _kind_allowed(self, key_id: str, kind: AttestationKind) -> bool:
        return kind in self._key_kinds.get(key_id, frozenset())

    def sign(
        self,
        key_id: str,
        kind: AttestationKind,
        subject: object,
        intent: Intent,
        *,
        issued_at: datetime,
        ttl_seconds: int = 30,
    ) -> Attestation:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        try:
            key = self._keys[key_id]
        except KeyError as exc:
            raise KeyError(f"unknown attestation key_id {key_id}") from exc
        if not self._kind_allowed(key_id, kind):
            raise PermissionError(f"attestation key {key_id} is not authorized for {kind.value}")
        expires_at = issued_at + timedelta(seconds=ttl_seconds)
        subject_hash = canonical_hash(subject)
        intent_hash = canonical_hash(intent)
        payload = _payload(
            algorithm=self.algorithm, kind=kind, key_id=key_id,
            subject_hash=subject_hash, intent_hash=intent_hash,
            issued_at=issued_at, expires_at=expires_at,
        )
        signature = hmac.new(key, payload, hashlib.sha256).hexdigest()
        return Attestation(
            kind, key_id, self.algorithm, subject_hash, intent_hash,
            issued_at, expires_at, signature,
        )

    def verify(
        self,
        attestation: Attestation,
        *,
        kind: AttestationKind,
        subject: object,
        intent: Intent,
        now: datetime,
    ) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        if attestation.algorithm != self.algorithm:
            reasons.append("ATTESTATION_ALGORITHM_MISMATCH")
        if attestation.kind != kind:
            reasons.append("ATTESTATION_KIND_MISMATCH")
        key = self._keys.get(attestation.key_id)
        if key is None:
            reasons.append("ATTESTATION_KEY_UNKNOWN")
            return False, tuple(reasons)
        if not self._kind_allowed(attestation.key_id, kind):
            reasons.append("ATTESTATION_KEY_KIND_NOT_ALLOWED")
        if attestation.subject_hash != canonical_hash(subject):
            reasons.append("ATTESTATION_SUBJECT_MISMATCH")
        if attestation.intent_hash != canonical_hash(intent):
            reasons.append("ATTESTATION_INTENT_MISMATCH")
        skew = timedelta(seconds=self.max_clock_skew_seconds)
        if attestation.issued_at > now + skew:
            reasons.append("ATTESTATION_FROM_FUTURE")
        if now > attestation.expires_at + skew:
            reasons.append("ATTESTATION_EXPIRED")
        payload = _payload(
            algorithm=attestation.algorithm, kind=attestation.kind, key_id=attestation.key_id,
            subject_hash=attestation.subject_hash, intent_hash=attestation.intent_hash,
            issued_at=attestation.issued_at, expires_at=attestation.expires_at,
        )
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, attestation.signature):
            reasons.append("ATTESTATION_SIGNATURE_INVALID")
        return not reasons, tuple(reasons)


def _verify_ed25519_attestation(
    keys: Mapping[str, object],
    key_kinds: Mapping[str, frozenset[AttestationKind]],
    attestation: Attestation,
    *,
    kind: AttestationKind,
    subject: object,
    intent: Intent,
    now: datetime,
    max_clock_skew_seconds: int,
) -> tuple[bool, tuple[str, ...]]:
    reasons: list[str] = []
    if attestation.algorithm != AttestationAlgorithm.ED25519:
        reasons.append("ATTESTATION_ALGORITHM_MISMATCH")
    if attestation.kind != kind:
        reasons.append("ATTESTATION_KIND_MISMATCH")
    key = keys.get(attestation.key_id)
    if key is None:
        reasons.append("ATTESTATION_KEY_UNKNOWN")
        return False, tuple(reasons)
    if kind not in key_kinds.get(attestation.key_id, frozenset()):
        reasons.append("ATTESTATION_KEY_KIND_NOT_ALLOWED")
    if attestation.subject_hash != canonical_hash(subject):
        reasons.append("ATTESTATION_SUBJECT_MISMATCH")
    if attestation.intent_hash != canonical_hash(intent):
        reasons.append("ATTESTATION_INTENT_MISMATCH")
    skew = timedelta(seconds=max_clock_skew_seconds)
    if attestation.issued_at > now + skew:
        reasons.append("ATTESTATION_FROM_FUTURE")
    if now > attestation.expires_at + skew:
        reasons.append("ATTESTATION_EXPIRED")
    payload = _payload(
        algorithm=attestation.algorithm, kind=attestation.kind, key_id=attestation.key_id,
        subject_hash=attestation.subject_hash, intent_hash=attestation.intent_hash,
        issued_at=attestation.issued_at, expires_at=attestation.expires_at,
    )
    pad = "=" * (-len(attestation.signature) % 4)
    try:
        raw = base64.urlsafe_b64decode(attestation.signature + pad)
        public = key.public_key() if hasattr(key, "public_key") else key
        public.verify(raw, payload)
    except Exception:
        reasons.append("ATTESTATION_SIGNATURE_INVALID")
    return not reasons, tuple(reasons)


class Ed25519AttestationSigner:
    """Role-scoped asymmetric attestation signer. Sign-only; no verify() API.

    Isolated verifiers must use `public_verifier()`, which returns
    `Ed25519AttestationVerifier` and does not expose a minting API.
    """

    algorithm = AttestationAlgorithm.ED25519

    def __init__(
        self,
        keys: Mapping[str, object],
        *,
        key_kinds: Mapping[str, Iterable[AttestationKind]],
        max_clock_skew_seconds: int = 5,
    ) -> None:
        if not keys:
            raise ValueError("at least one attestation key is required")
        self._keys = {str(k): v for k, v in keys.items()}
        self._key_kinds = _normalize_kinds(set(self._keys), key_kinds)
        if any(not has_signing_api(v) for v in self._keys.values()):
            raise ValueError("attestation signer requires signing-capable private keys")
        if any(not hasattr(v, "public_key") for v in self._keys.values()):
            raise ValueError("cannot derive a verify-only projection from signing material without a public key")
        if max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds must be non-negative")
        self.max_clock_skew_seconds = max_clock_skew_seconds

    @classmethod
    def generate(
        cls,
        key_kinds: Mapping[str, Iterable[AttestationKind]],
        *,
        max_clock_skew_seconds: int = 5,
    ) -> "Ed25519AttestationSigner":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return cls(
            {str(k): Ed25519PrivateKey.generate() for k in key_kinds},
            key_kinds=key_kinds,
            max_clock_skew_seconds=max_clock_skew_seconds,
        )

    def public_verifier(self, *, key_lifecycle: KeyLifecycle | None = None) -> "Ed25519AttestationVerifier":
        public = {key_id: key.public_key() for key_id, key in self._keys.items()}
        return Ed25519AttestationVerifier(
            public, key_kinds=self._key_kinds,
            max_clock_skew_seconds=self.max_clock_skew_seconds,
            key_lifecycle=key_lifecycle,
        )

    def _kind_allowed(self, key_id: str, kind: AttestationKind) -> bool:
        return kind in self._key_kinds.get(key_id, frozenset())

    def sign(
        self,
        key_id: str,
        kind: AttestationKind,
        subject: object,
        intent: Intent,
        *,
        issued_at: datetime,
        ttl_seconds: int = 30,
    ) -> Attestation:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        try:
            key = self._keys[key_id]
        except KeyError as exc:
            raise KeyError(f"unknown attestation key_id {key_id}") from exc
        if not self._kind_allowed(key_id, kind):
            raise PermissionError(f"attestation key {key_id} is not authorized for {kind.value}")
        expires_at = issued_at + timedelta(seconds=ttl_seconds)
        subject_hash = canonical_hash(subject)
        intent_hash = canonical_hash(intent)
        payload = _payload(
            algorithm=self.algorithm, kind=kind, key_id=key_id,
            subject_hash=subject_hash, intent_hash=intent_hash,
            issued_at=issued_at, expires_at=expires_at,
        )
        raw = key.sign(payload)
        signature = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        return Attestation(
            kind, key_id, self.algorithm, subject_hash, intent_hash,
            issued_at, expires_at, signature,
        )


# Compatibility name. This class is the signer, not a dual-role store: it has
# `sign()` and `public_verifier()`, and no `verify()`.
Ed25519TrustStore = Ed25519AttestationSigner


class Ed25519AttestationVerifier:
    """Public-key-only attestation verifier. No minting API and no private keys."""

    algorithm = AttestationAlgorithm.ED25519

    def __init__(
        self,
        keys: Mapping[str, object],
        *,
        key_kinds: Mapping[str, Iterable[AttestationKind]],
        max_clock_skew_seconds: int = 5,
        key_lifecycle: KeyLifecycle | None = None,
    ) -> None:
        if not keys:
            raise ValueError("at least one attestation key is required")
        if any(has_signing_api(v) for v in keys.values()):
            raise ValueError("attestation verifier cannot hold signing-capable private keys")
        self._keys = {str(k): v for k, v in keys.items()}
        self._key_kinds = _normalize_kinds(set(self._keys), key_kinds)
        if max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds must be non-negative")
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self.lifecycle = key_lifecycle
        if self.lifecycle is not None:
            if has_signing_api(self.lifecycle):
                raise ValueError("attestation key lifecycle must not expose a signing API")
            for key_id, key in self._keys.items():
                material = ed25519_public_material_hash(key)
                existing = self.lifecycle.get(key_id)
                if existing is None:
                    self.lifecycle.register_active(key_id, material_hash=material)
                elif existing.status is KeyStatus.REVOKED:
                    raise ValueError("revoked attestation keys cannot be reintroduced to a verifier")
                elif existing.material_hash and existing.material_hash != material:
                    raise KeyConflict("key_id collision: public material does not match registered key")
                elif not existing.material_hash:
                    self.lifecycle.register_active(key_id, material_hash=material)

    def verify(
        self,
        attestation: Attestation,
        *,
        kind: AttestationKind,
        subject: object,
        intent: Intent,
        now: datetime,
    ) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        if self.lifecycle is not None:
            ok, key_reason = self.lifecycle.accept_artifact(attestation.key_id, issued_at=attestation.issued_at)
            if not ok:
                reasons.append(key_reason or "KEY_REJECTED")
        crypto_ok, crypto_reasons = _verify_ed25519_attestation(
            self._keys, self._key_kinds, attestation,
            kind=kind, subject=subject, intent=intent, now=now,
            max_clock_skew_seconds=self.max_clock_skew_seconds,
        )
        if not crypto_ok:
            reasons.extend(crypto_reasons)
        return not reasons, tuple(dict.fromkeys(reasons))


def require_verify_only_attestation_trust(
    obj: object,
    *,
    hardened: bool = True,
    signing_api_error: str,
    hardened_error: str | None = None,
) -> None:
    """Construction guard for runtime/executor attestation trust objects.

    Rejects a callable `sign()` minting API. In hardened mode, also requires a
    FAAR-provided `Ed25519AttestationVerifier`. This is defense-in-depth, not
    proof that an arbitrary object holds no private key.
    """
    if has_signing_api(obj):
        raise ValueError(signing_api_error)
    if hardened and not isinstance(obj, Ed25519AttestationVerifier):
        raise ValueError(
            hardened_error
            or "hardened construction accepts only FAAR-provided Ed25519AttestationVerifier"
        )
