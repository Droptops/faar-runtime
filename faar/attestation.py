from __future__ import annotations

import base64
import hashlib
import hmac
from datetime import datetime, timedelta
from collections.abc import Iterable
from typing import Mapping, Protocol

from .canonical import canonical_hash, canonical_json
from .models import Attestation, AttestationAlgorithm, AttestationKind, Intent


class AttestationVerifier(Protocol):
    can_sign: bool

    def verify(
        self,
        attestation: Attestation,
        *,
        kind: AttestationKind,
        subject: object,
        intent: Intent,
        now: datetime,
    ) -> tuple[bool, tuple[str, ...]]: ...


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
    attestations. FAAR v0.3 runtime construction rejects signing-capable trust stores
    by default.
    """

    can_sign = True
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


class Ed25519TrustStore:
    """Role-scoped asymmetric attestation signer or verify-only trust store."""

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
        capabilities = {hasattr(v, "sign") for v in self._keys.values()}
        if len(capabilities) != 1:
            raise ValueError("attestation trust store cannot mix private and public keys")
        self.can_sign = capabilities.pop()
        if max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds must be non-negative")
        self.max_clock_skew_seconds = max_clock_skew_seconds

    @classmethod
    def generate(
        cls,
        key_kinds: Mapping[str, Iterable[AttestationKind]],
        *,
        max_clock_skew_seconds: int = 5,
    ) -> "Ed25519TrustStore":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return cls(
            {str(k): Ed25519PrivateKey.generate() for k in key_kinds},
            key_kinds=key_kinds,
            max_clock_skew_seconds=max_clock_skew_seconds,
        )

    def public_verifier(self) -> "Ed25519TrustStore":
        public = {
            key_id: (key.public_key() if hasattr(key, "public_key") else key)
            for key_id, key in self._keys.items()
        }
        return Ed25519TrustStore(
            public, key_kinds=self._key_kinds,
            max_clock_skew_seconds=self.max_clock_skew_seconds,
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
        if not self.can_sign:
            raise PermissionError("verify-only attestation trust store cannot sign")
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
        pad = "=" * (-len(attestation.signature) % 4)
        try:
            raw = base64.urlsafe_b64decode(attestation.signature + pad)
            public = key.public_key() if hasattr(key, "public_key") else key
            public.verify(raw, payload)
        except Exception:
            reasons.append("ATTESTATION_SIGNATURE_INVALID")
        return not reasons, tuple(reasons)
