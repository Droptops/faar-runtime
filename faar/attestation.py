from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta
from collections.abc import Iterable
from typing import Mapping, Protocol

from .canonical import canonical_hash, canonical_json
from .models import Attestation, AttestationKind, Intent


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


class HMACTrustStore:
    """Small reference trust domain for signed upstream decisions.

    HMAC is intentionally used here because it is in the Python standard library and
    keeps the reference kernel dependency-free. A production deployment can replace
    this with KMS/HSM-backed asymmetric signatures while preserving the verifier
    contract.
    """

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
        if set(key_kinds) != set(self._keys):
            missing = sorted(set(self._keys) - set(key_kinds))
            extra = sorted(set(key_kinds) - set(self._keys))
            raise ValueError(f"key_kinds must exactly cover keys; missing={missing}, extra={extra}")
        self._key_kinds: dict[str, frozenset[AttestationKind]] = {}
        for key_id, kinds in key_kinds.items():
            normalized = frozenset(AttestationKind(kind) for kind in kinds)
            if not normalized:
                raise ValueError(f"attestation key {key_id} must be scoped to at least one kind")
            self._key_kinds[str(key_id)] = normalized
        if max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds must be non-negative")
        self.max_clock_skew_seconds = max_clock_skew_seconds

    def _kind_allowed(self, key_id: str, kind: AttestationKind) -> bool:
        return kind in self._key_kinds.get(key_id, frozenset())

    @staticmethod
    def _payload(
        *,
        kind: AttestationKind,
        key_id: str,
        subject_hash: str,
        intent_hash: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> str:
        return canonical_json({
            "kind": kind.value,
            "key_id": key_id,
            "subject_hash": subject_hash,
            "intent_hash": intent_hash,
            "issued_at": issued_at,
            "expires_at": expires_at,
        })

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
        payload = self._payload(
            kind=kind,
            key_id=key_id,
            subject_hash=subject_hash,
            intent_hash=intent_hash,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        mac = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return Attestation(kind, key_id, subject_hash, intent_hash, issued_at, expires_at, mac)

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

        payload = self._payload(
            kind=attestation.kind,
            key_id=attestation.key_id,
            subject_hash=attestation.subject_hash,
            intent_hash=attestation.intent_hash,
            issued_at=attestation.issued_at,
            expires_at=attestation.expires_at,
        )
        expected = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, attestation.mac):
            reasons.append("ATTESTATION_MAC_INVALID")
        return not reasons, tuple(reasons)
