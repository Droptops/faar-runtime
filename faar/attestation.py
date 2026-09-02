from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from datetime import datetime, timedelta
from collections.abc import Iterable
from typing import Mapping, Protocol

from .canonical import canonical_hash, canonical_json
from .models import Attestation, AttestationAlgorithm, AttestationKind, Intent, KeyValidity


ED25519_SIGNATURE_BYTES = 64
ED25519_SIGNATURE_CHARS = 86  # unpadded base64url of 64 bytes
_B64URL_TO_STD = str.maketrans("-_", "+/")


def has_signing_api(obj: object) -> bool:
    """True if `obj` exposes a callable `sign` minting path.

    Runtime and executor trust objects must fail this check. A `can_sign` flag is
    not sufficient: a compromised verifier must not have an API that can mint.
    """
    return callable(getattr(obj, "sign", None))


def encode_ed25519_signature(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_ed25519_signature(signature: object) -> bytes | None:
    """Strictly decode the one canonical encoding of an Ed25519 signature.

    `urlsafe_b64decode` alone discards foreign characters, tolerates padding and
    ignores trailing bits, so one signature would have many accepted encodings that
    all hash differently. A verifier must accept exactly the encoding the signer
    produced; anything else is treated as an invalid signature.
    """
    if not isinstance(signature, str) or len(signature) != ED25519_SIGNATURE_CHARS:
        return None
    try:
        raw = base64.b64decode(signature.translate(_B64URL_TO_STD) + "==", validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) != ED25519_SIGNATURE_BYTES or encode_ed25519_signature(raw) != signature:
        return None
    return raw


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
    signing API.
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
        # Skew tolerance applies to issuance drift only. Extending the signed
        # expiry by the skew would lengthen the authority the signer granted.
        skew = timedelta(seconds=self.max_clock_skew_seconds)
        if attestation.issued_at > now + skew:
            reasons.append("ATTESTATION_FROM_FUTURE")
        if now > attestation.expires_at:
            reasons.append("ATTESTATION_EXPIRED")
        try:
            payload = _payload(
                algorithm=attestation.algorithm, kind=attestation.kind, key_id=attestation.key_id,
                subject_hash=attestation.subject_hash, intent_hash=attestation.intent_hash,
                issued_at=attestation.issued_at, expires_at=attestation.expires_at,
            )
        except Exception:
            reasons.append("ATTESTATION_MALFORMED")
            return False, tuple(reasons)
        expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
        if not isinstance(attestation.signature, str) or not hmac.compare_digest(expected, attestation.signature):
            reasons.append("ATTESTATION_SIGNATURE_INVALID")
        return not reasons, tuple(reasons)


def _normalize_validity(
    key_ids: set[str], key_validity: Mapping[str, KeyValidity] | None
) -> dict[str, KeyValidity]:
    if not key_validity:
        return {}
    unknown = sorted(set(key_validity) - key_ids)
    if unknown:
        raise ValueError(f"key_validity references unknown keys: {unknown}")
    out: dict[str, KeyValidity] = {}
    for key_id, validity in key_validity.items():
        if not isinstance(validity, KeyValidity):
            raise ValueError(f"key_validity for {key_id} must be a KeyValidity")
        out[str(key_id)] = validity
    return out


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
    key_validity: Mapping[str, KeyValidity] | None = None,
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
    validity = (key_validity or {}).get(attestation.key_id)
    if validity is not None:
        rejection = validity.rejection(attestation.issued_at)
        if rejection:
            reasons.append("ATTESTATION_" + rejection)
    if attestation.subject_hash != canonical_hash(subject):
        reasons.append("ATTESTATION_SUBJECT_MISMATCH")
    if attestation.intent_hash != canonical_hash(intent):
        reasons.append("ATTESTATION_INTENT_MISMATCH")
    # Skew tolerance applies to issuance drift only; the signed expiry is exact.
    skew = timedelta(seconds=max_clock_skew_seconds)
    if attestation.issued_at > now + skew:
        reasons.append("ATTESTATION_FROM_FUTURE")
    if now > attestation.expires_at:
        reasons.append("ATTESTATION_EXPIRED")
    try:
        payload = _payload(
            algorithm=attestation.algorithm, kind=attestation.kind, key_id=attestation.key_id,
            subject_hash=attestation.subject_hash, intent_hash=attestation.intent_hash,
            issued_at=attestation.issued_at, expires_at=attestation.expires_at,
        )
    except Exception:
        reasons.append("ATTESTATION_MALFORMED")
        return False, tuple(reasons)
    raw = decode_ed25519_signature(attestation.signature)
    if raw is None:
        reasons.append("ATTESTATION_SIGNATURE_INVALID")
        return False, tuple(reasons)
    try:
        public = key.public_key() if hasattr(key, "public_key") else key
        public.verify(raw, payload)
    except Exception:
        reasons.append("ATTESTATION_SIGNATURE_INVALID")
    return not reasons, tuple(reasons)


class Ed25519TrustStore:
    """Role-scoped asymmetric attestation signer.

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
        key_validity: Mapping[str, KeyValidity] | None = None,
    ) -> None:
        if not keys:
            raise ValueError("at least one attestation key is required")
        self._keys = {str(k): v for k, v in keys.items()}
        self._key_kinds = _normalize_kinds(set(self._keys), key_kinds)
        self._key_validity = _normalize_validity(set(self._keys), key_validity)
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
        key_validity: Mapping[str, KeyValidity] | None = None,
    ) -> "Ed25519TrustStore":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        return cls(
            {str(k): Ed25519PrivateKey.generate() for k in key_kinds},
            key_kinds=key_kinds,
            max_clock_skew_seconds=max_clock_skew_seconds,
            key_validity=key_validity,
        )

    def public_verifier(self, *, key_validity: Mapping[str, KeyValidity] | None = None) -> "Ed25519AttestationVerifier":
        """Verify-only projection. `key_validity` overrides the store's lifecycle map,
        so a verifier can revoke or window a key without touching signing material."""
        public = {}
        for key_id, key in self._keys.items():
            if callable(getattr(key, "sign", None)) and not hasattr(key, "public_key"):
                raise ValueError("cannot derive a verify-only attestation store from signing material without a public key")
            public[key_id] = key.public_key() if hasattr(key, "public_key") else key
        return Ed25519AttestationVerifier(
            public, key_kinds=self._key_kinds,
            max_clock_skew_seconds=self.max_clock_skew_seconds,
            key_validity=self._key_validity if key_validity is None else key_validity,
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
        signature = encode_ed25519_signature(raw)
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
        return _verify_ed25519_attestation(
            self._keys, self._key_kinds, attestation,
            kind=kind, subject=subject, intent=intent, now=now,
            max_clock_skew_seconds=self.max_clock_skew_seconds,
            key_validity=self._key_validity,
        )


class Ed25519AttestationVerifier:
    """Public-key-only attestation verifier. No minting API and no private keys.

    `key_validity` maps key ids to `KeyValidity` windows; keys absent from the map
    are valid indefinitely (until removed). Rotation is done by adding the new key,
    signing with it once its `not_before` has passed, and later revoking the old one.
    """

    algorithm = AttestationAlgorithm.ED25519

    def __init__(
        self,
        keys: Mapping[str, object],
        *,
        key_kinds: Mapping[str, Iterable[AttestationKind]],
        max_clock_skew_seconds: int = 5,
        key_validity: Mapping[str, KeyValidity] | None = None,
    ) -> None:
        if not keys:
            raise ValueError("at least one attestation key is required")
        if any(has_signing_api(v) for v in keys.values()):
            raise ValueError("attestation verifier cannot hold signing-capable private keys")
        self._keys = {str(k): v for k, v in keys.items()}
        self._key_kinds = _normalize_kinds(set(self._keys), key_kinds)
        self._key_validity = _normalize_validity(set(self._keys), key_validity)
        if max_clock_skew_seconds < 0:
            raise ValueError("max_clock_skew_seconds must be non-negative")
        self.max_clock_skew_seconds = max_clock_skew_seconds

    def with_key_validity(self, key_validity: Mapping[str, KeyValidity]) -> "Ed25519AttestationVerifier":
        """A copy with an updated lifecycle map (e.g. after revoking a key)."""
        return Ed25519AttestationVerifier(
            self._keys, key_kinds=self._key_kinds,
            max_clock_skew_seconds=self.max_clock_skew_seconds, key_validity=key_validity,
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
        return _verify_ed25519_attestation(
            self._keys, self._key_kinds, attestation,
            kind=kind, subject=subject, intent=intent, now=now,
            max_clock_skew_seconds=self.max_clock_skew_seconds,
            key_validity=self._key_validity,
        )
