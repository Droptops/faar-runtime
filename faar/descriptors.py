"""Serialized public-key verifier descriptors.

v0.5 execution-plane construction takes these records, not arbitrary Python
verifier objects. Private-key encodings are rejected. FAAR builds the
verify-only objects internally.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Iterable, Mapping

from .keys import KeyStatus, ed25519_public_material_hash
from .models import AttestationKind


class VerifierScheme(StrEnum):
    ED25519 = "ed25519"


class VerifierPurpose(StrEnum):
    PERMIT = "permit"
    ATTESTATION = "attestation"


def _b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def encode_ed25519_public(public_key) -> str:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    if len(raw) != 32:
        raise ValueError("DESCRIPTOR_PUBLIC_KEY_LENGTH")
    return _b64encode(raw)


def decode_ed25519_public(text: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(text, str) or not text:
        raise ValueError("DESCRIPTOR_PUBLIC_KEY_INVALID")
    upper = text.upper()
    if "PRIVATE" in upper or "BEGIN" in upper or "-----" in text:
        raise ValueError("DESCRIPTOR_PRIVATE_MATERIAL")
    try:
        raw = _b64decode(text)
    except Exception as exc:
        raise ValueError("DESCRIPTOR_PUBLIC_KEY_INVALID") from exc
    if len(raw) != 32:
        raise ValueError("DESCRIPTOR_PUBLIC_KEY_LENGTH")
    return Ed25519PublicKey.from_public_bytes(raw)


@dataclass(frozen=True)
class VerifierDescriptor:
    scheme: VerifierScheme
    key_id: str
    public_key: str
    purpose: VerifierPurpose
    status: KeyStatus
    material_hash: str
    key_kinds: tuple[str, ...] = ()
    retired_at: datetime | None = None

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "scheme", VerifierScheme(self.scheme))
        except ValueError as exc:
            raise ValueError("DESCRIPTOR_SCHEME_UNSUPPORTED") from exc
        try:
            object.__setattr__(self, "purpose", VerifierPurpose(self.purpose))
        except ValueError as exc:
            raise ValueError("DESCRIPTOR_PURPOSE_MISMATCH") from exc
        try:
            object.__setattr__(self, "status", KeyStatus(self.status))
        except ValueError as exc:
            raise ValueError("DESCRIPTOR_STATUS_INVALID") from exc
        object.__setattr__(self, "key_kinds", tuple(str(k) for k in self.key_kinds))
        if not self.key_id:
            raise ValueError("DESCRIPTOR_KEY_ID_REQUIRED")
        if self.scheme is not VerifierScheme.ED25519:
            raise ValueError("DESCRIPTOR_SCHEME_UNSUPPORTED")
        public = decode_ed25519_public(self.public_key)
        expected = ed25519_public_material_hash(public)
        if self.material_hash != expected:
            raise ValueError("DESCRIPTOR_MATERIAL_MISMATCH")
        if self.purpose is VerifierPurpose.ATTESTATION and not self.key_kinds:
            raise ValueError("DESCRIPTOR_ATTESTATION_KINDS_REQUIRED")
        if self.status is KeyStatus.RETIRED and self.retired_at is None:
            raise ValueError("DESCRIPTOR_RETIRED_WITHOUT_TIMESTAMP")
        if self.status is KeyStatus.REVOKED:
            raise ValueError("DESCRIPTOR_REVOKED")

    def public_key_object(self):
        return decode_ed25519_public(self.public_key)

    def to_dict(self) -> dict:
        return {
            "scheme": self.scheme.value,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "purpose": self.purpose.value,
            "status": self.status.value,
            "material_hash": self.material_hash,
            "key_kinds": list(self.key_kinds),
            "retired_at": None if self.retired_at is None else self.retired_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "VerifierDescriptor":
        if not isinstance(data, Mapping):
            raise ValueError("DESCRIPTOR_NOT_AN_OBJECT")
        banned = {"private_key", "secret", "seed", "signing_key"}
        extra_private = banned.intersection(data)
        if extra_private:
            raise ValueError("DESCRIPTOR_PRIVATE_MATERIAL")
        retired = data.get("retired_at")
        retired_at = None
        if retired is not None:
            if not isinstance(retired, str):
                raise ValueError("DESCRIPTOR_RETIRED_AT_INVALID")
            retired_at = datetime.fromisoformat(retired)
            if retired_at.tzinfo is None or retired_at.utcoffset() is None:
                raise ValueError("DESCRIPTOR_RETIRED_AT_NAIVE")
        kinds = data.get("key_kinds") or ()
        if isinstance(kinds, str):
            raise ValueError("DESCRIPTOR_ATTESTATION_KINDS_REQUIRED")
        return cls(
            scheme=str(data.get("scheme", "")),
            key_id=str(data.get("key_id", "")),
            public_key=str(data.get("public_key", "")),
            purpose=str(data.get("purpose", "")),
            status=str(data.get("status", "")),
            material_hash=str(data.get("material_hash", "")),
            key_kinds=tuple(kinds),
            retired_at=retired_at,
        )


def descriptor_from_public_key(
    *,
    key_id: str,
    public_key,
    purpose: VerifierPurpose,
    status: KeyStatus = KeyStatus.ACTIVE,
    key_kinds: Iterable[str] = (),
    retired_at: datetime | None = None,
) -> VerifierDescriptor:
    encoded = encode_ed25519_public(public_key)
    return VerifierDescriptor(
        scheme=VerifierScheme.ED25519,
        key_id=key_id,
        public_key=encoded,
        purpose=purpose,
        status=status,
        material_hash=ed25519_public_material_hash(public_key),
        key_kinds=tuple(key_kinds),
        retired_at=retired_at,
    )


def permit_verifier_from_descriptor(descriptor: VerifierDescriptor):
    """Construct a FAAR permit verifier from public material only."""
    from .permits import Ed25519PermitVerifier

    if descriptor.purpose is not VerifierPurpose.PERMIT:
        raise ValueError("DESCRIPTOR_PURPOSE_MISMATCH")
    return Ed25519PermitVerifier(descriptor.key_id, descriptor.public_key_object())


def attestation_verifier_from_descriptors(descriptors: Iterable[VerifierDescriptor]):
    """Construct a FAAR attestation verifier from public material only."""
    from .attestation import Ed25519AttestationVerifier

    keys: dict[str, object] = {}
    kinds: dict[str, set[AttestationKind]] = {}
    for descriptor in descriptors:
        if descriptor.purpose is not VerifierPurpose.ATTESTATION:
            raise ValueError("DESCRIPTOR_PURPOSE_MISMATCH")
        keys[descriptor.key_id] = descriptor.public_key_object()
        kinds[descriptor.key_id] = {AttestationKind(k) for k in descriptor.key_kinds}
    if not keys:
        raise ValueError("DESCRIPTOR_ATTESTATION_EMPTY")
    return Ed25519AttestationVerifier(keys, key_kinds=kinds)


def load_descriptor_bundle(payload: Iterable[Mapping[str, object]]) -> tuple[VerifierDescriptor, ...]:
    return tuple(VerifierDescriptor.from_dict(item) for item in payload)
