"""Deterministic public-key lifecycle for FAAR v0.4.

This module is verify-side state. It never holds private keys and exposes no
`sign` API. Signing remains in isolated signer objects; this directory only
answers whether a named key may be used to accept an already-issued artifact.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

KEY_PLANES = frozenset({"PERMIT", "ATTESTATION", "INGRESS"})


class KeyStatus(StrEnum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


def ed25519_public_material_hash(public_key) -> str:
    """Stable fingerprint of an Ed25519 public key.

    `key_id` is an explicit name, not an identity proof. Binding the public
    material prevents two different keys from occupying the same identifier.
    """
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


class KeyConflict(RuntimeError):
    pass


class UnknownKey(RuntimeError):
    pass


@dataclass(frozen=True)
class KeyState:
    key_id: str
    plane: str
    status: KeyStatus
    retired_at: datetime | None = None
    revoked_at: datetime | None = None
    material_hash: str | None = None

    def accept_issued_at(self, issued_at: datetime) -> tuple[bool, str | None]:
        """Whether an artifact issued at `issued_at` may still be verified.

        ACTIVE: accept.
        RETIRED: accept only if the artifact was issued at or before retirement.
        REVOKED: reject always. Revocation is not a graceful overlap window.
        """
        if not isinstance(issued_at, datetime) or issued_at.tzinfo is None:
            return False, "KEY_ISSUED_AT_NOT_AWARE"
        if self.status is KeyStatus.REVOKED:
            return False, "KEY_REVOKED"
        if self.status is KeyStatus.RETIRED:
            if self.retired_at is None or self.retired_at.tzinfo is None:
                return False, "KEY_RETIRED_WITHOUT_TIMESTAMP"
            if issued_at > self.retired_at:
                return False, "KEY_RETIRED"
            return True, None
        if self.status is KeyStatus.ACTIVE:
            return True, None
        return False, "KEY_STATUS_UNKNOWN"


class KeyDirectoryStore(Protocol):
    def register_key(
        self, key_id: str, plane: str, status: str = "ACTIVE", *, material_hash: str | None = None
    ) -> None: ...
    def retire_key(self, key_id: str, *, at: datetime) -> None: ...
    def revoke_key(self, key_id: str, *, at: datetime) -> None: ...
    def get_key(self, key_id: str) -> KeyState | None: ...


class KeyLifecycle:
    """Durable key-status directory. No minting capability.

    Status is re-read from the store on every decision so a stale in-process
    cache cannot keep a revoked key alive.
    """

    def __init__(self, store: KeyDirectoryStore, plane: str) -> None:
        if plane not in KEY_PLANES:
            raise ValueError("key plane must be PERMIT, ATTESTATION, or INGRESS")
        self._store = store
        self.plane = plane

    def register_active(self, key_id: str, *, material_hash: str | None = None) -> None:
        if not key_id:
            raise ValueError("key_id is required")
        self._store.register_key(key_id, self.plane, "ACTIVE", material_hash=material_hash)

    def retire(self, key_id: str, *, at: datetime) -> None:
        self._store.retire_key(key_id, at=at)

    def revoke(self, key_id: str, *, at: datetime) -> None:
        self._store.revoke_key(key_id, at=at)

    def get(self, key_id: str) -> KeyState | None:
        return self._store.get_key(key_id)

    def require(self, key_id: str) -> KeyState:
        state = self.get(key_id)
        if state is None:
            raise UnknownKey(key_id)
        if state.plane != self.plane:
            raise KeyConflict(f"key {key_id} is registered on plane {state.plane}")
        return state

    def accept_artifact(self, key_id: str, *, issued_at: datetime) -> tuple[bool, str | None]:
        state = self.get(key_id)
        if state is None:
            return False, "KEY_UNKNOWN"
        if state.plane != self.plane:
            return False, "KEY_PLANE_MISMATCH"
        return state.accept_issued_at(issued_at)

    def assert_active_for_signing(self, key_id: str) -> None:
        state = self.get(key_id)
        if state is None or state.status is not KeyStatus.ACTIVE:
            raise KeyConflict("KEY_NOT_ACTIVE")
