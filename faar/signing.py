"""Private signing-key providers. Authority-process only.

The v0.5 executor must not import this module. KMS/HSM is an interface; no
cloud adapter ships in this tree.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol

from .descriptors import VerifierDescriptor, VerifierPurpose, descriptor_from_public_key
from .keys import KeyStatus
from .models import PermitAlgorithm


class SigningKeyProvider(Protocol):
    def sign(self, key_id: str, payload: bytes) -> bytes: ...
    def public_descriptor(self, key_id: str) -> VerifierDescriptor: ...


class UnknownSigningKey(KeyError):
    pass


class InMemoryEd25519Provider:
    """Test/dev provider. Holds Ed25519 private keys in process memory."""

    def __init__(self, keys: dict[str, tuple[object, VerifierPurpose, tuple[str, ...]]]) -> None:
        if not keys:
            raise ValueError("signing provider requires at least one key")
        self._keys = dict(keys)

    @classmethod
    def generate(
        cls,
        *,
        permit_key_id: str = "permit-v05",
        attestation_key_ids: dict[str, tuple[str, ...]] | None = None,
    ) -> "InMemoryEd25519Provider":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        attestation_key_ids = attestation_key_ids or {
            "authority-v05": ("AUTHORITY",),
            "risk-v05": ("RISK",),
        }
        keys: dict[str, tuple[object, VerifierPurpose, tuple[str, ...]]] = {
            permit_key_id: (Ed25519PrivateKey.generate(), VerifierPurpose.PERMIT, ()),
        }
        for key_id, kinds in attestation_key_ids.items():
            keys[key_id] = (Ed25519PrivateKey.generate(), VerifierPurpose.ATTESTATION, tuple(kinds))
        return cls(keys)

    def sign(self, key_id: str, payload: bytes) -> bytes:
        try:
            private, _, _ = self._keys[key_id]
        except KeyError as exc:
            raise UnknownSigningKey(key_id) from exc
        return private.sign(payload)

    def public_descriptor(self, key_id: str) -> VerifierDescriptor:
        try:
            private, purpose, kinds = self._keys[key_id]
        except KeyError as exc:
            raise UnknownSigningKey(key_id) from exc
        return descriptor_from_public_key(
            key_id=key_id,
            public_key=private.public_key(),
            purpose=purpose,
            status=KeyStatus.ACTIVE,
            key_kinds=kinds,
        )

    def list_key_ids(self) -> list[str]:
        return list(self._keys)

    def permit_key_id(self) -> str:
        for key_id, (_, purpose, _) in self._keys.items():
            if purpose is VerifierPurpose.PERMIT:
                return key_id
        raise UnknownSigningKey("permit")

    def attestation_key_ids(self) -> dict[str, tuple[str, ...]]:
        return {
            key_id: kinds
            for key_id, (_, purpose, kinds) in self._keys.items()
            if purpose is VerifierPurpose.ATTESTATION
        }

    def export_descriptors(self) -> list[dict]:
        return [self.public_descriptor(key_id).to_dict() for key_id in self._keys]


class FileBackedEd25519Provider(InMemoryEd25519Provider):
    """Local reference provider. Private files stay in `key_dir`; never in the executor."""

    @classmethod
    def create(cls, key_dir: str | Path, *, permit_key_id: str = "permit-v05") -> "FileBackedEd25519Provider":
        from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

        key_dir = Path(key_dir)
        key_dir.mkdir(parents=True, exist_ok=True)
        memory = InMemoryEd25519Provider.generate(permit_key_id=permit_key_id)
        index = []
        for key_id, (private, purpose, kinds) in memory._keys.items():
            raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            secret_path = key_dir / f"{key_id}.ed25519"
            secret_path.write_bytes(raw)
            secret_path.chmod(0o600)
            index.append({
                "key_id": key_id,
                "purpose": purpose.value,
                "key_kinds": list(kinds),
                "file": secret_path.name,
            })
        (key_dir / "index.json").write_text(json.dumps(index, indent=2, sort_keys=True))
        (key_dir / "descriptors.json").write_text(json.dumps(memory.export_descriptors(), indent=2, sort_keys=True))
        return cls(memory._keys)

    @classmethod
    def load(cls, key_dir: str | Path) -> "FileBackedEd25519Provider":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key_dir = Path(key_dir)
        index = json.loads((key_dir / "index.json").read_text())
        keys: dict[str, tuple[object, VerifierPurpose, tuple[str, ...]]] = {}
        for item in index:
            raw = (key_dir / item["file"]).read_bytes()
            if len(raw) != 32:
                raise ValueError("FILE_KEY_LENGTH")
            private = Ed25519PrivateKey.from_private_bytes(raw)
            keys[item["key_id"]] = (
                private,
                VerifierPurpose(item["purpose"]),
                tuple(item.get("key_kinds") or ()),
            )
        return cls(keys)


class KMSHSMProvider:
    """Declared KMS/HSM interface. No AWS/GCP/HSM adapter is included."""

    def sign(self, key_id: str, payload: bytes) -> bytes:
        raise NotImplementedError("KMS_HSM_ADAPTER_NOT_IMPLEMENTED")

    def public_descriptor(self, key_id: str) -> VerifierDescriptor:
        raise NotImplementedError("KMS_HSM_ADAPTER_NOT_IMPLEMENTED")


class ProviderBackedPermitSigner:
    """PermitSigner adapter over SigningKeyProvider. Authority-process only."""

    algorithm = PermitAlgorithm.ED25519

    def __init__(self, provider: SigningKeyProvider, key_id: str) -> None:
        descriptor = provider.public_descriptor(key_id)
        if descriptor.purpose is not VerifierPurpose.PERMIT:
            raise ValueError("PROVIDER_KEY_PURPOSE_MISMATCH")
        self.signer_id = key_id
        self._provider = provider
        self._public_key = descriptor.public_key_object()

    def sign(self, payload: bytes) -> str:
        import base64

        raw = self._provider.sign(self.signer_id, payload)
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def public_verifier(self):
        from .permits import Ed25519PermitVerifier

        return Ed25519PermitVerifier(self.signer_id, self._public_key)


class ProviderBackedAttestationKey:
    def __init__(self, provider: SigningKeyProvider, key_id: str) -> None:
        self._provider = provider
        self._key_id = key_id

    def sign(self, payload: bytes) -> bytes:
        return self._provider.sign(self._key_id, payload)

    def public_key(self):
        return self._provider.public_descriptor(self._key_id).public_key_object()
