from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Protocol

from .attestation import AttestationVerifier
from .canonical import canonical_hash, canonical_json
from .gates import evaluate_authority, evaluate_capability, evaluate_risk
from .models import (
    Attestation,
    AttestationKind,
    AuthorityDecision,
    CapabilityGrant,
    ExecutionPermit,
    ExecutionRequest,
    Intent,
    MONETARY_PRIMITIVES,
    PermitAlgorithm,
    RiskSnapshot,
    SignedExecutionPermit,
    Verdict,
)


class PermitIssuanceError(RuntimeError):
    def __init__(self, reasons: tuple[str, ...]):
        super().__init__(",".join(reasons))
        self.reasons = reasons


class PermitSignatureBackend(Protocol):
    signer_id: str
    algorithm: PermitAlgorithm
    can_sign: bool

    def sign(self, payload: bytes) -> str: ...
    def verify(self, payload: bytes, signature: str) -> bool: ...


@dataclass(frozen=True)
class HMACPermitSignature:
    """Symmetric compatibility backend. Not suitable for an isolated verifier.

    Any holder that can verify also has enough key material to mint permits. v0.3
    therefore rejects this backend at execution gateways unless an explicit test-only
    override is supplied.
    """

    signer_id: str
    key: bytes
    algorithm: PermitAlgorithm = PermitAlgorithm.HMAC_SHA256
    can_sign: bool = True

    def __post_init__(self) -> None:
        if not self.signer_id or len(self.key) < 16:
            raise ValueError("permit HMAC signer requires signer_id and >=16-byte key")

    def sign(self, payload: bytes) -> str:
        return hmac.new(self.key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class Ed25519PermitSignature:
    """Optional asymmetric reference backend.

    The private-key form is appropriate for the isolated permit signer. Venues and
    settlement infrastructure should receive only `public_verifier()`, so compromise
    of a transport component cannot mint new permits.
    """

    algorithm = PermitAlgorithm.ED25519

    def __init__(self, signer_id: str, private_key=None, public_key=None) -> None:
        if not signer_id:
            raise ValueError("signer_id is required")
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        except ImportError as exc:  # pragma: no cover - optional dependency guard
            raise RuntimeError("cryptography is required for Ed25519 permit signatures") from exc
        if private_key is None and public_key is None:
            private_key = Ed25519PrivateKey.generate()
        self.signer_id = signer_id
        self._private_key = private_key
        self._public_key = public_key or private_key.public_key()
        self.can_sign = private_key is not None

    def sign(self, payload: bytes) -> str:
        if self._private_key is None:
            raise PermissionError("public verifier cannot sign permits")
        raw = self._private_key.sign(payload)
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def verify(self, payload: bytes, signature: str) -> bool:
        pad = "=" * (-len(signature) % 4)
        try:
            raw = base64.urlsafe_b64decode(signature + pad)
            self._public_key.verify(raw, payload)
            return True
        except Exception:
            return False

    def public_verifier(self) -> "Ed25519PermitSignature":
        return Ed25519PermitSignature(self.signer_id, public_key=self._public_key)


class PermitControlStore(Protocol):
    def verify_grant(self, grant: CapabilityGrant, grant_hash: str) -> None: ...
    def verify_usage_held(self, intent: Intent, grant: CapabilityGrant) -> bool: ...
    def claim_permit_risk_state(
        self, intent: Intent, grant: CapabilityGrant, risk: RiskSnapshot
    ) -> tuple[bool, tuple[str, ...]]: ...
    def next_execution_fence(self, grant: CapabilityGrant) -> tuple[int, int]: ...
    def get_grant_control(self, principal_id: str, grant_id: str, version: int) -> tuple[str, int, int]: ...
    def record_execution_permit(
        self,
        permit_id: str,
        intent: Intent,
        grant: CapabilityGrant,
        grant_epoch: int,
        fence_token: int,
        permit_hash: str,
    ) -> None: ...
    def consume_execution_permit(
        self, *, permit_id: str, principal_id: str, grant_id: str, grant_version: int,
        grant_epoch: int, fence_token: int, permit_hash: str,
    ) -> tuple[bool, tuple[str, ...]]: ...


def _amount(request: ExecutionRequest) -> Decimal | None:
    raw = request.payload.get("amount_usd", request.payload.get("notional_usd"))
    if raw is None:
        return None
    try:
        value = Decimal(str(raw))
    except (InvalidOperation, TypeError, ValueError):
        return None
    return value if value.is_finite() else None


class ConstrainedPermitAuthority:
    """Independent policy signer for one economic request.

    The caller cannot ask this component to sign an arbitrary adapter payload. It
    independently checks:
      * request == the sanitized projection of the signed intent;
      * immutable grant fingerprint + ACTIVE runtime epoch;
      * signed authority and risk decisions;
      * deterministic authority/capability/risk gates;
      * an atomic HELD usage reservation exists;
      * a bounded, short-lived amount envelope.

    In production this logic belongs in a separately isolated signer/KMS/HSM service
    or a capability contract, not in the same compromise domain as the LLM worker.
    """

    def __init__(
        self,
        store: PermitControlStore,
        trust: AttestationVerifier,
        signature: PermitSignatureBackend,
        *,
        max_permit_ttl_seconds: int = 5,
    ) -> None:
        if max_permit_ttl_seconds <= 0:
            raise ValueError("max_permit_ttl_seconds must be positive")
        if not getattr(signature, "can_sign", True):
            raise ValueError("permit authority requires a signing-capable private backend")
        if getattr(trust, "can_sign", False):
            raise ValueError("permit authority must receive a verify-only upstream attestation trust store")
        self.store = store
        self.trust = trust
        self.signature = signature
        self.max_permit_ttl_seconds = max_permit_ttl_seconds

    def issue(
        self,
        request: ExecutionRequest,
        *,
        intent: Intent,
        authority: AuthorityDecision,
        grant: CapabilityGrant,
        risk: RiskSnapshot,
        authority_attestation: Attestation,
        risk_attestation: Attestation,
        now: datetime,
    ) -> SignedExecutionPermit:
        reasons: list[str] = []
        expected_request = ExecutionRequest.from_intent(intent)
        if canonical_hash(request) != canonical_hash(expected_request):
            reasons.append("PERMIT_REQUEST_NOT_CANONICAL_INTENT_PROJECTION")

        if request.principal_id != intent.principal_id or grant.principal_id != intent.principal_id:
            reasons.append("PERMIT_PRINCIPAL_MISMATCH")

        try:
            self.store.verify_grant(grant, canonical_hash(grant))
        except Exception:
            reasons.append("PERMIT_GRANT_NOT_TRUSTED")

        ok, attestation_reasons = self.trust.verify(
            authority_attestation,
            kind=AttestationKind.AUTHORITY,
            subject=authority,
            intent=intent,
            now=now,
        )
        if not ok:
            reasons.extend("PERMIT_AUTHORITY_" + r for r in attestation_reasons)
        ok, attestation_reasons = self.trust.verify(
            risk_attestation,
            kind=AttestationKind.RISK,
            subject=risk,
            intent=intent,
            now=now,
        )
        if not ok:
            reasons.extend("PERMIT_RISK_" + r for r in attestation_reasons)

        for decision in (
            evaluate_authority(authority),
            evaluate_capability(intent, grant, now),
            evaluate_risk(intent, grant, risk, now),
        ):
            if decision.verdict != Verdict.ALLOW:
                reasons.append(f"PERMIT_{decision.layer.upper()}_{decision.verdict.value}")
                reasons.extend("PERMIT_" + r for r in decision.reason_codes)

        if not self.store.verify_usage_held(intent, grant):
            reasons.append("PERMIT_USAGE_RESERVATION_NOT_HELD")

        if now > intent.expires_at:
            reasons.append("PERMIT_INTENT_EXPIRED")
        if grant.valid_until is not None and now > grant.valid_until:
            reasons.append("PERMIT_GRANT_EXPIRED")

        amount = _amount(request)
        if intent.primitive in MONETARY_PRIMITIVES:
            if amount is None or amount <= 0:
                reasons.append("PERMIT_AMOUNT_INVALID")
            if grant.limits.max_order_usd is None or (amount is not None and amount > grant.limits.max_order_usd):
                reasons.append("PERMIT_AMOUNT_EXCEEDS_GRANT")

        if reasons:
            raise PermitIssuanceError(tuple(dict.fromkeys(reasons)))

        try:
            claimed, claim_reasons = self.store.claim_permit_risk_state(intent, grant, risk)
        except Exception as exc:
            raise PermitIssuanceError(("PERMIT_RISK_CLAIM_UNAVAILABLE",)) from exc
        if not claimed:
            raise PermitIssuanceError(tuple(claim_reasons) or ("PERMIT_RISK_CLAIM_REJECTED",))

        try:
            epoch, fence = self.store.next_execution_fence(grant)
        except Exception:
            raise PermitIssuanceError(("PERMIT_GRANT_FENCE_UNAVAILABLE",))

        # Re-read after allocating the fence. A lifecycle update in another process
        # changes epoch and makes this issuance fail rather than minting a stale permit.
        status, current_epoch, _ = self.store.get_grant_control(grant.principal_id, grant.grant_id, grant.version)
        if status != "ACTIVE" or current_epoch != epoch:
            raise PermitIssuanceError(("PERMIT_GRANT_EPOCH_CHANGED",))

        expires_at = min(
            intent.expires_at,
            grant.valid_until if grant.valid_until is not None else intent.expires_at,
            now + timedelta(seconds=self.max_permit_ttl_seconds),
        )
        if expires_at <= now:
            raise PermitIssuanceError(("PERMIT_TTL_EMPTY",))

        request_hash = canonical_hash(request)
        grant_hash = canonical_hash(grant)
        permit_seed = canonical_json({
            "principal_id": intent.principal_id,
            "intent_id": intent.intent_id,
            "grant_hash": grant_hash,
            "request_hash": request_hash,
            "grant_epoch": epoch,
            "fence_token": fence,
        })
        permit_id = "permit_" + hashlib.sha256(permit_seed.encode("utf-8")).hexdigest()[:32]
        permit = ExecutionPermit(
            permit_id=permit_id,
            principal_id=intent.principal_id,
            intent_id=intent.intent_id,
            grant_id=grant.grant_id,
            grant_version=grant.version,
            grant_hash=grant_hash,
            request_hash=request_hash,
            authority_attestation_hash=canonical_hash(authority_attestation),
            risk_attestation_hash=canonical_hash(risk_attestation),
            grant_epoch=epoch,
            fence_token=fence,
            max_amount_usd=amount,
            issued_at=now,
            expires_at=expires_at,
        )
        payload = canonical_json(permit).encode("utf-8")
        signed = SignedExecutionPermit(
            permit=permit,
            signer_id=self.signature.signer_id,
            algorithm=self.signature.algorithm,
            signature=self.signature.sign(payload),
        )
        self.store.record_execution_permit(
            permit_id,
            intent,
            grant,
            epoch,
            fence,
            canonical_hash(signed),
        )
        return signed


class ExecutionPermitVerifier:
    """Public-side verifier used by a constrained venue/capability gateway."""

    def __init__(
        self,
        signature: PermitSignatureBackend,
        control_store: PermitControlStore,
        *,
        max_clock_skew_seconds: int = 2,
        allow_signing_backend_for_tests: bool = False,
    ) -> None:
        if getattr(signature, "can_sign", True) and not allow_signing_backend_for_tests:
            raise ValueError(
                "execution permit verifier must be verify-only; private/symmetric signing material "
                "must not enter the execution transport trust domain"
            )
        self.signature = signature
        self.control_store = control_store
        self.max_clock_skew_seconds = max_clock_skew_seconds

    def verify(
        self,
        signed: SignedExecutionPermit,
        request: ExecutionRequest,
        *,
        now: datetime,
    ) -> tuple[bool, tuple[str, ...]]:
        reasons: list[str] = []
        permit = signed.permit
        if signed.signer_id != self.signature.signer_id:
            reasons.append("PERMIT_SIGNER_UNKNOWN")
        if signed.algorithm != self.signature.algorithm:
            reasons.append("PERMIT_ALGORITHM_MISMATCH")
        payload = canonical_json(permit).encode("utf-8")
        if not self.signature.verify(payload, signed.signature):
            reasons.append("PERMIT_SIGNATURE_INVALID")
        if permit.request_hash != canonical_hash(request):
            reasons.append("PERMIT_REQUEST_HASH_MISMATCH")
        if permit.principal_id != request.principal_id or permit.intent_id != request.intent_id:
            reasons.append("PERMIT_REQUEST_IDENTITY_MISMATCH")
        skew = timedelta(seconds=self.max_clock_skew_seconds)
        if permit.issued_at > now + skew:
            reasons.append("PERMIT_FROM_FUTURE")
        if now > permit.expires_at:
            reasons.append("PERMIT_EXPIRED")

        try:
            status, epoch, _ = self.control_store.get_grant_control(
                permit.principal_id, permit.grant_id, permit.grant_version
            )
            if status != "ACTIVE":
                reasons.append("PERMIT_GRANT_NOT_ACTIVE")
            if epoch != permit.grant_epoch:
                reasons.append("PERMIT_GRANT_EPOCH_STALE")
        except Exception:
            reasons.append("PERMIT_GRANT_CONTROL_UNAVAILABLE")

        actual = _amount(request)
        if permit.max_amount_usd is not None:
            if actual is None or actual <= 0:
                reasons.append("PERMIT_REQUEST_AMOUNT_INVALID")
            elif actual > permit.max_amount_usd:
                reasons.append("PERMIT_REQUEST_AMOUNT_EXCEEDED")
        return not reasons, tuple(reasons)

    def consume(
        self, signed: SignedExecutionPermit, request: ExecutionRequest, *, now: datetime
    ) -> tuple[bool, tuple[str, ...]]:
        """Cryptographically verify, then atomically consume the execution permit."""
        ok, reasons = self.verify(signed, request, now=now)
        if not ok:
            return False, reasons
        permit = signed.permit
        try:
            return self.control_store.consume_execution_permit(
                permit_id=permit.permit_id,
                principal_id=permit.principal_id,
                grant_id=permit.grant_id,
                grant_version=permit.grant_version,
                grant_epoch=permit.grant_epoch,
                fence_token=permit.fence_token,
                permit_hash=canonical_hash(signed),
            )
        except Exception:
            return False, ("PERMIT_CONSUMPTION_UNAVAILABLE",)
