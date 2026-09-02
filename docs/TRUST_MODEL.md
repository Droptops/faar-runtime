# Trust Model

FAAR is useful only if its trust boundaries are explicit.

| Component | Reference assumption | What compromise means |
|---|---|---|
| Strategy / LLM | Untrusted | Can propose malicious actions; should not bypass gates |
| Authority signer | Trusted for AAR posture/primitive | Can authorize work that should not execute |
| Risk signer | Trusted for risk/portfolio semantics | Can understate risk or issue unsafe versions |
| Grant authority | Trusted for capability envelope/status | Can broaden/re-enable economic authority |
| Operator (halt/resume, grant lifecycle, anchor recovery) | Trusted administrator | Can stop everything; cannot release held budget, resurrect a revoked version, or forge evidence without the key |
| FAAR runtime | Trusted security kernel; holds public keys only | Full bypass possible |
| Permit authority (signer) | Trusted; the only holder of the permit private key; independently re-checks everything | Can mint permits for requests the gates would allow; cannot broaden a grant |
| Datastore | Trusted for availability/transactions; MAC and signed heads harden DB-only mutation | Corruption can stop service; forged state depends on key/host access; restore is detected only with an external anchor |
| Authority anchor | Trusted append-only high-water mark outside the backup set | If restored with the DB it detects nothing; if forged upward it can only stop the grant (fail closed) |
| Adapter / submitter | Trusted execution transport; its receipts are untrusted telemetry | Can submit a different action before the runtime detects bad evidence unless the venue verifies permits |
| Venue / permit gateway | External; must verify and consume permits for the fence to hold | A venue that ignores permits leaves the adapter in the TCB |
| Settlement verifier | Trusted for economic ground truth; distinct from the submitter | Can misreport settlement; quorum reduces single-source trust |
| Task-contract signer | Trusted for definition of done | Can define misleading success criteria |

## Reference attestations and permits

Attestations and execution permits are Ed25519. Each key is scoped to one or more `AttestationKind` roles; a risk-only key cannot mint AUTHORITY even with a valid signature. Signers (`Ed25519TrustStore`, `Ed25519PermitSigner`) hold private keys; the runtime, permit authority and gateway hold `Ed25519AttestationVerifier` / `Ed25519PermitVerifier` objects that expose no `sign()`. Construction fails if a signing-capable object is passed where a verifier belongs (`has_signing_api`).

```text
policy/risk/task signer          permit authority
        │ private key                    │ private key
        ▼                                ▼
 signed attestation              signed execution permit
        │                                │
        ▼                                ▼
FAAR verifier (public key)     venue gateway verifier (public key)
```

Signatures have exactly one accepted encoding; expiry is exact; permit signatures cover signer id and algorithm.

Symmetric `HMACTrustStore` / `HMACPermitSignature` remain as test fixtures only and are refused by the runtime, the permit authority and the gateway.

## Key lifecycle

Verifiers accept a `KeyValidity` map per key id: `not_before`, `not_after`, `revoked`. Validity is judged on the artifact's `issued_at`; revocation is immediate; an artifact issued inside its key's window stays verifiable for its own lifetime, which is what makes overlap-window rotation safe. Unknown key ids and unknown permit signers are always rejected. Production custody of the private keys (KMS/HSM, process isolation) is a deployment property and a live-money gate.

## Trust is not transitive

A valid authority attestation does not prove risk is safe. A valid risk attestation does not prove the grant permits the action. A finalized venue effect does not prove the user's objective was met. A submitter receipt proves nothing.

FAAR requires the relevant independent predicates to hold rather than collapsing them into one "approved" bit.

## Trust-minimization direction

```text
proposal -> policy/risk authorization -> constrained permit signer -> permit-verifying venue -> independent settlement verifier
```

The component allowed to produce venue actions sees only the sanitized `ExecutionRequest` and a permit scoped to it. The component that verifies settlement does not depend on self-reported state from that executor. The emergency stop and the authority anchor are operator controls that act on the store, not on the model.
