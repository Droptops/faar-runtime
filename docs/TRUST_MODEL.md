# Trust Model

FAAR is useful only if its trust boundaries are explicit.

| Component | v0.2 assumption | What compromise means |
|---|---|---|
| Strategy / LLM | Untrusted | Can propose malicious actions; should not bypass gates |
| Authority signer | Trusted for AAR posture/primitive | Can authorize work that should not execute |
| Risk signer | Trusted for risk/portfolio semantics | Can understate risk or issue unsafe versions |
| Grant authority | Trusted for capability envelope/status | Can broaden/re-enable economic authority |
| FAAR runtime | Trusted security kernel | Full bypass possible |
| Isolated permit signer | Trusted to mint bounded ExecutionPermit | Can authorize in-policy requests while its key is ACTIVE |
| Permit/attestation verifier | Trusted to accept artifacts for ACTIVE/RETIRED keys | Compromise of verify-only material cannot mint |
| Authenticated ingress | Trusted for principal binding / admin split | Bypass by talking to the store directly is a trusted-operator path |
| Datastore | Trusted for availability/transactions; MAC hardens DB-only mutation | Corruption can stop service; forged state depends on key/host access |
| Adapter | Trusted credential/execution + reconciliation boundary | Can submit a different action before runtime detects bad evidence; live design should reduce this trust |
| Venue/RPC | External and potentially ambiguous | Requires adapter-specific reconciliation/finality |
| Task-contract signer | Trusted for definition of done | Can define misleading success criteria |

## Reference attestations

The repository uses HMAC-SHA256 so tests can exercise cryptographic binding without third-party dependencies. Each reference key is explicitly scoped to one or more `AttestationKind` roles; a risk-only key cannot mint AUTHORITY even with a valid MAC. HMAC remains symmetric: any verifier holding a permitted key can also sign within that role. This is not the preferred production separation.

Production direction:

```text
policy/risk/task signer
        │ private KMS/HSM key
        ▼
 signed attestation
        │
        ▼
FAAR verifier
        │ public key / KMS verify permission only
```

Key rotation should use explicit `key_id` values bound to a public-material hash. Retired keys may verify artifacts issued before retirement. Revoked keys cannot mint, verify, or be resurrected.

## Trust is not transitive

A valid authority attestation does not prove risk is safe. A valid risk attestation does not prove the grant permits the action. A finalized venue effect does not prove the user's objective was met.

FAAR requires the relevant independent predicates to hold rather than collapsing them into one “approved” bit.


## Trust-minimization direction

The long-term architecture should separate:

```text
proposal -> policy/risk authorization -> constrained signer/executor -> independent settlement verifier
```

The component allowed to produce venue signatures should see only the sanitized `ExecutionRequest` and should hold credentials whose external permissions are no broader than necessary. The component that verifies settlement should ideally not depend solely on self-reported state from that signer/executor.
