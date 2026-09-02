# FAAR Threat Model

## Assets protected

- principal funds and positions;
- capability grants and risk budgets;
- execution/signing credentials;
- intent identity and replay state;
- settlement/effect identity;
- evidence history;
- task success criteria;
- the authority ledger itself (epochs, fence tokens, consumed permits, claimed risk states).

## Adversary assumptions

### Compromised or prompt-injected model

The model may intentionally request unauthorized targets/assets/venues, oversized orders, withdrawals or arbitrary transfers, raw calldata or signed transaction blobs, unlimited approvals, reuse of stale decisions, or rewriting success criteria after seeing the result. It may also craft payloads meant to break the runtime rather than move money: non-JSON payloads, dual amount fields, Unicode or exponent amount strings, amounts whose fixed-point form would allocate gigabytes, multi-megabyte identifiers.

FAAR treats these as untrusted proposals: typed allowlists, a strict amount grammar with canonical bounds, identifier bounds, and construction-time validation reject them before any state is written.

### Compromised coordinator/API

The coordinator may fabricate an EXECUTE decision, present stale/fake risk data, substitute grant contents under a known ID/version, race multiple intents against one portfolio snapshot, replay old attestations, present a settlement record belonging to another intent, or suppress an external effect and ask for retry.

Mitigations include signed intent-bound attestations with exact expiry and key lifecycle, bounded-by-construction grant envelopes with strict parsing, grant fingerprinting, monotonic single-consumption risk-state claims in both ledgers, authoritative reconciliation bound to the request hash (for positive and negative observations), effect continuity checks, settled-amount envelope validation, and the permit authority's independent re-verification.

Residual risk: if the trusted authority/risk signing domains themselves are compromised, FAAR cannot infer the intended policy from first principles.

### Duplicate/concurrent workers

Expected faults include queue redelivery, concurrent processing, crashes, response loss, and retries. Transactional intent/usage/risk reservations, durable per-intent leases, single-use permits and stable external identity are required. A retry is never issued while the venue can still act on the previous attempt's permit.

### Intent-identity namespace abuse

Because `intent_id` is durable economic identity, an attacker who can submit unauthenticated, attacker-chosen IDs can attempt identifier squatting as a denial-of-service primitive. The store namespaces ids by principal and rejects cross-principal reuse; ids must be at least 16 characters. Production ingress must still authenticate the actor and bind or mint IDs within that actor's namespace; ID collision handling never silently creates a second economic intent.

### Revocation race

An operator may revoke, pause or halt while a worker is near external submission.

- In-process: submission and lifecycle changes serialize on a per-grant guard shared by every store instance on the same database file; once revocation returns, no later submission begins.
- Across processes: every lifecycle change advances the grant epoch; the permit carries the epoch and consumption re-checks it inside the store transaction, so an in-flight attempt in another process is refused at the venue.
- Hung calls: `adapter_deadline_seconds` bounds how long the fence is held; the abandoned call is bounded by the permit window; `halt` does not wait on the fence at all.

Residual risk: the fence is exactly as strong as the store's transactional guarantee and as the venue's permit verification. A venue that ignores permits cannot be fenced from outside.

### Market/risk evidence faults

Threats include stale quotes, manipulated prices, source disagreement, stale positions, and concurrent intents evaluated against one snapshot. FAAR checks freshness/contradiction and consumes risk state versions once and monotonically; a proven limit breach is a DENY, missing or stale data a DEFER. The risk signer remains responsible for correct portfolio semantics and version advancement.

### Venue/RPC ambiguity

Threats include timeout before/after effect, partial fill, reorg, sequencer/exchange outage, API success before settlement, weak RPC returning not-found, effect identity changing across observations, a truthful "no effect yet" while the request is still queued at the venue, and a settlement source that is simply down.

FAAR distinguishes authoritative and non-authoritative reconciliation for both absence and positive settlement, ignores absence while an attempt's permit is live, stops on contradictory identity evidence, requires money-moving settlement amounts to remain inside the authorized envelope, and lets a quorum tolerate a raising minority source without treating it as evidence.

### Evidence-store tampering

A database-only attacker may rewrite, delete, or truncate rows. Hash chains detect ordinary mutation, interior deletion, and reordering; the evidence MAC detects rewriting by an attacker without the key; the signed head commitment detects tail truncation and whole-chain deletion; the store refuses to append to a chain whose head no longer matches, so truncation cannot be laundered by later activity; verification of an unknown intent fails closed.

Residual risk: the head commitment is only meaningful when an evidence key is configured. Rollback of the entire database to an older, validly signed snapshot is not detectable by the chain; the authority anchor detects the authority regression that accompanies it, not the lost evidence. Compromise of the runtime host plus evidence key can still forge new valid MACs. Production may require remote append-only logging or transparency anchoring.

### Backup restore

Restoring an older database resurrects revoked grants, consumed permits and spent risk states. With an authority anchor outside the backup set, affected grant versions become `REGRESSED` and can only be closed. Residual risk: an anchor restored together with the database, or an operator who reconciles without checking the venue, defeats the control.

### Malicious/buggy execution adapter

The adapter receives only a sanitized `ExecutionRequest` and a permit scoped to it; its receipts are untrusted; the runtime verifies positive effect identity, request binding and amount evidence independently. That reduces accidental authority expansion, but an adapter holding a broad external credential can still perform an out-of-policy action before reporting back. Until the venue verifies permits itself, the adapter is part of the trusted computing base. Live-money release requires key isolation and preferably venue-level permit enforcement that makes broader actions impossible.

### Key compromise

FAAR limits what a legitimate execution path asks a key to do, and compromised attestation keys or permit signers can be revoked at every verifier immediately. Key theft can still bypass FAAR if the venue credential itself has broader power. Production must enforce least privilege at the wallet/exchange/payment-provider layer where possible.

## Out of scope for v0.4

- root operator/principal compromise;
- fully malicious execution venue;
- bridge security;
- arbitrary smart-contract execution;
- leverage/liquidation correctness;
- partial-fill and cancellation linkage;
- datastore failover semantics beyond SQLite;
- regulatory/compliance guarantees;
- profitability;
- universal exactly-once semantics for external systems lacking stable identity/reconciliation.

## Security preference

When authority preservation conflicts with availability, FAAR chooses deny/defer/stop.
