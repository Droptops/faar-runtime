# FAAR Threat Model

## Assets protected

- principal funds and positions;
- capability grants and risk budgets;
- execution/signing credentials;
- intent identity and replay state;
- settlement/effect identity;
- evidence history;
- task success criteria.

## Adversary assumptions

### Compromised or prompt-injected model

The model may intentionally request:

- unauthorized targets/assets/venues;
- oversized orders;
- withdrawals or arbitrary transfers;
- raw calldata or signed transaction blobs;
- unlimited approvals;
- reuse of stale decisions;
- rewriting success criteria after seeing the result.

FAAR treats these as untrusted proposals.

### Compromised coordinator/API

The coordinator may:

- fabricate an EXECUTE decision;
- present stale/fake risk data;
- substitute grant contents under a known ID/version;
- race multiple intents against one portfolio snapshot;
- replay old attestations;
- suppress an external effect and ask for retry.

Mitigations include signed intent-bound attestations, bounded-by-construction grant envelopes, grant fingerprinting, risk-state claims, authoritative reconciliation (for positive and negative observations), effect continuity checks, and settled-amount envelope validation.

Residual risk: if the trusted authority/risk signing domains themselves are compromised, FAAR cannot infer the intended policy from first principles.

### Duplicate/concurrent workers

Expected faults include queue redelivery, concurrent processing, crashes, response loss, and retries. Transactional intent/usage/risk reservations and stable external identity are required.

### Intent-identity namespace abuse

Because `intent_id` is durable economic identity, an attacker who can submit unauthenticated, attacker-chosen IDs can attempt identifier squatting as a denial-of-service primitive. Production ingress must authenticate the actor and bind or mint IDs within that actor's namespace; ID collision handling must not silently create a second economic intent.

### Revocation race

An operator may revoke while a worker is near external submission. The reference implementation serializes local submission and revocation under a per-grant execution guard.

Residual risk: an in-process Python lock does not solve a distributed race. Production needs datastore/lease/fencing-token semantics or lower-level venue capabilities that make revoked authority unenforceable by old workers. Adapter calls must also be time-bounded: the reference fence is held across submission, so a hung venue call can delay local revocation completion.

### Market/risk evidence faults

Threats include stale quotes, manipulated prices, source disagreement, stale positions, and concurrent intents evaluated against one snapshot.

FAAR checks freshness/contradiction and consumes risk state versions once. The risk signer remains responsible for correct portfolio semantics and version advancement.

### Venue/RPC ambiguity

Threats include:

- timeout before/after effect;
- partial fill;
- reorg;
- sequencer/exchange outage;
- API success before settlement;
- weak RPC returning not-found;
- effect identity changing across observations.

FAAR distinguishes authoritative and non-authoritative reconciliation for both absence and positive settlement, stops on contradictory identity evidence, and requires money-moving settlement amounts to remain inside the authorized envelope.

### Evidence-store tampering

A database-only attacker may rewrite rows. Hash chains detect ordinary mutation and an optional HMAC detects rewriting by an attacker without the evidence key.

Residual risk: compromise of the runtime host plus evidence key can forge new valid MACs. Production evidence may require remote append-only logging, signed checkpoints, or external transparency anchoring.

### Malicious/buggy execution adapter

The adapter receives only a sanitized `ExecutionRequest`, and the runtime verifies positive effect identity/amount evidence. That reduces accidental authority expansion, but an adapter holding a broad external credential can still perform an out-of-policy action before reporting back. In v0.2 the adapter is therefore part of the trusted computing base. Live-money release requires key isolation and preferably lower-level account/contract controls that make broader actions impossible.

### Key compromise

FAAR limits what a legitimate execution path asks a key to do, but key theft can bypass FAAR if the venue credential itself has broader power. Production must enforce least privilege at the wallet/exchange/payment-provider layer where possible.

## Out of scope for v0.2

- root operator/principal compromise;
- fully malicious execution venue;
- bridge security;
- arbitrary smart-contract execution;
- leverage/liquidation correctness;
- regulatory/compliance guarantees;
- profitability;
- universal exactly-once semantics for external systems lacking stable identity/reconciliation.

## Security preference

When authority preservation conflicts with availability, FAAR chooses deny/defer/stop.
