# v0.2 Live-Money Release Gates

A green reference suite is necessary but not sufficient for real funds.

## Blockers before first live adapter

### 1. Production attestation

- asymmetric or KMS/HSM-backed signing;
- verifier cannot mint policy decisions merely because it can verify them;
- key rotation/revocation documented;
- authority, risk, grant, and task signers separated where practical.

### 2. Production datastore/fencing

- serializable/transactional semantics tested across multiple processes;
- distributed grant-revocation/submission fence;
- unique intent/effect/risk-state constraints preserved;
- backup/restore does not resurrect consumed authority.

### 3. Risk engine contract

- monotonic state versions reflect held/committed reservations;
- position, P&L, turnover, and market evidence are authoritative enough for the chosen venue;
- concurrency fault test demonstrates no aggregate oversubscription.

### 4. Venue adapter review

- bounded request deadlines/timeouts so a hung adapter cannot indefinitely block revocation;
- stable external intent identity;
- authoritative reconciliation by that identity;
- documented partial-fill/cancel semantics;
- effect ID definition;
- authoritative positive and negative reconciliation;
- independent verification of settled amount/assets/target where the venue exposes sufficient evidence;
- retry behavior and maximum ambiguity window;
- finality/settlement definition.

### 5. Key isolation / unplug test

- model cannot access signing secrets;
- credential scope is narrower than root wallet/account authority where the venue permits;
- withdrawal/transfer authority disabled for a trading-only adapter when possible;
- adapter/signer receives only sanitized execution requests and cannot consume model metadata as authority;
- removing/bypassing FAAR does not leave the coordinator with an alternate direct execution credential path. See `UNPLUG_TEST.md`.

### 6. Failure injection

Test at minimum:

- timeout before/after venue acceptance;
- process/network partition;
- duplicate workers;
- datastore failover;
- stale/malicious RPC/provider;
- revocation during submission;
- partial fill + cancellation race;
- venue returns changing identifiers/states.

### 7. Authenticated ingress / intent identity / administration

- economic-intent creation is authenticated to a principal;
- grant provisioning, pause, resume, and revoke endpoints are separately authenticated/authorized;
- production security time does not trust caller-provided timestamps;
- client-chosen IDs are principal-bound or IDs are server-minted;
- an unauthenticated caller cannot squat another principal's durable `intent_id`;
- collision/replay handling never creates a replacement economic intent implicitly.

### 8. Independent review

- external security review of core + adapter;
- explicit unresolved findings;
- no production-safety claim based solely on the repository's own tests.

### 9. Bounded first exposure

Even after the above, the first deployment should use an explicitly capped funded balance and kill switch. Passing the release gates does not justify unbounded authority.
