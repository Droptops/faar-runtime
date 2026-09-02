# Operations Runbook

Reference procedures for the states FAAR deliberately fails stuck in, for backups,
and for emergency controls. Every command is `python -m faar.cli ...` (or `faar`
once installed) and prints JSON. Commands that read the evidence MAC key take it
from an environment variable, never from the command line.

The reference store is SQLite. Every procedure below also applies, with the same
semantics, to a production datastore that reproduces the store contract.

## 1. Emergency stop (kill switch)

```bash
faar halt --scope global --reason "incident-42" --db faar.sqlite --anchor faar.anchor.json
faar halt --scope principal:principal:demo --reason "compromised agent" --db faar.sqlite
faar controls --db faar.sqlite
faar resume --scope global --db faar.sqlite
```

- `halt` marks the scope halted and advances the runtime epoch of every grant in
  scope in one transaction. Outstanding permits become unconsumable immediately,
  including at venues that verify permits themselves, and they stay dead after
  `resume`.
- `halt` does not wait for a hung adapter call. In-flight attempts are refused
  at permit consumption; their intents reconcile as usual and stay UNKNOWN until
  their permit window closes.
- While halted, `list-grants` shows `effective_status: HALTED`; new intents end
  `STOPPED` with `GRANT_RUNTIME_HALTED`.
- Per-grant `set-grant-status ... --status PAUSED|REVOKED` remains the
  fine-grained control; `REVOKED` is irreversible for that grant version.

## 2. Stale intent lease (`INTENT_BUSY`)

A worker that dies inside `process()`/`reconcile()` leaves its durable lease in
place. By design nothing takes the lease over automatically; every later call
returns `INTENT_BUSY` after `wait_seconds`.

```bash
faar list-leases --db faar.sqlite
# confirm the owning process is dead (owner_token = <store instance id>:<thread id>)
faar inspect --intent-id <id> --db faar.sqlite
# reconcile external settlement by hand if the intent is SUBMITTED/UNKNOWN/RECONCILING
faar clear-lease --intent-id <id> --owner-token <token> --db faar.sqlite
```

Never clear a lease whose owner may still be running: two workers inside one
intent's state machine is exactly the duplicate-execution race the lease prevents.

## 3. Intents parked in UNKNOWN with budget HELD

```bash
faar list-intents --state UNKNOWN --db faar.sqlite
faar held-usage --db faar.sqlite            # HELD reservations joined to intent state
```

Read `reason_codes` and `ambiguity_until`:

| Reason | Meaning | Action |
|---|---|---|
| `SETTLEMENT_NONE_WITHIN_PERMIT_WINDOW` | the last attempt may still be in flight | wait until `ambiguity_until` + grant clock skew; the next `process()` call with fresh attestations reconciles |
| `SETTLEMENT_NONE_NOT_AUTHORITATIVE` / `SETTLEMENT_POSITIVE_NOT_AUTHORITATIVE` | the verifier could not give an authoritative answer | fix the verifier's data source; re-run `process()` |
| `SETTLEMENT_UNKNOWN`, `RECONCILIATION_EXCEPTION` | verifier unavailable | same |
| `EXECUTION_DETERMINISTIC_FAILURE_UNVERIFIED` (with one of the above) | adapter rejected the request; block on resubmission is durable | once an authoritative NONE arrives the intent ends `FAILED_SAFE`; a new intent is required |

Budget held by an UNKNOWN intent is never released by hand through the CLI. It is
released when the verifier proves absence after the permit window, or committed
when settlement is finalized.

## 4. Intents STOPPED with budget HELD

`SETTLEMENT_CONTRADICTORY`, `SETTLEMENT_EFFECT_ID_MISMATCH`,
`SETTLEMENT_LOST_PREVIOUS_EFFECT`, `SETTLED_AMOUNT_*`, `PAYMENT_AMOUNT_MISMATCH`,
`EFFECT_ID_ALREADY_CLAIMED`, `SETTLED_EFFECT_ID_INVALID` and
`SETTLEMENT_REQUEST_BINDING_MISMATCH` are terminal and keep the reservation HELD
because an effect may exist that FAAR cannot attribute safely. These need a human:
reconcile at the venue, then decide whether to revoke the grant version. The
trailing 24 h turnover window means the held amount stops counting on its own
after a day; the velocity window ages it out after `action_window_seconds`.

## 5. Backups and restore (authority anchor)

All consumed authority lives in the store file: grant epochs, fence tokens,
consumed permits, claimed risk states. Restoring an older copy resurrects all of
it. Run the store with an authority anchor kept **outside** the backup set:

```bash
faar provision-grant --grant grant.json --db faar.sqlite --anchor /mnt/anchor/faar.anchor.json
# runtime: SQLiteIntentStore(path, evidence_key=..., authority_anchor=FileAuthorityAnchor(...))
```

Taking a backup:

```bash
faar checkpoint --db faar.sqlite      # fold the WAL into the main file first
cp faar.sqlite backups/faar-$(date -u +%Y%m%dT%H%M%SZ).sqlite
```

After a restore, any grant version whose `(runtime_epoch, fence_counter)` is
older than the anchor reports `effective_status: REGRESSED`; the runtime stops new
intents with `GRANT_RUNTIME_REGRESSED`, permit issuance fails, and venues refuse
consumption with `PERMIT_AUTHORITY_REGRESSED`. Lifecycle changes on that version
raise `AuthorityRegression`. The only supported continuation closes the version:

```bash
faar list-grants --db faar.sqlite --anchor /mnt/anchor/faar.anchor.json
faar revoke-after-restore --grant-id grant:demo --grant-version 1 --db faar.sqlite --anchor /mnt/anchor/faar.anchor.json
# provision a new grant version for continued authority
```

Intents that were in flight in the lost history must be reconciled at the venue by
hand; the restored store does not know about them.

Without an anchor a restore is undetectable (see
`test_controls.test_without_an_anchor_a_restore_is_undetectable`). An anchor file
restored together with the database detects nothing.

## 6. Evidence verification

```bash
export FAAR_EVIDENCE_KEY=...                  # the runtime's evidence MAC key
faar verify-evidence --intent-id <id> --db faar.sqlite --evidence-key-env FAAR_EVIDENCE_KEY
```

Exit code 2 means the chain, a MAC, or the signed head commitment does not verify,
or the intent does not exist. Verification without a key checks the public hash
chain only and cannot detect tail truncation.

A keyed store created before signed heads existed refuses to append to a chain
that has no head (`EvidenceIntegrityError`). After verifying the chain out of
band, commit a head once:

```bash
faar rebuild-evidence-head --intent-id <id> --db faar.sqlite --evidence-key-env FAAR_EVIDENCE_KEY
```

The command refuses if the chain itself does not verify.

## 7. Key rotation

Attestation keys and permit signers are rotated with overlapping validity windows:

1. add the new key id to the verifiers (`Ed25519AttestationVerifier(..., key_validity=...)`,
   `ExecutionPermitVerifier({old_id: ..., new_id: ...}, ...)`), with `not_before`
   set for the new key;
2. switch signers once `not_before` has passed;
3. set `revoked=True` (or `not_after`) for the old key id in the verifiers.

Validity is judged on each artifact's `issued_at`: revocation is immediate; a
window closing never invalidates an artifact issued inside it. Unknown key ids are
always rejected.

## 8. What the CLI deliberately cannot do

- release a HELD reservation;
- resurrect a REVOKED grant version;
- take over a lease without the exact owner token;
- change an intent's state directly;
- verify keyed evidence without the key.

Each of these would let an operator path bypass an invariant the runtime enforces.
