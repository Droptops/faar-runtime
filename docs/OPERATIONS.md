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
  at permit consumption (`PERMIT_HALTED`). Their intents reconcile as usual with
  resubmission blocked: an effect the verifier finds still finalizes; otherwise
  they stay UNKNOWN until their permit window closes and then end `STOPPED`
  (`GRANT_RUNTIME_HALTED`) with the reservation released once absence is
  authoritative. A durable deterministic-failure block survives the halt and
  ends the intent `FAILED_SAFE` instead.
- `halt` and `resume` are authority changes: on a database bound to an anchor
  they require `--anchor` (see §5).
- Scopes are `global` or `principal:<principal_id>` (ids are themselves of the
  form `principal:<name>`, so the scope is doubled); a principal with no
  provisioned grant is refused (`UnknownPrincipal`) unless
  `--allow-unprovisioned-principal` is given, so a typo cannot report a halt or
  a cap that protects nothing.
- A first funded deployment also sets a fleet-wide ceiling that no grant can
  exceed. `EXPOSURE_CAP_EXCEEDED` defers the intent at reservation time:

```bash
faar set-exposure-cap --scope global --max-usd 500 --db faar.sqlite --anchor faar.anchor.json
faar set-exposure-cap --scope principal:principal:demo --max-usd 100 --db faar.sqlite --anchor faar.anchor.json
faar exposure-caps --db faar.sqlite
faar set-exposure-cap --scope global --clear --db faar.sqlite --anchor faar.anchor.json
```
- While halted, `list-grants` shows `effective_status: HALTED`; new intents end
  `STOPPED` with `GRANT_RUNTIME_HALTED`.
- Per-grant `set-grant-status ... --status PAUSED|REVOKED` remains the
  fine-grained control; `REVOKED` is irreversible for that grant version.

## 2. Stale intent lease (`INTENT_BUSY`)

A worker that dies inside `process()`/`reconcile()` leaves its durable lease in
place. By design nothing takes the lease over automatically; every later call
returns `INTENT_BUSY` after `wait_seconds`.

```bash
faar list-leases --db faar.sqlite          # shows owner_token, host, pid, acquired_at
# confirm the owning process is dead: on the lease's host, check the pid
faar inspect --intent-id <id> --db faar.sqlite
# reconcile external settlement by hand if the intent is SUBMITTED/UNKNOWN/RECONCILING
faar clear-lease --intent-id <id> --owner-token <token> --db faar.sqlite
```

`clear-lease` refuses (`LeaseOwnerAlive`, exit 2) when the owner is a live process
on the host you run it from; `--force` overrides that only when you have confirmed
the worker is gone by other means. A worker that hit a busy datastore keeps the
right to re-acquire its own lease, so a lease row with a live pid is not
necessarily stuck: wait for the worker's next call first.

Never clear a lease whose owner may still be running: two workers inside one
intent's state machine is exactly the duplicate-execution race the lease prevents.

This procedure is exercised by `make crash` (`evals/run_crash_injection.py`),
which kills a worker before every store call and recovers with exactly these
steps.

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
| `EXECUTION_DETERMINISTIC_FAILURE` (with one of the above; `_UNVERIFIED` only before the first reconciliation) | adapter rejected the request; block on resubmission is durable | once an authoritative NONE arrives after the permit window the intent ends `FAILED_SAFE`; a new intent is required |
| `EXECUTION_PERMIT_REJECTED`, `PERMIT_PREVIOUS_ATTEMPT_LIVE` | the store refused a second live permit for this intent | wait for the recorded window; budget stays held |
| `EVIDENCE_INTEGRITY_FAILURE` | the evidence chain refused an append (legacy chain without a head, or a tail that no longer matches its signed head) | state was not advanced; see §6 and §8 |
| `SETTLEMENT_PARTIAL_FILL_OPEN` (state `CONFIRMED`) | the order rests partially filled at the venue | reconcile again later; cancel at the venue to finish; the remainder is never a second order |
| `ADAPTER_ORPHAN_LIMIT_REACHED` (state `STOPPED`, budget released) | this worker has too many abandoned adapter calls | let them drain or restart the worker; investigate the venue latency |

Budget held by an UNKNOWN intent is never released by hand through the CLI. It is
released when the verifier proves absence after the permit window, or committed
when settlement is finalized.

## 4. Intents STOPPED with budget HELD

`SETTLEMENT_CONTRADICTORY`, `SETTLEMENT_EFFECT_ID_MISMATCH`,
`SETTLEMENT_LOST_PREVIOUS_EFFECT`, `SETTLEMENT_CANCEL_CONTRADICTS_RECORDED_EFFECT`,
`SETTLEMENT_NONE_AFTER_PERMIT_CONSUMED` (the venue admitted the request but has
no record of it), `SETTLEMENT_RECORD_MALFORMED`,
`SETTLED_AMOUNT_*`, `PAYMENT_AMOUNT_MISMATCH`, `PAYMENT_PARTIAL_NOT_ALLOWED`,
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

The first open with an anchor binds the database to it durably and writes a
shared identity into both; opening later with a different anchor, or with a
fresh file at the same path (an unmounted volume, a new host), fails with
`AnchorMismatch` instead of silently un-regressing a restored database. From
then on an instance opened **without** an anchor (a worker missing the option, an operator
command without `--anchor`) cannot issue, consume, or change authority:
`list-grants` shows `effective_status: ANCHOR_REQUIRED`, new intents stop with
`GRANT_RUNTIME_ANCHOR_REQUIRED`, venues refuse `PERMIT_ANCHOR_REQUIRED`, and
`halt`/`resume`/`set-grant-status`/`provision-grant`/`revoke-after-restore` exit 2
with `AuthorityAnchorRequired`. Read-only commands work without it. An anchor
file that cannot be read or parsed fails closed the same way
(`ANCHOR_UNAVAILABLE`, `PERMIT_ANCHOR_UNAVAILABLE`).

The per-grant fence counter advances on every permit issuance **and** every
consumption, so a snapshot taken between the two is detected too. The mark is
raised inside the datastore transaction, before commit: provisioning,
re-activation, permit issuance and consumption roll back when the anchor cannot
be written, so no authority ever exists without its mark. Pause, revoke, `halt`
and `revoke-after-restore` commit regardless (stopping is always the safe
direction) and then exit 2 with `AnchorUnavailable ... committed; anchor not
updated`; treat that as an alert, not a failed stop. The file anchor holds an
inter-process lock on `<anchor>.lock` around each update, waits at most
`ANCHOR_LOCK_TIMEOUT_SECONDS` (5 s) for it and otherwise reports
`ANCHOR_UNAVAILABLE`; every worker and the CLI may share one file.

Taking a backup:

```bash
faar checkpoint --db faar.sqlite      # fold the WAL into the main file first; exit 2 = not folded, do not copy
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
hand; the restored store does not know about them. Exposure caps are anchored
too: after a restore every monetary reservation is refused with
`EXPOSURE_CAPS_REGRESSED` until an operator re-applies the caps with
`set-exposure-cap` (re-check every scope; the snapshot may carry a looser cap).

Without an anchor a restore is undetectable (see
`test_controls.test_without_an_anchor_a_restore_is_undetectable`). An anchor file
restored together with the database detects nothing.

## 6. Evidence verification

```bash
export FAAR_EVIDENCE_KEY=...                  # the runtime's evidence MAC key
faar verify-evidence --intent-id <id> --db faar.sqlite --evidence-key-env FAAR_EVIDENCE_KEY
```

Exit code 2 means the chain, a MAC, or the signed head commitment does not verify,
or the intent does not exist. The `status` field says which: `chain_invalid`
(hash or MAC), `head_mismatch` (tail truncated or head rewritten), `head_deleted`
(a chain that started with a signed head has lost it: tampering, and the rebuild
refuses it), `head_missing`
(a chain written before signed heads existed; not tampering), `chain_empty`
(an intent with no events at all), `unknown_intent`. Verification without a key
checks the public hash chain only and cannot detect tail truncation.

A keyed store refuses to append to a chain that has no head. The runtime then
returns `EVIDENCE_INTEGRITY_FAILURE` without advancing the intent. After
verifying the chains out of band, commit heads once:

```bash
faar rebuild-evidence-head --all --db faar.sqlite --evidence-key-env FAAR_EVIDENCE_KEY
faar rebuild-evidence-head --intent-id <id> --db faar.sqlite --evidence-key-env FAAR_EVIDENCE_KEY
```

The command refuses any chain that does not verify (`refused:` in the per-intent
outcome) and skips chains with zero events unless `--adopt-empty` is given, in
which case the adoption is recorded as the chain's first keyed event. It is never
run by the runtime.

## 7. Key rotation

Attestation keys and permit signers are rotated with overlapping validity windows:

1. add the new key id to the verifiers (`Ed25519AttestationVerifier(..., key_validity=...)`,
   `ExecutionPermitVerifier({old_id: ..., new_id: ...}, ...)`), with `not_before`
   set for the new key;
2. switch signers once `not_before` has passed;
3. set `revoked=True` (or `not_after`) for the old key id in the verifiers.

Validity is judged on each artifact's `issued_at`: revocation is immediate; a
window closing never invalidates an artifact issued inside it. Unknown key ids are
always rejected. Because `issued_at` is signer-controlled, a retired key could
back-date a long-lived artifact; the verifiers therefore bound every artifact's
own lifetime (`ATTESTATION_TTL_EXCEEDED` above 24 h by default,
`PERMIT_TTL_EXCEEDED` above 60 s), which caps the exposure of a retired key to
`not_after + lifetime`. **Revocation is the hard control; `not_after` is a
rotation convenience.**

## 8. Upgrading a 0.3.x database

1. Stop every 0.3.x worker and wait at least the permit TTL plus the grant clock
   skew (default 5 s + 2 s). Mixed-version fleets are unsupported: the permit
   signature payload changed, and a 0.3.x worker keeps writing rows without a
   venue namespace.
2. Take a backup (`checkpoint`, then copy).
3. Open the database once with 0.4 (any command). The migration runs in one
   transaction and backfills what the new invariants rely on: each intent's
   venue from its canonical payload (per-venue effect identity), each legacy
   reservation's window timestamp (velocity), and a 60 s ambiguity window for
   in-flight legacy attempts. A row that cannot be brought into the model makes
   the open fail with `MigrationError`; fix the row, do not skip it.
4. If the runtime uses an evidence key, run
   `rebuild-evidence-head --all --evidence-key-env ...` and re-run
   `verify-evidence` for the intents you care about.
5. If you run with an authority anchor, open the store with it before any
   worker starts; that first open binds the database.

## 9. What the CLI deliberately cannot do

- release a HELD reservation;
- resurrect a REVOKED grant version;
- take over a lease without the exact owner token;
- change an intent's state directly;
- verify keyed evidence without the key;
- commit a head over a chain that does not verify;
- change authority on an anchored database without the anchor.

Each of these would let an operator path bypass an invariant the runtime enforces.
