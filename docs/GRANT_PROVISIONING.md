# Grant Provisioning and Runtime Status

## Full-envelope binding

Binding only to `grant_id + version` is insufficient if a coordinator can present different grant contents. FAAR provisions:

```text
(grant_id, version) -> SHA256(canonical_grant)
```

and verifies the full fingerprint on every execution path. The parser rejects unknown top-level and `limits` keys, so a misspelled optional limit is a provisioning error rather than an unenforced control hiding inside a valid fingerprint.


## Bounded-by-construction grant rules

FAAR does not use `None` to mean unlimited monetary authority. A grant that permits a money-moving primitive (`PAY`, `SWAP`, `BUY`, `SELL`, `PLACE_ORDER`) must define:

```text
allowed_assets != empty
max_order_usd > 0
max_daily_turnover_usd > 0
max_actions_per_window > 0
action_window_seconds > 0
```

`PAY` and `SWAP` also require a non-empty `allowed_targets` set because the request names a direct recipient/router target. All grants, including cancel-only grants, require an action-velocity bound.

This does not prove the *chosen* limits are prudent. It prevents accidental construction of an unscoped/infinite reference capability.

## Provisioning authority

The autonomous model may request broader authority but must never approve/provision it itself.

Production implementations should use an independent authority domain such as an operator-signed document, KMS/HSM signer, multisig/admin service, on-chain capability registry, or signed policy release pipeline.

## Runtime status

Immutable grant contents are distinct from emergency operational state:

```text
ACTIVE <-> PAUSED
ACTIVE/PAUSED -> REVOKED
REVOKED -X-> ACTIVE
```

A revoked version cannot be resurrected; create a new version instead. Trailing
turnover and velocity windows are summed over every version of a grant id owned
by the same principal, so a new version never restarts a budget; its own limits
apply to the total. A grant that allows SWAP, BUY, SELL or PLACE_ORDER must set
`limits.max_slippage_bps`: it is the cap the executor-side bound in every trade
request is checked against (I-39), and a grant without it is refused at
construction and by the schema.

## Revocation and ambiguous effects

Revocation cannot undo an effect that already happened. FAAR may continue reconciliation after revocation to discover/record a prior effect, but it does not resubmit when no effect is found.

## Fencing

Two mechanisms:

1. **In-process guard.** Submission and status mutation serialize on a per-grant guard shared by every store instance opened on the same database file in one process: after `REVOKED` returns, no later adapter submission under that grant version can begin in that process.
2. **Durable epoch.** Every lifecycle change (pause, resume, revoke, halt) advances the grant's `runtime_epoch`. Each execution permit carries the epoch it was issued under, and permit consumption re-checks it in the same store transaction. An in-flight attempt in another process is therefore refused at the venue (`PERMIT_GRANT_EPOCH_STALE`) even though the in-process guard could not stop it.

The durable fence is as strong as the store's transactional guarantee and as the venue's permit verification; a venue that ignores permits cannot be fenced from outside.

## Emergency halt

`halt(scope, reason)` with scope `global` or `principal:<id>` marks the scope halted and advances every affected grant epoch in one transaction; the effective grant status becomes `HALTED`, new intents stop with `GRANT_RUNTIME_HALTED`, and permits issued before the halt stay dead after `resume`. A halt does not wait for in-flight adapter calls. See `OPERATIONS.md` §1.

## Restore safety

With an `AuthorityAnchor` configured outside the backup set, a grant version whose `(runtime_epoch, fence_counter)` is older than the anchor is `REGRESSED`: nothing is issued or consumed under it and its lifecycle can only be closed with `revoke_after_restore`. See `OPERATIONS.md` §5.
