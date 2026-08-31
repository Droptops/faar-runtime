# Grant Provisioning and Runtime Status

## Full-envelope binding

Binding only to `grant_id + version` is insufficient if a coordinator can present different grant contents. FAAR provisions:

```text
(grant_id, version) -> SHA256(canonical_grant)
```

and verifies the full fingerprint on every execution path.


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

A revoked version cannot be resurrected; create a new version instead.

## Revocation and ambiguous effects

Revocation cannot undo an effect that already happened. FAAR may continue reconciliation after revocation to discover/record a prior effect, but it does not resubmit when no effect is found.

## Fencing

The reference runtime serializes local submission and status mutation with a per-grant execution guard. Its precise local guarantee is:

> after `REVOKED` returns, no later adapter submission under that grant version can begin in that process.

This is not a distributed guarantee. Production multi-node systems require a fencing token/lease/serializable authority mechanism or venue-level capability revocation.
