# Contributing

FAAR is security-sensitive financial infrastructure. Small, reviewable changes are preferred.

## Required workflow

1. State the invariant or behavior being changed.
2. Add or update a deterministic regression test first.
3. Keep model reasoning outside trusted execution logic.
4. Run `make test` and `make adversarial`.
5. Document any new adapter/recovery semantics.

## Security-relevant changes

Changes to grant provisioning, canonicalization, state transitions, usage reservation, adapter identity, retry behavior, settlement mapping, or key boundaries require explicit security review.

Do not weaken a fail-closed behavior merely to improve availability.

## Live adapters

Do not add a live-money adapter without satisfying `docs/ADAPTER_CONTRACT.md` and the live-adapter release gate in the README.
