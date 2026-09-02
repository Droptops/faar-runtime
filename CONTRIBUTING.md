# Contributing

FAAR is security-sensitive financial infrastructure. Small, reviewable changes are preferred.

## Required workflow

1. State the invariant (`docs/INVARIANTS.md`) or behavior being changed.
2. Add or update a deterministic regression test first. If the change guards against an attack class, map it in `evals/run_redteam.py` so the red-team matrix cannot drift from real coverage.
3. Keep model reasoning outside trusted execution logic.
4. Run the full release gate: `make check` (unit tests, adversarial, mapped red-team matrix, fuzz, demo, bounded model). `python -m pip install -e ".[dev]"` adds schema validation to the unit suite.
5. Document any new adapter/recovery/operator semantics (`docs/ADAPTER_CONTRACT.md`, `docs/RECOVERY.md`, `docs/OPERATIONS.md`).

## Security-relevant changes

Changes to grant provisioning, parsing, canonicalization, state transitions, usage reservation, permit issuance or consumption, adapter identity, retry behavior, the ambiguity window, settlement mapping, evidence, emergency controls, the authority anchor, or key boundaries require explicit security review.

Do not weaken a fail-closed behavior merely to improve availability. Do not add a test that passes by lowering an assertion.

## Live adapters

Do not add a live-money adapter without satisfying `docs/ADAPTER_CONTRACT.md`, closing the rows in `docs/GO_LIVE_CHECKLIST.md`, and obtaining the independent review required by `docs/V0_2_RELEASE_GATES.md`.
