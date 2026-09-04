## Invariant and scope

- Invariant or contract affected:
- Economic effect or denial path affected:
- Why this is the narrowest safe change:

## Evidence

- [ ] A regression test fails without the change.
- [ ] Security-relevant behavior is mapped in `evals/run_redteam.py`.
- [ ] `make check` passes.
- [ ] PostgreSQL contract tests pass when store behavior changes.
- [ ] Adapter settlement and replay semantics are documented when applicable.

## Public-safety check

- [ ] No credentials, private keys, seed phrases, wallet secrets, production
      endpoints, account identifiers, or funded-balance details are included.
- [ ] No missing financial limit is treated as unbounded.
- [ ] No real-money adapter or production-safety claim is introduced while a
      release gate remains open.
- [ ] Exploit details for an unpatched vulnerability were reported privately,
      not included here.
