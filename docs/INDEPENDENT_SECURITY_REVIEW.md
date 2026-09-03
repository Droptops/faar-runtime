# Gate 8 Independent Security Review

This is the handoff packet for the human review required by release gate 8. It
does not record an approval. Gate 8 remains **OPEN** until an independent human
reviews a pinned commit, publishes a report, and reviews any security-relevant
remediation against that same scope.

## Who qualifies as independent

The reviewer must be a human security engineer who did not author the reviewed
implementation or its self-red-team report and is not acting as another agent in
the development session. Automated scanners and model-assisted analysis may
support the work, but they cannot sign the conclusion. The reviewer must control
their own methodology and report unresolved findings without maintainer edits.

## Pin the review target

The review request must record the full 40-character commit SHA. The reviewer
should begin from a fresh clone, run `git status --porcelain`, and include both
`git rev-parse HEAD` and the reviewed tree hash in the report. Later code changes
require a delta review; a report for an earlier SHA does not approve a new head.

No production credential, private key, wallet secret, or funded account is
needed or permitted for this review.

## Required scope

1. Authority and input boundaries: `models.py`, `parsing.py`, `canonical.py`,
   `gates.py`, `attestation.py`, and definition-of-done evaluation.
2. State and money invariants: `runtime.py`, `store.py`, `postgres_store.py`,
   migrations, leases, aggregate usage, per-attempt velocity, evidence integrity,
   and the external authority anchor.
3. Permit lifecycle: issuance, request binding, expiry, single consumption,
   venue binding, halt/revoke epochs, restore regression, and ambiguity windows.
4. Settlement: independent-source requirements, effect identity, amount
   envelopes, quorum behavior, partial fills, cancellation, and finality.
5. Execution boundaries: the mock and paper gateways plus the fixed-origin
   Hyperliquid **testnet candidate**. Their declarations must not be treated as
   proof of real venue behavior.
6. Operator and recovery paths: authenticated-control assumptions, halt/resume,
   stale-lease handling, backups, failover requirements, and held-budget cases.
7. Tests and claims: verify that every security stop has a mutation-killing
   regression, every red-team class maps to a real test, and documentation does
   not overstate what the evidence establishes.

The starting threat model is [`THREAT_MODEL.md`](THREAT_MODEL.md); normative
runtime properties are in [`INVARIANTS.md`](INVARIANTS.md). The datastore and
adapter obligations are in [`STORE_CONTRACT.md`](STORE_CONTRACT.md) and
[`ADAPTER_CONTRACT.md`](ADAPTER_CONTRACT.md). The self-red-team report
[`RED_TEAM_REPORT.md`](RED_TEAM_REPORT.md) is review input, not review evidence.

## High-priority attack questions

- Can any path create an economic effect without a valid, current, request- and
  venue-bound permit being consumed first?
- Can replay, timeout, crash, failover, retry, duplicate workers, or changing
  settlement observations produce a second effect or release budget too early?
- Can parallel intents or retries exceed turnover, exposure, position, or the
  configured venue-attempt velocity ceiling?
- Can a caller, signer, adapter, verifier, database row, or restored backup
  broaden authority, change identity, hide an effect, or turn ambiguity into
  success/absence?
- Can a hung external call delay pause/revoke, exhaust workers without a bound,
  or leave authority consumable after the stop returns?
- Do PostgreSQL isolation, advisory locking, schema migration, acknowledged
  durability, and reconnect behavior actually preserve the store contract?
- Which claims depend on venue, KMS/HSM, ingress, signer isolation, independent
  settlement data, anchor placement, or funded-balance controls not present here?

## Reproduce the repository evidence

Use Python 3.11, 3.12, and 3.13 for the reference gate:

```bash
python -m pip install -e ".[dev]"
make check
```

Use a disposable PostgreSQL 16 database for the backend-specific pass:

```bash
python -m pip install -e ".[dev,postgres]"
export FAAR_TEST_POSTGRES_DSN='postgresql://...'
export FAAR_TEST_POSTGRES_ALLOW_SCHEMA_DROP=1
PYTHONPATH=test:. python -m unittest discover -s test -p 'test_postgres_store.py' -v
PYTHONPATH=. python evals/run_redteam.py
PYTHONPATH=. python evals/run_crash_injection.py
```

The schema-drop flag is intentionally explicit. Never point these commands at a
database containing data that must survive.

Passing the commands is necessary, not sufficient. Review transaction boundaries
and deliberately remove or invert important checks to confirm the mapped tests
fail. At minimum mutate permit consumption, ambiguity-window absence, effect-id
continuity, settled-amount bounds, revoke epochs, evidence-head checks, aggregate
turnover, and per-attempt velocity.

## Required report

The reviewer supplies a report containing:

- reviewer name, affiliation (or independent status), date, and independence
  statement;
- reviewed commit SHA and tree hash;
- methodology, tools, test environment, and commands actually run;
- scope covered and any exclusions;
- findings with unique IDs, severity, reproduction, affected invariant, impact,
  and recommended remediation;
- disposition of every finding: open, accepted residual, fixed and retested, or
  disputed with rationale;
- an explicit conclusion on **core Gate 8 for that SHA**, separate from every
  deployment and venue row;
- a statement that production safety and live venue semantics were not inferred
  merely from green repository tests.

Critical or high findings remain release blockers. Any accepted lower-severity
residual must have an owner and written rationale in `GO_LIVE_CHECKLIST.md`.

## Maintainer acceptance checklist

- [ ] Full review target SHA and tree hash recorded.
- [ ] Reviewer independence statement present.
- [ ] Core, PostgreSQL store, and selected adapter/verifier scope explicit.
- [ ] All findings tracked; critical/high findings closed and delta-reviewed.
- [ ] Final report stored or linked immutably with its SHA-256 digest.
- [ ] Gate 6.4 managed-failover evidence remains separate.
- [ ] Every DEPLOYMENT row has venue/environment evidence before funding.
- [ ] Only then change Gate 8 from OPEN to reviewed for the pinned SHA.

