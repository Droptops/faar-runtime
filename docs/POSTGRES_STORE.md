# PostgreSQL 16 Store

Status: **port candidate; not production or failover evidence**.

`faar.postgres_store.PostgresIntentStore` reproduces the reference store's
transaction boundaries on PostgreSQL 16. It is intentionally conservative:
every operation that is `BEGIN IMMEDIATE` in `SQLiteIntentStore` takes one
transaction-scoped advisory writer lock. This preserves a single cross-host
linearization order for intent CAS, aggregate reservations, grant lifecycle,
permit issuance/consumption and evidence appends.

## Construction

Install the optional driver extra and obtain the DSN from the deployment's
secret channel. Do not place a password-bearing DSN in source, a command-line
argument, logs or test fixtures.

```python
import os

from faar.postgres_store import PostgresIntentStore

store = PostgresIntentStore(
    os.environ["FAAR_DATABASE_DSN"],
    schema="faar",
    evidence_key=os.environ["FAAR_EVIDENCE_KEY"].encode("utf-8"),
    authority_anchor=anchor,
)
```

The database role needs connection and schema/data privileges appropriate to
the deployment. Initial installation and migration additionally require
`CREATE SCHEMA`, `CREATE TABLE`, `CREATE INDEX` and `ALTER TABLE`. A deployment
may perform migrations with a separate role before starting a runtime role
that cannot change schema.

Each store schema binds `store_settings.backend=postgresql16` and a
PostgreSQL-specific schema revision. A conflicting backend marker is a migration
failure, not something the runtime overwrites.

## Concurrency and revocation

- Mutating multi-statement methods are one PostgreSQL transaction and take a
  transaction-scoped advisory writer lock derived from database plus schema.
- Evidence verification uses a repeatable-read, read-only transaction.
- Autocommit single-statement changes remain atomic and run with
  `synchronous_commit=on`.
- Monotonic counters and epoch-second values are `BIGINT`; the port does not
  introduce a 2038 boundary or narrow SQLite's integer range.
- Permit insertion order uses an explicit identity column instead of SQLite's
  implicit `rowid`.
- Durable intent leases remain fail-stuck. No clock-based lease takeover was
  introduced.
- `execution_guard` remains process-local. Holding a database/session lock over
  the external adapter call would let a hung venue block a cross-host emergency
  revoke. Cross-host revocation linearizes at the datastore transaction; a
  permit that loses that order is rejected by the durable grant-epoch check at
  consumption.

The global writer order is a safety-first baseline, not a throughput claim.
Reducing its scope requires invariant tests proving that aggregate budget,
authority, permit and identity races remain linearizable.

## Automated evidence

The `postgres-store-contract` Actions job starts PostgreSQL 16 and runs the
PostgreSQL contract tests with disposable, randomly named schemas. Those tests
cover:

- end-to-end execution, replay, usage commit and evidence verification;
- atomic intent CAS and per-venue effect identity;
- multiprocess aggregate-turnover contention;
- durable lease contention;
- a cross-process revoke while an adapter call is blocked;
- evidence-tail tampering;
- schema/backend revision persistence; and
- 64-bit monotonic and epoch-second columns.

The same job runs the mapped red-team suite and the 309-point crash evaluator
with `FAAR_TEST_POSTGRES_DSN` set. A process death drops any open PostgreSQL
transaction; recovery then follows `OPERATIONS.md` exactly as the SQLite run
does.

These tests require both variables so a developer cannot accidentally drop
schemas merely by having a DSN in the environment:

```text
FAAR_TEST_POSTGRES_DSN=postgresql://...
FAAR_TEST_POSTGRES_ALLOW_SCHEMA_DROP=1
```

Use only a disposable test database. Test schemas start with `faar_test_` or
`faar_crash_`.

## Gate 6.4 deployment evidence

An ordinary single-node PostgreSQL test does not prove datastore failover.
Before Gate 6.4 can close for an environment, the deployment owner must record:

1. PostgreSQL 16 topology and synchronous-durability policy, including the
   acknowledged-write failure assumptions and maximum acceptable data loss.
2. A failover endpoint that reconnects clients to the promoted primary without
   letting two writable primaries serve the FAAR schema.
3. The authority anchor stored outside the database backup and replication set.
4. A successful contract, multiprocess, mapped red-team and crash run against
   the exact database configuration.
5. A forced-primary-loss exercise during reservation, permit issuance,
   consumption, terminalization and evidence append, followed by reconciliation
   and verification that no acknowledged row regressed.
6. Post-failover `list-grants`, anchor-regression, held-usage, lease and evidence
   checks before execution resumes.

Gate 8 still requires an independent person. Passing this datastore suite does
not approve live funds, venue credentials or production deployment.
