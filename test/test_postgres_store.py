from __future__ import annotations

import multiprocessing as mp
import os
import time
import unittest
import uuid
from dataclasses import replace
from decimal import Decimal

from faar.adapters import REFERENCE_SAFE_PROFILE, MockVenue
from faar.canonical import canonical_hash
from faar.models import IntentState
from faar.postgres_store import POSTGRES_SCHEMA_REVISION, PostgresIntentStore, _PostgresConnection, _postgres_sql
from faar.settlement import MockSettlementVerifier
from faar.store import EffectConflict, IntentBusy
from support import AUTH, NOW, attest_pair, grant, intent, permit_stack, risk, trust, verification_trust


POSTGRES_DSN = os.environ.get("FAAR_TEST_POSTGRES_DSN")
ALLOW_DROP = os.environ.get("FAAR_TEST_POSTGRES_ALLOW_SCHEMA_DROP") == "1"
EVIDENCE_KEY = b"postgres-contract-evidence-key-32!!"


class PostgresStoreBoundaryTests(unittest.TestCase):
    def test_sql_translation_does_not_rewrite_quoted_question_marks(self):
        translated = _postgres_sql(
            "SELECT '?' AS literal, rowid,* FROM execution_permits "
            "WHERE permit_id=? AND rowid > ?"
        )
        self.assertEqual(
            "SELECT '?' AS literal, issuance_seq AS rowid,* FROM execution_permits "
            "WHERE permit_id=%s AND issuance_seq > %s",
            translated,
        )

    def test_execution_guard_never_acquires_a_database_session_lock(self):
        class RefuseDatabaseUse:
            def execute(self, *args, **kwargs):
                raise AssertionError("execution_guard must not touch PostgreSQL")

        store = object.__new__(PostgresIntentStore)
        store._fence_scope = "postgres-contract-boundary-test"
        store._conn = RefuseDatabaseUse()
        with store.execution_guard("grant:test", 1):
            pass

    def test_schema_and_dsn_are_validated_before_driver_loading(self):
        with self.assertRaisesRegex(ValueError, "DSN"):
            PostgresIntentStore("")
        with self.assertRaisesRegex(ValueError, "schema"):
            PostgresIntentStore("postgresql://unused", schema="public; DROP SCHEMA public")

    def test_writer_lock_timeout_rolls_back_before_failing_closed(self):
        class DriverError(Exception):
            pass

        class FakeDriver:
            IntegrityError = type("IntegrityError", (Exception,), {})
            OperationalError = DriverError
            InterfaceError = type("InterfaceError", (Exception,), {})

        class FakeRaw:
            closed = False

            def __init__(self):
                self.statements = []

            def execute(self, statement, params=()):
                self.statements.append(str(statement))
                if "pg_advisory_xact_lock" in str(statement):
                    raise DriverError("lock timeout")
                return self

        raw = FakeRaw()
        connection = _PostgresConnection(raw, FakeDriver, "test-writer-lock")
        from faar.store import StoreUnavailable

        with self.assertRaises(StoreUnavailable):
            connection.execute("BEGIN IMMEDIATE")
        self.assertEqual("ROLLBACK", raw.statements[-1])


def _reserve_worker(dsn, schema, grant_id, intent_id, risk_version, barrier, queue):
    store = PostgresIntentStore(dsn, schema=schema)
    try:
        limited = grant(
            grant_id=grant_id,
            limits=replace(grant().limits, max_daily_turnover_usd=Decimal("75")),
        )
        barrier.wait()
        queue.put(store.reserve_usage(
            intent(intent_id=intent_id, grant_id=grant_id),
            limited,
            risk(state_version=risk_version),
            NOW,
        ))
    finally:
        store.close()


def _blocked_submit_worker(dsn, schema, entered, release, queue):
    from faar.runtime import FAARRuntime

    signing = trust()
    store = PostgresIntentStore(dsn, schema=schema)
    try:
        authority, verifier = permit_stack(store, signing)
        venue = MockVenue(permit_verifier=verifier, name="mock-dex", clock=lambda: NOW)

        class BlockingAdapter:
            name = "mock-dex"
            security_profile = REFERENCE_SAFE_PROFILE

            def execute(self, request, permit):
                entered.set()
                release.wait(10)
                return venue.execute(request, permit)

        runtime = FAARRuntime(
            store,
            {"mock-dex": BlockingAdapter()},
            verification_trust(signing),
            authority,
            {"mock-dex": MockSettlementVerifier(venue)},
            clock=lambda: NOW,
            allow_test_time_override=True,
        )
        value = intent(intent_id="pg_revoke_000000000000001")
        aa, ra = attest_pair(signing, value, AUTH, risk(), NOW)
        result = runtime.process(
            value,
            AUTH,
            grant(),
            risk(),
            authority_attestation=aa,
            risk_attestation=ra,
            now=NOW,
        )
        rejection_messages = [
            event["payload"].get("message", "")
            for event in store.evidence(value.intent_id)
            if event["event_type"] == "adapter_rejection_untrusted"
        ]
        queue.put((
            "submit",
            result.state.value,
            tuple(result.reason_codes),
            venue.successful_effect_count(value.intent_id),
            rejection_messages,
        ))
    finally:
        store.close()


def _revoke_worker(dsn, schema, entered, release, queue):
    store = PostgresIntentStore(dsn, schema=schema)
    try:
        entered.wait(10)
        started = time.monotonic()
        store.set_grant_status(grant().principal_id, grant().grant_id, grant().version, "REVOKED")
        queue.put(("revoke", time.monotonic() - started))
    finally:
        release.set()
        store.close()


@unittest.skipUnless(
    POSTGRES_DSN and ALLOW_DROP,
    "requires FAAR_TEST_POSTGRES_DSN and explicit schema-drop authorization",
)
class PostgresStoreContractTests(unittest.TestCase):
    def setUp(self):
        self.schema = "faar_test_" + uuid.uuid4().hex[:24]
        self.store = PostgresIntentStore(
            POSTGRES_DSN,
            schema=self.schema,
            evidence_key=EVIDENCE_KEY,
        )

    def tearDown(self):
        self.store.close()
        self.assertTrue(self.schema.startswith("faar_test_"))
        import psycopg
        from psycopg import sql

        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(self.schema))
            )

    def test_runtime_effect_replay_and_evidence_contract(self):
        from support import build_mock_runtime

        signing = trust()
        allowed = grant()
        self.store.provision_grant(allowed, canonical_hash(allowed))
        runtime, venue, _, _, _ = build_mock_runtime(self.store, signing)
        value = intent(intent_id="pg_runtime_00000000000001")
        snapshot = risk()
        aa, ra = attest_pair(signing, value, AUTH, snapshot, NOW)
        first = runtime.process(
            value,
            AUTH,
            allowed,
            snapshot,
            authority_attestation=aa,
            risk_attestation=ra,
            now=NOW,
        )
        replay = runtime.process(
            value,
            AUTH,
            allowed,
            snapshot,
            authority_attestation=aa,
            risk_attestation=ra,
            now=NOW,
        )
        self.assertEqual(IntentState.FINALIZED, first.state)
        self.assertEqual(IntentState.FINALIZED, replay.state)
        self.assertTrue(replay.replayed)
        self.assertEqual(1, venue.successful_effect_count(value.intent_id))
        self.assertEqual("COMMITTED", self.store.usage(allowed.grant_id, allowed.version)[0]["status"])
        self.assertTrue(self.store.verify_evidence_chain(value.intent_id))

    def test_intent_cas_and_effect_identity_are_atomic(self):
        values = (
            intent(intent_id="pg_effect_000000000000001"),
            intent(intent_id="pg_effect_000000000000002"),
        )
        for value in values:
            self.store.register(value, canonical_hash(value))
            self.assertTrue(self.store.transition(value.intent_id, IntentState.PROPOSED, IntentState.AUTHORIZED))
            self.assertTrue(self.store.transition(value.intent_id, IntentState.AUTHORIZED, IntentState.RESERVED))
            self.assertEqual((True, False, 1), self.store.begin_submission(
                value.intent_id, [IntentState.RESERVED], max_attempts=2,
            ))
        self.assertTrue(self.store.transition(
            values[0].intent_id,
            IntentState.SUBMITTED,
            IntentState.CONFIRMED,
            effect_id="venue-effect-1",
        ))
        with self.assertRaises(EffectConflict):
            self.store.transition(
                values[1].intent_id,
                IntentState.SUBMITTED,
                IntentState.CONFIRMED,
                effect_id="venue-effect-1",
            )
        self.assertEqual(IntentState.SUBMITTED, self.store.get(values[1].intent_id).state)

    def test_distinct_processes_cannot_oversubscribe_turnover(self):
        limited = grant(
            grant_id="grant:pg-budget",
            limits=replace(grant().limits, max_daily_turnover_usd=Decimal("75")),
        )
        self.store.provision_grant(limited, canonical_hash(limited))
        ctx = mp.get_context("spawn")
        barrier = ctx.Barrier(2)
        queue = ctx.Queue()
        workers = [
            ctx.Process(
                target=_reserve_worker,
                args=(
                    POSTGRES_DSN,
                    self.schema,
                    limited.grant_id,
                    f"pg_budget_0000000000000{number}",
                    100 + number,
                    barrier,
                    queue,
                ),
            )
            for number in (1, 2)
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(20)
            self.assertEqual(0, worker.exitcode)
        results = [queue.get(timeout=3), queue.get(timeout=3)]
        self.assertEqual(1, sum(1 for accepted, _ in results if accepted))
        refusal = next(reasons for accepted, reasons in results if not accepted)
        self.assertIn("ATOMIC_DAILY_TURNOVER_EXCEEDED", refusal)

    def test_durable_lease_blocks_another_store_instance(self):
        value = intent(intent_id="pg_lease_0000000000000001")
        self.store.register(value, canonical_hash(value))
        other = PostgresIntentStore(POSTGRES_DSN, schema=self.schema)
        try:
            with self.store.intent_guard(value.intent_id):
                with self.assertRaises(IntentBusy):
                    with other.intent_guard(value.intent_id, wait_seconds=0.03):
                        pass
            with other.intent_guard(value.intent_id, wait_seconds=0.1):
                self.assertIsNotNone(other.intent_lease(value.intent_id))
        finally:
            other.close()

    def test_cross_process_revoke_does_not_wait_on_hung_adapter(self):
        allowed = grant()
        self.store.provision_grant(allowed, canonical_hash(allowed))
        ctx = mp.get_context("spawn")
        entered, release, queue = ctx.Event(), ctx.Event(), ctx.Queue()
        submitter = ctx.Process(
            target=_blocked_submit_worker,
            args=(POSTGRES_DSN, self.schema, entered, release, queue),
        )
        revoker = ctx.Process(
            target=_revoke_worker,
            args=(POSTGRES_DSN, self.schema, entered, release, queue),
        )
        submitter.start()
        revoker.start()
        submitter.join(30)
        revoker.join(30)
        self.assertEqual(0, submitter.exitcode)
        self.assertEqual(0, revoker.exitcode)
        messages = [queue.get(timeout=5), queue.get(timeout=5)]
        revoke = next(item for item in messages if item[0] == "revoke")
        submission = next(item for item in messages if item[0] == "submit")
        self.assertLess(revoke[1], 5.0)
        self.assertIn(submission[1], {"FAILED_SAFE", "STOPPED", "UNKNOWN"})
        self.assertEqual(0, submission[3])
        self.assertTrue(any(
            "PERMIT_GRANT_NOT_ACTIVE" in message or "PERMIT_GRANT_EPOCH_STALE" in message
            for message in submission[4]
        ), submission[4])

    def test_evidence_tail_tampering_is_not_healed(self):
        value = intent(intent_id="pg_evidence_00000000000001")
        self.store.register(value, canonical_hash(value))
        self.store.add_evidence(value.intent_id, "authorized", {"step": 1})
        self.store._conn.execute(
            "DELETE FROM evidence WHERE id=(SELECT MAX(id) FROM evidence WHERE intent_id=?)",
            (value.intent_id,),
        )
        self.assertFalse(self.store.verify_evidence_chain(value.intent_id))

    def test_reopen_preserves_schema_revision_without_mutation(self):
        revision = self.store._conn.execute(
            "SELECT value FROM store_settings WHERE key='schema_revision'"
        ).fetchone()["value"]
        self.assertEqual(POSTGRES_SCHEMA_REVISION, revision)
        reopened = PostgresIntentStore(POSTGRES_DSN, schema=self.schema)
        try:
            self.assertEqual(revision, reopened._conn.execute(
                "SELECT value FROM store_settings WHERE key='schema_revision'"
            ).fetchone()["value"])
        finally:
            reopened.close()

    def test_monotonic_and_epoch_second_columns_are_64_bit(self):
        names = {
            "grants": {"runtime_epoch", "fence_counter"},
            "usage_reservations": {"velocity_bucket", "velocity_ts"},
            "risk_claims": {"state_version"},
            "permit_risk_claims": {"state_version"},
            "execution_permits": {"grant_epoch", "fence_token", "issuance_seq"},
            "evidence_head": {"seq"},
        }
        for table, columns in names.items():
            rows = self.store._conn.execute(
                "SELECT column_name,data_type FROM information_schema.columns "
                "WHERE table_schema=current_schema() AND table_name=?",
                (table,),
            ).fetchall()
            types = {str(row["column_name"]): str(row["data_type"]) for row in rows}
            for column in columns:
                self.assertEqual("bigint", types[column], f"{table}.{column}")


if __name__ == "__main__":
    unittest.main()
