from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Iterable, Iterator

from .canonical import canonical_json, parse_bounded_decimal
from .models import CapabilityGrant, Intent, IntentState, MONETARY_PRIMITIVES, RiskSnapshot


# Trailing window used for the atomic "daily" turnover reservation. A calendar-day
# bucket would let up to 2x the cap fire across midnight (the same defect RT-39
# fixed for action velocity); a trailing window is strictly more conservative.
TURNOVER_WINDOW_SECONDS = 86_400

# Per-grant execution fences are shared by every store instance opened on the same
# database file inside one process. Keying them per instance would let an
# in-process admin component revoke through a second instance without waiting for
# a submission that is in flight through the first.
_LOCK_REGISTRY_GUARD = threading.Lock()
_GRANT_LOCKS: dict[tuple[str, str, int], threading.RLock] = {}


TERMINAL_STATES = {
    IntentState.DENIED,
    IntentState.DEFERRED,
    IntentState.STOPPED,
    IntentState.FINALIZED,
    IntentState.FAILED_SAFE,
}


@dataclass(frozen=True)
class StoredIntent:
    intent_id: str
    intent_hash: str
    state: IntentState
    intent_json: str
    effect_id: str | None
    reason_codes: tuple[str, ...]
    submission_count: int
    created_at: str
    updated_at: str


class IntentConflict(RuntimeError):
    pass


class UnknownIntent(KeyError):
    """No durable state exists for this intent_id (it was never registered)."""


class IntentBusy(RuntimeError):
    """Another process owns the durable state-machine lease for this intent."""


class InvalidTransition(RuntimeError):
    pass


class GrantConflict(RuntimeError):
    pass


class EffectConflict(RuntimeError):
    pass


class UnknownGrant(RuntimeError):
    pass


class EvidenceIntegrityError(RuntimeError):
    """The persisted evidence chain no longer matches its signed head commitment.

    Raised instead of appending: a new event must never re-commit a head over a
    truncated or rewritten prefix, which would launder the tampering.
    """


_ALLOWED_TRANSITIONS: dict[IntentState, set[IntentState]] = {
    IntentState.PROPOSED: {IntentState.DENIED, IntentState.DEFERRED, IntentState.STOPPED, IntentState.AUTHORIZED},
    IntentState.AUTHORIZED: {IntentState.RESERVED, IntentState.STOPPED},
    IntentState.RESERVED: {IntentState.SUBMITTED, IntentState.RECONCILING, IntentState.STOPPED},
    IntentState.SUBMITTED: {IntentState.CONFIRMED, IntentState.UNKNOWN, IntentState.RECONCILING, IntentState.STOPPED, IntentState.FAILED_SAFE},
    IntentState.UNKNOWN: {IntentState.RECONCILING, IntentState.STOPPED},
    IntentState.RECONCILING: {IntentState.SUBMITTED, IntentState.CONFIRMED, IntentState.FINALIZED, IntentState.FAILED_SAFE, IntentState.STOPPED, IntentState.UNKNOWN},
    IntentState.CONFIRMED: {IntentState.FINALIZED, IntentState.RECONCILING, IntentState.STOPPED},
    IntentState.DENIED: set(),
    IntentState.DEFERRED: set(),
    IntentState.STOPPED: set(),
    IntentState.FINALIZED: set(),
    IntentState.FAILED_SAFE: set(),
}


class SQLiteIntentStore:
    """Transactional reference store for FAAR.

    Security-relevant properties:
    - UNIQUE(intent_id) binds one logical intent to one canonical payload and one
      principal namespace.
    - BEGIN IMMEDIATE serializes grant-wide usage reservation in this reference DB.
    - compare-and-set state transitions prevent concurrent workers from submitting the
      same intent simultaneously.
    - per-grant execution guards make revocation linearizable for every store
      instance opened on the same database file inside one process: once
      set_grant_status(..., REVOKED) returns, no later submission may begin under
      that grant version through any of those instances. The grant runtime_epoch is
      the cross-process fence consumed at the permit gateway.
    - optional evidence HMACs plus a signed per-intent head commitment detect
      database-only rewriting and tail-truncation of the hash chain; appends refuse
      to re-commit a head over a chain that no longer matches the previous head.

    A production distributed store must reproduce these semantics; SQLite itself is
    not the claimed production architecture.
    """

    def __init__(self, path: str | Path = ":memory:", *, evidence_key: bytes | None = None) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._intent_lock_guard = threading.Lock()
        self._intent_locks: dict[str, tuple[threading.RLock, int]] = {}
        self._intent_guard_local = threading.local()
        self._instance_id = uuid.uuid4().hex
        # ":memory:" databases are private to their connection, so their fences are
        # private too. File-backed stores share fences per resolved path.
        self._fence_scope = self._instance_id if self.path == ":memory:" else os.path.realpath(self.path)
        self._evidence_key = bytes(evidence_key) if evidence_key is not None else None
        if self._evidence_key is not None and len(self._evidence_key) < 16:
            raise ValueError("evidence_key must be at least 16 bytes")

        self._conn = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout = 30000")
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._execute_with_busy_retry("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = FULL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS grants (
                grant_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                principal_id TEXT NOT NULL,
                grant_hash TEXT NOT NULL,
                grant_json TEXT NOT NULL,
                runtime_status TEXT NOT NULL CHECK(runtime_status IN ('ACTIVE','PAUSED','REVOKED')),
                runtime_epoch INTEGER NOT NULL DEFAULT 1,
                fence_counter INTEGER NOT NULL DEFAULT 0,
                provisioned_at TEXT NOT NULL,
                PRIMARY KEY(grant_id, version)
            );
            CREATE TABLE IF NOT EXISTS usage_reservations (
                intent_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                grant_version INTEGER NOT NULL,
                day_key TEXT NOT NULL,
                velocity_bucket INTEGER,
                velocity_ts INTEGER,
                amount_usd TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('HELD','COMMITTED','RELEASED')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_usage_grant_day
              ON usage_reservations(grant_id, grant_version, day_key, status);
            CREATE INDEX IF NOT EXISTS ix_usage_grant_bucket
              ON usage_reservations(grant_id, grant_version, velocity_bucket, status);
            CREATE TABLE IF NOT EXISTS risk_claims (
                principal_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                grant_version INTEGER NOT NULL,
                risk_scope TEXT NOT NULL,
                state_version INTEGER NOT NULL,
                intent_id TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                PRIMARY KEY(grant_id, grant_version, risk_scope, state_version)
            );
            CREATE INDEX IF NOT EXISTS ix_risk_claims_scope
              ON risk_claims(grant_id, grant_version, risk_scope, state_version);
            CREATE TABLE IF NOT EXISTS permit_risk_claims (
                principal_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                grant_version INTEGER NOT NULL,
                risk_scope TEXT NOT NULL,
                state_version INTEGER NOT NULL,
                intent_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(grant_id, grant_version, risk_scope, state_version)
            );
            CREATE INDEX IF NOT EXISTS ix_permit_risk_claims_intent
              ON permit_risk_claims(intent_id, grant_id, grant_version);
            CREATE TABLE IF NOT EXISTS intents (
                intent_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                venue TEXT NOT NULL DEFAULT '',
                intent_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                intent_json TEXT NOT NULL,
                effect_id TEXT,
                reason_codes TEXT NOT NULL DEFAULT '[]',
                submission_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS intent_leases (
                intent_id TEXT PRIMARY KEY,
                owner_token TEXT NOT NULL,
                acquired_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intent_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                prev_hash TEXT,
                event_hash TEXT NOT NULL,
                event_mac TEXT,
                FOREIGN KEY(intent_id) REFERENCES intents(intent_id)
            );
            CREATE TABLE IF NOT EXISTS evidence_head (
                intent_id TEXT PRIMARY KEY,
                seq INTEGER NOT NULL,
                head_hash TEXT NOT NULL,
                head_mac TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS execution_permits (
                permit_id TEXT PRIMARY KEY,
                intent_id TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                grant_version INTEGER NOT NULL,
                grant_epoch INTEGER NOT NULL,
                fence_token INTEGER NOT NULL,
                permit_hash TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                consumed_at TEXT,
                UNIQUE(grant_id, grant_version, fence_token)
            );
            """
        )
        self._migrate_columns()
        self._create_dependent_indexes()

    def _execute_with_busy_retry(self, sql: str, *, attempts: int = 200) -> None:
        # PRAGMA statements do not honour busy_timeout on every SQLite build; a fleet
        # of workers opening the same file concurrently must not fail on startup.
        for attempt in range(attempts):
            try:
                self._conn.execute(sql)
                return
            except sqlite3.OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == attempts - 1:
                    raise
                time.sleep(0.01)

    _COLUMN_MIGRATIONS: tuple[tuple[str, str, str], ...] = (
        ("intents", "submission_count", "INTEGER NOT NULL DEFAULT 0"),
        ("intents", "principal_id", "TEXT NOT NULL DEFAULT 'legacy:unknown'"),
        ("intents", "venue", "TEXT NOT NULL DEFAULT ''"),
        ("evidence", "event_mac", "TEXT"),
        ("evidence", "principal_id", "TEXT NOT NULL DEFAULT 'legacy:unknown'"),
        ("grants", "principal_id", "TEXT NOT NULL DEFAULT 'legacy:unknown'"),
        ("grants", "runtime_epoch", "INTEGER NOT NULL DEFAULT 1"),
        ("grants", "fence_counter", "INTEGER NOT NULL DEFAULT 0"),
        ("usage_reservations", "principal_id", "TEXT NOT NULL DEFAULT 'legacy:unknown'"),
        ("usage_reservations", "velocity_ts", "INTEGER"),
        ("risk_claims", "principal_id", "TEXT NOT NULL DEFAULT 'legacy:unknown'"),
        ("execution_permits", "consumed_at", "TEXT"),
    )

    def _migrate_columns(self) -> None:
        """Add columns introduced after a database was created.

        Runs as one IMMEDIATE transaction and re-reads the schema inside it so that
        several workers starting against the same legacy file cannot both observe a
        missing column and race their ALTER statements.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                for table, column, definition in self._COLUMN_MIGRATIONS:
                    cols = {row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()}
                    if column not in cols:
                        self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def _create_dependent_indexes(self) -> None:
        """Indexes over columns that may only exist after `_migrate_columns`.

        A v0.3.0 database had no `velocity_ts` column; creating this index inside the
        initial `executescript` made every v0.3.1 entry point crash on open before the
        migration could run.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS ix_usage_grant_velocity_ts "
                    "ON usage_reservations(grant_id, grant_version, velocity_ts, status)"
                )
                # Effect identity is a per-venue namespace (ADAPTER_CONTRACT §3):
                # exchange fill/order identifiers legitimately collide across venues.
                # Uniqueness is enforced per (venue, effect_id); the legacy global
                # index would record a genuine second-venue effect as STOPPED.
                self._conn.execute("DROP INDEX IF EXISTS ux_effect_id_nonnull")
                self._conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS ux_effect_id_per_venue "
                    "ON intents(venue, effect_id) WHERE effect_id IS NOT NULL"
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "SQLiteIntentStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _grant_lock(self, grant_id: str, version: int) -> threading.RLock:
        key = (self._fence_scope, grant_id, version)
        with _LOCK_REGISTRY_GUARD:
            lock = _GRANT_LOCKS.get(key)
            if lock is None:
                lock = threading.RLock()
                _GRANT_LOCKS[key] = lock
            return lock

    @contextmanager
    def execution_guard(self, grant_id: str, version: int) -> Iterator[None]:
        lock = self._grant_lock(grant_id, version)
        with lock:
            yield

    def _acquire_intent_lock(self, intent_id: str, timeout: float) -> threading.RLock | None:
        with self._intent_lock_guard:
            lock, refs = self._intent_locks.get(intent_id, (None, 0))
            if lock is None:
                lock = threading.RLock()
            self._intent_locks[intent_id] = (lock, refs + 1)
        if lock.acquire(timeout=max(timeout, 0.0)):
            return lock
        self._release_intent_lock(intent_id, None)
        return None

    def _release_intent_lock(self, intent_id: str, lock: threading.RLock | None) -> None:
        if lock is not None:
            lock.release()
        # Reference-counted so a long-running worker does not retain one RLock per
        # intent it has ever processed.
        with self._intent_lock_guard:
            current, refs = self._intent_locks[intent_id]
            if refs <= 1:
                del self._intent_locks[intent_id]
            else:
                self._intent_locks[intent_id] = (current, refs - 1)

    @contextmanager
    def intent_guard(self, intent_id: str, *, wait_seconds: float = 5.0) -> Iterator[None]:
        """Serialize one intent's state machine across threads and processes.

        `wait_seconds` bounds the total wait for both the in-process lock and the
        durable database lease; contention past the deadline raises `IntentBusy`.

        The database lease deliberately has no automatic TTL. If a process dies while
        owning it, subsequent workers fail-stuck with `IntentBusy`; an operator must
        reconcile external settlement and explicitly clear the stale lease (see
        `clear_stale_intent_lease` and docs/RECOVERY.md). Automatic time-based
        takeover would reintroduce duplicate-execution risk.
        """
        active = getattr(self._intent_guard_local, "active", set())
        if intent_id in active:
            yield
            return

        deadline = time.monotonic() + max(wait_seconds, 0.0)
        local_lock = self._acquire_intent_lock(intent_id, wait_seconds)
        if local_lock is None:
            raise IntentBusy(f"intent {intent_id} is being processed by another worker in this process")
        try:
            owner = f"{self._instance_id}:{threading.get_ident()}"
            acquired = False
            while not acquired:
                with self._lock:
                    try:
                        self._conn.execute(
                            "INSERT INTO intent_leases(intent_id,owner_token,acquired_at) VALUES(?,?,?)",
                            (intent_id, owner, self._now()),
                        )
                        acquired = True
                    except sqlite3.IntegrityError:
                        acquired = False
                if acquired:
                    break
                if time.monotonic() >= deadline:
                    raise IntentBusy(f"intent {intent_id} is leased by another worker")
                time.sleep(0.005)

            new_active = set(active); new_active.add(intent_id)
            self._intent_guard_local.active = new_active
            try:
                yield
            finally:
                active2 = set(getattr(self._intent_guard_local, "active", set()))
                active2.discard(intent_id); self._intent_guard_local.active = active2
                with self._lock:
                    self._conn.execute(
                        "DELETE FROM intent_leases WHERE intent_id=? AND owner_token=?",
                        (intent_id, owner),
                    )
        finally:
            self._release_intent_lock(intent_id, local_lock)

    def intent_lease(self, intent_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM intent_leases WHERE intent_id=?", (intent_id,)
            ).fetchone()
        return None if row is None else dict(row)

    def clear_stale_intent_lease(self, intent_id: str, *, expected_owner_token: str) -> bool:
        """Administrative recovery primitive; never called automatically by runtime."""
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM intent_leases WHERE intent_id=? AND owner_token=?",
                (intent_id, expected_owner_token),
            )
            return cur.rowcount == 1

    def provision_grant(self, grant: CapabilityGrant, grant_hash: str) -> None:
        """Provision an immutable grant version from a separate authority domain."""
        payload = canonical_json(grant)
        with self.execution_guard(grant.grant_id, grant.version), self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT grant_hash,principal_id FROM grants WHERE grant_id=? AND version=?",
                    (grant.grant_id, grant.version),
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO grants(grant_id,version,principal_id,grant_hash,grant_json,runtime_status,runtime_epoch,fence_counter,provisioned_at) VALUES(?,?,?,?,?,?,?,?,?)",
                        (grant.grant_id, grant.version, grant.principal_id, grant_hash, payload, grant.status.value, 1, 0, self._now()),
                    )
                elif row["grant_hash"] != grant_hash or row["principal_id"] != grant.principal_id:
                    raise GrantConflict("grant_id/version already provisioned with a different principal or capability envelope")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def verify_grant(self, grant: CapabilityGrant, grant_hash: str) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT grant_hash,principal_id FROM grants WHERE grant_id=? AND version=?",
                (grant.grant_id, grant.version),
            ).fetchone()
            if row is None:
                raise UnknownGrant(f"grant {grant.grant_id}@{grant.version} is not provisioned")
            if row["grant_hash"] != grant_hash or row["principal_id"] != grant.principal_id:
                raise GrantConflict("presented grant does not match provisioned principal/capability envelope")

    def get_grant_control(self, principal_id: str, grant_id: str, version: int) -> tuple[str, int, int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT principal_id,runtime_status,runtime_epoch,fence_counter FROM grants WHERE grant_id=? AND version=?",
                (grant_id, version),
            ).fetchone()
            if row is None:
                raise UnknownGrant(f"grant {grant_id}@{version} is not provisioned")
            if str(row["principal_id"]) != principal_id:
                raise GrantConflict("grant principal mismatch")
            return str(row["runtime_status"]), int(row["runtime_epoch"]), int(row["fence_counter"])

    def get_grant_status(self, principal_id: str, grant_id: str, version: int) -> str:
        return self.get_grant_control(principal_id, grant_id, version)[0]

    def set_grant_status(self, principal_id: str, grant_id: str, version: int, status: str) -> None:
        if status not in {"ACTIVE", "PAUSED", "REVOKED"}:
            raise ValueError("invalid grant runtime status")
        # v0.3: runtime_epoch is the distributed revocation fence. Every actual
        # lifecycle change increments it, invalidating permits issued under the
        # previous epoch even in another process.
        with self.execution_guard(grant_id, version), self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT principal_id,runtime_status,runtime_epoch FROM grants WHERE grant_id=? AND version=?",
                    (grant_id, version),
                ).fetchone()
                if row is None:
                    raise UnknownGrant(f"grant {grant_id}@{version} is not provisioned")
                if str(row["principal_id"]) != principal_id:
                    raise GrantConflict("grant principal mismatch")
                current = str(row["runtime_status"])
                if current == "REVOKED" and status != "REVOKED":
                    raise GrantConflict("revoked grant versions cannot be reactivated; provision a new version")
                if current != status:
                    self._conn.execute(
                        "UPDATE grants SET runtime_status=?, runtime_epoch=runtime_epoch+1 WHERE grant_id=? AND version=?",
                        (status, grant_id, version),
                    )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def next_execution_fence(self, grant: CapabilityGrant) -> tuple[int, int]:
        """Atomically allocate a monotonically increasing fence for an ACTIVE grant."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT principal_id,runtime_status,runtime_epoch,fence_counter,grant_hash FROM grants WHERE grant_id=? AND version=?",
                    (grant.grant_id, grant.version),
                ).fetchone()
                if row is None:
                    raise UnknownGrant(f"grant {grant.grant_id}@{grant.version} is not provisioned")
                if str(row["principal_id"]) != grant.principal_id:
                    raise GrantConflict("grant principal mismatch")
                if str(row["runtime_status"]) != "ACTIVE":
                    raise GrantConflict(f"grant runtime status is {row['runtime_status']}")
                counter = int(row["fence_counter"]) + 1
                epoch = int(row["runtime_epoch"])
                self._conn.execute(
                    "UPDATE grants SET fence_counter=? WHERE grant_id=? AND version=?",
                    (counter, grant.grant_id, grant.version),
                )
                self._conn.execute("COMMIT")
                return epoch, counter
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def verify_usage_held(self, intent: Intent, grant: CapabilityGrant) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT principal_id,grant_id,grant_version,status FROM usage_reservations WHERE intent_id=?",
                (intent.intent_id,),
            ).fetchone()
        return bool(
            row is not None
            and str(row["principal_id"]) == intent.principal_id == grant.principal_id
            and str(row["grant_id"]) == grant.grant_id
            and int(row["grant_version"]) == grant.version
            and str(row["status"]) == "HELD"
        )

    def claim_permit_risk_state(
        self, intent: Intent, grant: CapabilityGrant, risk: RiskSnapshot
    ) -> tuple[bool, tuple[str, ...]]:
        """Atomically bind every risk snapshot used to mint an execution permit.

        `reserve_usage` claims the initial risk state. Retries can legitimately use a
        fresher state without creating a new usage row; this second ledger prevents
        that fresh state from being replayed by a different intent. Claims are
        conservative and are not released if later permit issuance fails.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                held = self._conn.execute(
                    "SELECT principal_id,grant_id,grant_version,status FROM usage_reservations WHERE intent_id=?",
                    (intent.intent_id,),
                ).fetchone()
                if not (
                    held is not None
                    and str(held["principal_id"]) == intent.principal_id == grant.principal_id
                    and str(held["grant_id"]) == grant.grant_id
                    and int(held["grant_version"]) == grant.version
                    and str(held["status"]) == "HELD"
                ):
                    self._conn.execute("COMMIT")
                    return False, ("PERMIT_RISK_USAGE_NOT_HELD",)

                prior = self._conn.execute(
                    "SELECT principal_id,intent_id FROM permit_risk_claims "
                    "WHERE grant_id=? AND grant_version=? AND risk_scope=? AND state_version=?",
                    (grant.grant_id, grant.version, risk.scope, risk.state_version),
                ).fetchone()
                if prior is not None:
                    if str(prior["principal_id"]) != intent.principal_id or str(prior["intent_id"]) != intent.intent_id:
                        self._conn.execute("COMMIT")
                        return False, ("PERMIT_RISK_STATE_VERSION_ALREADY_CLAIMED",)
                    self._conn.execute("COMMIT")
                    return True, ()

                max_initial = self._conn.execute(
                    "SELECT MAX(state_version) AS v FROM risk_claims "
                    "WHERE grant_id=? AND grant_version=? AND risk_scope=?",
                    (grant.grant_id, grant.version, risk.scope),
                ).fetchone()["v"]
                max_permit = self._conn.execute(
                    "SELECT MAX(state_version) AS v FROM permit_risk_claims "
                    "WHERE grant_id=? AND grant_version=? AND risk_scope=?",
                    (grant.grant_id, grant.version, risk.scope),
                ).fetchone()["v"]
                versions = [int(v) for v in (max_initial, max_permit) if v is not None]
                if versions and risk.state_version < max(versions):
                    self._conn.execute("COMMIT")
                    return False, ("PERMIT_RISK_STATE_VERSION_NOT_MONOTONIC",)

                self._conn.execute(
                    "INSERT INTO permit_risk_claims(principal_id,grant_id,grant_version,risk_scope,state_version,intent_id,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (intent.principal_id, grant.grant_id, grant.version, risk.scope, risk.state_version, intent.intent_id, self._now()),
                )
                self._conn.execute("COMMIT")
                return True, ()
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def permit_risk_claims(self, grant_id: str, version: int, scope: str = "portfolio") -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM permit_risk_claims WHERE grant_id=? AND grant_version=? AND risk_scope=? ORDER BY state_version",
                (grant_id, version, scope),
            ).fetchall()
        return [dict(r) for r in rows]

    def record_execution_permit(self, permit_id: str, intent: Intent, grant: CapabilityGrant, grant_epoch: int, fence_token: int, permit_hash: str) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO execution_permits(permit_id,intent_id,principal_id,grant_id,grant_version,grant_epoch,fence_token,permit_hash,issued_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (permit_id, intent.intent_id, intent.principal_id, grant.grant_id, grant.version, grant_epoch, fence_token, permit_hash, self._now()),
            )

    def consume_execution_permit(
        self,
        *,
        permit_id: str,
        principal_id: str,
        grant_id: str,
        grant_version: int,
        grant_epoch: int,
        fence_token: int,
        permit_hash: str,
    ) -> tuple[bool, tuple[str, ...]]:
        """Atomically consume a permit against the current grant epoch.

        This transaction is the reference execution authorization linearization
        point. It serializes with `set_grant_status`: a permit either consumes while
        the grant epoch is ACTIVE, or a pause/revoke completes first and consumption
        is rejected. A consumed permit is single-use even if a transport retries it.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT * FROM execution_permits WHERE permit_id=?", (permit_id,)
                ).fetchone()
                if row is None:
                    self._conn.execute("COMMIT")
                    return False, ("PERMIT_NOT_RECORDED",)
                expected = (
                    str(row["principal_id"]) == principal_id
                    and str(row["grant_id"]) == grant_id
                    and int(row["grant_version"]) == grant_version
                    and int(row["grant_epoch"]) == grant_epoch
                    and int(row["fence_token"]) == fence_token
                    and str(row["permit_hash"]) == permit_hash
                )
                if not expected:
                    self._conn.execute("COMMIT")
                    return False, ("PERMIT_LEDGER_BINDING_MISMATCH",)
                if row["consumed_at"] is not None:
                    self._conn.execute("COMMIT")
                    return False, ("PERMIT_ALREADY_CONSUMED",)

                grant_row = self._conn.execute(
                    "SELECT principal_id,runtime_status,runtime_epoch FROM grants WHERE grant_id=? AND version=?",
                    (grant_id, grant_version),
                ).fetchone()
                if grant_row is None:
                    self._conn.execute("COMMIT")
                    return False, ("PERMIT_GRANT_CONTROL_UNAVAILABLE",)
                reasons: list[str] = []
                if str(grant_row["principal_id"]) != principal_id:
                    reasons.append("PERMIT_GRANT_PRINCIPAL_MISMATCH")
                if str(grant_row["runtime_status"]) != "ACTIVE":
                    reasons.append("PERMIT_GRANT_NOT_ACTIVE")
                if int(grant_row["runtime_epoch"]) != grant_epoch:
                    reasons.append("PERMIT_GRANT_EPOCH_STALE")
                if reasons:
                    self._conn.execute("COMMIT")
                    return False, tuple(reasons)

                self._conn.execute(
                    "UPDATE execution_permits SET consumed_at=? WHERE permit_id=? AND consumed_at IS NULL",
                    (self._now(), permit_id),
                )
                self._conn.execute("COMMIT")
                return True, ()
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _reservation_amount(intent: Intent) -> Decimal | None:
        """Economic amount a reservation must hold, or None when it is not usable.

        The store is the atomic enforcement point for I-13, so it must not coerce a
        malformed, negative or non-finite amount on a money-moving primitive into a
        zero-cost reservation (I-18). Non-monetary primitives reserve zero notional
        and only consume action velocity.
        """
        if intent.primitive not in MONETARY_PRIMITIVES:
            return Decimal("0")
        amount = parse_bounded_decimal(intent.payload.get("amount_usd", intent.payload.get("notional_usd")))
        if amount is None or amount <= 0:
            return None
        return amount

    def reserve_usage(self, intent: Intent, grant: CapabilityGrant, risk: RiskSnapshot, now: datetime) -> tuple[bool, tuple[str, ...]]:
        """Atomically reserve grant-level turnover and action velocity.

        HELD reservations count against limits until reconciliation proves no effect
        and the reservation is explicitly released. This intentionally sacrifices
        availability under ambiguity to prevent concurrent oversubscription.

        Turnover is a trailing `TURNOVER_WINDOW_SECONDS` window, not a calendar day.
        """
        amount = self._reservation_amount(intent)
        if amount is None:
            return False, ("USAGE_AMOUNT_INVALID",)

        day_key = now.astimezone(timezone.utc).date().isoformat()
        window = grant.limits.action_window_seconds
        bucket = int(now.timestamp()) // window if window else None
        velocity_ts = int(now.timestamp())

        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT status,principal_id FROM usage_reservations WHERE intent_id=?",
                    (intent.intent_id,),
                ).fetchone()
                if existing is not None:
                    if str(existing["principal_id"]) != intent.principal_id:
                        self._conn.execute("COMMIT")
                        return False, ("INTENT_NAMESPACE_CONFLICT",)
                    self._conn.execute("COMMIT")
                    return True, ()

                reasons: list[str] = []
                prior_claim = self._conn.execute(
                    "SELECT intent_id FROM risk_claims WHERE grant_id=? AND grant_version=? AND risk_scope=? AND state_version=?",
                    (grant.grant_id, grant.version, risk.scope, risk.state_version),
                ).fetchone()
                if prior_claim is not None and prior_claim["intent_id"] != intent.intent_id:
                    reasons.append("RISK_STATE_VERSION_ALREADY_CLAIMED")
                # The monotonic ceiling spans both ledgers: a fresher state version
                # consumed by a retry (permit_risk_claims) supersedes older versions
                # exactly as an initial claim does. Both ledgers must agree on what
                # "stale" means or a new intent burns a submission attempt on a
                # version the permit authority will refuse anyway.
                max_initial = self._conn.execute(
                    "SELECT MAX(state_version) AS v FROM risk_claims WHERE grant_id=? AND grant_version=? AND risk_scope=?",
                    (grant.grant_id, grant.version, risk.scope),
                ).fetchone()["v"]
                max_permit = self._conn.execute(
                    "SELECT MAX(state_version) AS v FROM permit_risk_claims WHERE grant_id=? AND grant_version=? AND risk_scope=?",
                    (grant.grant_id, grant.version, risk.scope),
                ).fetchone()["v"]
                ceilings = [int(v) for v in (max_initial, max_permit) if v is not None]
                if ceilings and risk.state_version < max(ceilings):
                    reasons.append("RISK_STATE_VERSION_NOT_MONOTONIC")
                if grant.limits.max_daily_turnover_usd is not None:
                    # Trailing window. Rows written before `velocity_ts` existed fall
                    # back to their calendar day so an upgrade never under-counts.
                    rows = self._conn.execute(
                        "SELECT amount_usd FROM usage_reservations WHERE grant_id=? AND grant_version=? "
                        "AND status IN ('HELD','COMMITTED') "
                        "AND ((velocity_ts IS NOT NULL AND velocity_ts > ?) OR (velocity_ts IS NULL AND day_key=?))",
                        (grant.grant_id, grant.version, velocity_ts - TURNOVER_WINDOW_SECONDS, day_key),
                    ).fetchall()
                    current = sum((Decimal(r["amount_usd"]) for r in rows), Decimal("0"))
                    if current + amount > grant.limits.max_daily_turnover_usd:
                        reasons.append("ATOMIC_DAILY_TURNOVER_EXCEEDED")

                if grant.limits.max_actions_per_window is not None and window:
                    # Sliding window over the trailing `window` seconds. A fixed
                    # tumbling bucket (timestamp // window) would let up to 2x the
                    # limit fire across a bucket boundary.
                    count = self._conn.execute(
                        "SELECT COUNT(*) AS n FROM usage_reservations WHERE grant_id=? AND grant_version=? AND velocity_ts > ? AND status IN ('HELD','COMMITTED')",
                        (grant.grant_id, grant.version, velocity_ts - window),
                    ).fetchone()["n"]
                    if count + 1 > grant.limits.max_actions_per_window:
                        reasons.append("ATOMIC_ACTION_VELOCITY_EXCEEDED")

                if reasons:
                    self._conn.execute("COMMIT")
                    return False, tuple(reasons)

                ts = self._now()
                self._conn.execute(
                    "INSERT INTO risk_claims(principal_id,grant_id,grant_version,risk_scope,state_version,intent_id,created_at) VALUES(?,?,?,?,?,?,?)",
                    (intent.principal_id, grant.grant_id, grant.version, risk.scope, risk.state_version, intent.intent_id, ts),
                )
                self._conn.execute(
                    "INSERT INTO usage_reservations(intent_id,principal_id,grant_id,grant_version,day_key,velocity_bucket,velocity_ts,amount_usd,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (intent.intent_id, intent.principal_id, grant.grant_id, grant.version, day_key, bucket, velocity_ts, format(amount, "f"), "HELD", ts, ts),
                )
                self._conn.execute("COMMIT")
                return True, ()
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def commit_usage(self, intent_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE usage_reservations SET status='COMMITTED', updated_at=? WHERE intent_id=? AND status='HELD'",
                (self._now(), intent_id),
            )

    def release_usage(self, intent_id: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE usage_reservations SET status='RELEASED', updated_at=? WHERE intent_id=? AND status='HELD'",
                (self._now(), intent_id),
            )

    def usage(self, grant_id: str, version: int) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM usage_reservations WHERE grant_id=? AND grant_version=? ORDER BY created_at,intent_id",
                (grant_id, version),
            ).fetchall()
        return [dict(r) for r in rows]

    def risk_claims(self, grant_id: str, version: int, scope: str = "portfolio") -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM risk_claims WHERE grant_id=? AND grant_version=? AND risk_scope=? ORDER BY state_version",
                (grant_id, version, scope),
            ).fetchall()
        return [dict(r) for r in rows]

    def register(self, intent: Intent, intent_hash: str) -> StoredIntent:
        payload = canonical_json(intent)
        now = self._now()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT * FROM intents WHERE intent_id = ?", (intent.intent_id,)).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO intents(intent_id,principal_id,venue,intent_hash,state,intent_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                        (intent.intent_id, intent.principal_id, intent.venue, intent_hash, IntentState.PROPOSED.value, payload, now, now),
                    )
                    # The chain starts in the same transaction as the intent row, so
                    # every registered intent owns a signed head from birth. A keyed
                    # verifier can then treat "intent exists but has no evidence" as
                    # whole-chain deletion rather than an empty chain.
                    self._append_evidence_in_txn(
                        intent.intent_id, intent.principal_id, "intent_registered",
                        {"intent_hash": intent_hash, "venue": intent.venue, "primitive": intent.primitive.value},
                    )
                elif str(row["principal_id"]) != intent.principal_id:
                    raise IntentConflict("intent_id is already claimed by another principal namespace")
                elif row["intent_hash"] != intent_hash:
                    raise IntentConflict("intent_id already exists with a different canonical payload")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return self.get(intent.intent_id)

    def get(self, intent_id: str) -> StoredIntent:
        with self._lock:
            row = self._conn.execute("SELECT * FROM intents WHERE intent_id = ?", (intent_id,)).fetchone()
        if row is None:
            raise UnknownIntent(intent_id)
        return StoredIntent(
            intent_id=row["intent_id"],
            intent_hash=row["intent_hash"],
            state=IntentState(row["state"]),
            intent_json=row["intent_json"],
            effect_id=row["effect_id"],
            reason_codes=tuple(json.loads(row["reason_codes"])),
            submission_count=int(row["submission_count"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def transition(
        self,
        intent_id: str,
        expected: IntentState | Iterable[IntentState],
        new_state: IntentState,
        *,
        reason_codes: Iterable[str] = (),
        effect_id: str | None = None,
        release_usage: bool = False,
    ) -> bool:
        """Compare-and-set the intent state.

        `release_usage=True` releases the intent's HELD reservation in the same
        transaction. Terminalizing and releasing as two autocommit statements leaves
        a crash window in which a provably never-submitted intent keeps consuming the
        grant's turnover and velocity budget forever.
        """
        expected_set = {expected} if isinstance(expected, IntentState) else set(expected)
        if effect_id is not None and not isinstance(effect_id, str):
            raise ValueError("effect_id must be a string")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute("SELECT state,effect_id FROM intents WHERE intent_id = ?", (intent_id,)).fetchone()
                if row is None:
                    raise KeyError(intent_id)
                current = IntentState(row["state"])
                if current not in expected_set:
                    self._conn.execute("COMMIT")
                    return False
                if new_state not in _ALLOWED_TRANSITIONS[current]:
                    raise InvalidTransition(f"{current.value} -> {new_state.value} is not allowed")
                final_effect = effect_id if effect_id is not None else row["effect_id"]
                ts = self._now()
                self._conn.execute(
                    "UPDATE intents SET state=?, effect_id=?, reason_codes=?, updated_at=? WHERE intent_id=?",
                    (new_state.value, final_effect, json.dumps(list(reason_codes)), ts, intent_id),
                )
                if release_usage:
                    self._conn.execute(
                        "UPDATE usage_reservations SET status='RELEASED', updated_at=? WHERE intent_id=? AND status='HELD'",
                        (ts, intent_id),
                    )
                self._conn.execute("COMMIT")
                return True
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                if "effect_id" in str(exc):
                    raise EffectConflict("effect_id is already bound to another intent") from exc
                raise
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def begin_submission(
        self,
        intent_id: str,
        expected: Iterable[IntentState],
        *,
        max_attempts: int,
    ) -> tuple[bool, bool, int]:
        """CAS into SUBMITTED and atomically increment the durable attempt count.

        Returns (started, limit_reached, resulting_count).
        """
        expected_set = set(expected)
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT state,submission_count FROM intents WHERE intent_id=?",
                    (intent_id,),
                ).fetchone()
                if row is None:
                    raise KeyError(intent_id)
                current = IntentState(row["state"])
                count = int(row["submission_count"])
                if current not in expected_set:
                    self._conn.execute("COMMIT")
                    return False, False, count
                if count >= max_attempts:
                    self._conn.execute("COMMIT")
                    return False, True, count
                if IntentState.SUBMITTED not in _ALLOWED_TRANSITIONS[current]:
                    raise InvalidTransition(f"{current.value} -> SUBMITTED is not allowed")
                count += 1
                self._conn.execute(
                    "UPDATE intents SET state=?, submission_count=?, reason_codes='[]', updated_at=? WHERE intent_id=?",
                    (IntentState.SUBMITTED.value, count, self._now(), intent_id),
                )
                self._conn.execute("COMMIT")
                return True, False, count
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def _head_mac(self, intent_id: str, seq: int, head_hash: str) -> str | None:
        if self._evidence_key is None:
            return None
        return hmac.new(
            self._evidence_key,
            f"{intent_id}\x1f{seq}\x1f{head_hash}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _check_head_matches_tail(self, intent_id: str, count: int, last_hash: str | None) -> None:
        """Refuse to extend a chain whose committed head no longer matches its tail.

        Without this check, the next legitimate append after a tail truncation
        re-commits the head over the shortened prefix and the tampering becomes
        undetectable. Only meaningful under an evidence key (an unkeyed head row can
        be rewritten by the same attacker), so unkeyed stores are not blocked.
        """
        if self._evidence_key is None:
            return
        head = self._conn.execute(
            "SELECT seq,head_hash,head_mac FROM evidence_head WHERE intent_id=?", (intent_id,)
        ).fetchone()
        if count == 0:
            if head is not None:
                raise EvidenceIntegrityError(f"evidence chain for {intent_id} is missing but a head commitment exists")
            return
        if head is None:
            raise EvidenceIntegrityError(
                f"evidence chain for {intent_id} has no head commitment; "
                "run rebuild_evidence_head under operator control after verifying the chain"
            )
        expected_mac = self._head_mac(intent_id, count - 1, last_hash or "")
        if (
            int(head["seq"]) != count - 1
            or str(head["head_hash"]) != last_hash
            or not head["head_mac"]
            or not hmac.compare_digest(str(expected_mac), str(head["head_mac"]))
        ):
            raise EvidenceIntegrityError(f"evidence chain for {intent_id} does not match its signed head commitment")

    def _append_evidence_in_txn(self, intent_id: str, principal_id: str, event_type: str, payload: dict) -> str:
        """Append one hash-linked event. Caller owns the lock and the transaction."""
        tail = self._conn.execute(
            "SELECT COUNT(*) AS n, MAX(id) AS last_id FROM evidence WHERE intent_id=?", (intent_id,)
        ).fetchone()
        count = int(tail["n"])
        prev_hash = None
        if count:
            last = self._conn.execute("SELECT event_hash FROM evidence WHERE id=?", (tail["last_id"],)).fetchone()
            prev_hash = last["event_hash"]
        self._check_head_matches_tail(intent_id, count, prev_hash)

        created_at = self._now()
        payload_json = canonical_json(payload)
        envelope = canonical_json({
            "intent_id": intent_id,
            "event_type": event_type,
            "payload": json.loads(payload_json),
            "created_at": created_at,
            "prev_hash": prev_hash,
        })
        event_hash = hashlib.sha256(envelope.encode("utf-8")).hexdigest()
        event_mac = None
        if self._evidence_key is not None:
            event_mac = hmac.new(self._evidence_key, event_hash.encode("ascii"), hashlib.sha256).hexdigest()
        self._conn.execute(
            "INSERT INTO evidence(intent_id,principal_id,event_type,payload_json,created_at,prev_hash,event_hash,event_mac) VALUES(?,?,?,?,?,?,?,?)",
            (intent_id, principal_id, event_type, payload_json, created_at, prev_hash, event_hash, event_mac),
        )
        # Signed head commitment. A prev_hash chain alone cannot detect tail
        # truncation (a deleted suffix leaves an internally consistent prefix).
        # Binding the (seq, head_hash) under the evidence MAC lets a keyed verifier
        # detect that the most recent events were dropped.
        seq = count
        self._conn.execute(
            "INSERT INTO evidence_head(intent_id,seq,head_hash,head_mac,updated_at) VALUES(?,?,?,?,?) "
            "ON CONFLICT(intent_id) DO UPDATE SET seq=excluded.seq, head_hash=excluded.head_hash, head_mac=excluded.head_mac, updated_at=excluded.updated_at",
            (intent_id, seq, event_hash, self._head_mac(intent_id, seq, event_hash), created_at),
        )
        return event_hash

    def add_evidence(self, intent_id: str, event_type: str, payload: dict) -> str:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                principal = self._conn.execute("SELECT principal_id FROM intents WHERE intent_id=?", (intent_id,)).fetchone()
                if principal is None:
                    raise KeyError(intent_id)
                event_hash = self._append_evidence_in_txn(intent_id, str(principal["principal_id"]), event_type, payload)
                self._conn.execute("COMMIT")
                return event_hash
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def rebuild_evidence_head(self, intent_id: str) -> bool:
        """Operator-only migration: commit a head over a chain that predates head rows.

        Never called by the runtime. Requires the evidence key (which only the trusted
        runtime/operator holds) and refuses when the chain itself does not verify, so
        it cannot be used to launder a tampered prefix.
        """
        if self._evidence_key is None:
            raise ValueError("rebuild_evidence_head requires an evidence key")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if self._conn.execute("SELECT 1 FROM intents WHERE intent_id=?", (intent_id,)).fetchone() is None:
                    raise KeyError(intent_id)
                if self._conn.execute("SELECT 1 FROM evidence_head WHERE intent_id=?", (intent_id,)).fetchone() is not None:
                    self._conn.execute("COMMIT")
                    return False
                rows = self._evidence_rows_locked(intent_id)
                ok, count, last_hash = self._verify_chain_rows(intent_id, rows)
                if not ok or count == 0:
                    raise EvidenceIntegrityError(f"evidence chain for {intent_id} does not verify; refusing to commit a head")
                self._conn.execute(
                    "INSERT INTO evidence_head(intent_id,seq,head_hash,head_mac,updated_at) VALUES(?,?,?,?,?)",
                    (intent_id, count - 1, last_hash, self._head_mac(intent_id, count - 1, str(last_hash)), self._now()),
                )
                self._conn.execute("COMMIT")
                return True
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def _evidence_rows_locked(self, intent_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT event_type,payload_json,created_at,prev_hash,event_hash,event_mac FROM evidence WHERE intent_id=? ORDER BY id",
            (intent_id,),
        ).fetchall()
        return [
            {
                "event_type": r["event_type"],
                "payload": json.loads(r["payload_json"]),
                "created_at": r["created_at"],
                "prev_hash": r["prev_hash"],
                "event_hash": r["event_hash"],
                "event_mac": r["event_mac"],
            }
            for r in rows
        ]

    def evidence(self, intent_id: str) -> list[dict]:
        with self._lock:
            return self._evidence_rows_locked(intent_id)

    def _verify_chain_rows(self, intent_id: str, events: list[dict]) -> tuple[bool, int, str | None]:
        prev_hash = None
        count = 0
        last_hash = None
        for event in events:
            if event["prev_hash"] != prev_hash:
                return False, count, last_hash
            envelope = canonical_json({
                "intent_id": intent_id,
                "event_type": event["event_type"],
                "payload": event["payload"],
                "created_at": event["created_at"],
                "prev_hash": event["prev_hash"],
            })
            expected = hashlib.sha256(envelope.encode("utf-8")).hexdigest()
            if expected != event["event_hash"]:
                return False, count, last_hash
            if self._evidence_key is not None:
                if not event["event_mac"]:
                    return False, count, last_hash
                expected_mac = hmac.new(self._evidence_key, expected.encode("ascii"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected_mac, str(event["event_mac"])):
                    return False, count, last_hash
            prev_hash = event["event_hash"]
            last_hash = event["event_hash"]
            count += 1
        return True, count, last_hash

    def verify_evidence_chain(self, intent_id: str) -> bool:
        """Verify the per-intent hash chain (and, when keyed, its signed head).

        Fails closed: an unknown intent id is invalid rather than vacuously valid. The
        chain rows and the head row are read inside one read transaction so a
        concurrent append cannot produce a spurious tamper alarm.
        """
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                exists = self._conn.execute("SELECT 1 FROM intents WHERE intent_id=?", (intent_id,)).fetchone()
                events = self._evidence_rows_locked(intent_id)
                head = self._conn.execute(
                    "SELECT seq,head_hash,head_mac FROM evidence_head WHERE intent_id=?",
                    (intent_id,),
                ).fetchone()
            finally:
                self._conn.execute("COMMIT")
        if exists is None:
            return False

        ok, count, last_hash = self._verify_chain_rows(intent_id, events)
        if not ok:
            return False

        # Verify the signed head commitment to catch tail truncation and whole-chain
        # deletion. Only enforced when an evidence key is configured; without a key a
        # DB-level attacker can rewrite the head row too, so the chain-only guarantees
        # above are the ceiling. Every intent registered by this version owns a head
        # from birth, so "exists but has no events" is deletion, not an empty chain.
        # Rollback of the whole database to an older, validly signed snapshot is not
        # detectable without an external anchor (see THREAT_MODEL.md).
        if self._evidence_key is not None:
            if count == 0 or head is None or not head["head_mac"]:
                return False
            if int(head["seq"]) != count - 1 or str(head["head_hash"]) != last_hash:
                return False
            expected_head_mac = self._head_mac(intent_id, count - 1, str(last_hash))
            if not hmac.compare_digest(str(expected_head_mac), str(head["head_mac"])):
                return False
        return True
