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
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Iterable, Iterator

from .anchor import AnchorUnavailable, AuthorityAnchor, AuthorityRegression, regressed
from .canonical import canonical_json, parse_bounded_decimal
from .models import CapabilityGrant, Intent, IntentState, MONETARY_PRIMITIVES, RiskSnapshot

GLOBAL_CONTROL_SCOPE = "global"
PRINCIPAL_CONTROL_PREFIX = "principal:"


# Trailing window used for the atomic "daily" turnover reservation. A calendar-day
# bucket would let up to 2x the cap fire across midnight (the same defect RT-39
# fixed for action velocity); a trailing window is strictly more conservative.
TURNOVER_WINDOW_SECONDS = 86_400
# Ambiguity window granted to in-flight rows written by a version that did not
# persist permit expiry (pre-0.4). Generous relative to the 5 s default permit TTL.
LEGACY_AMBIGUITY_WINDOW_SECONDS = 60

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
    # ISO timestamp until which a submission attempt may still be acted on by the
    # venue (the permit expiry of an in-flight, ambiguous attempt). Absence of an
    # effect is not authoritative before this instant has passed.
    ambiguity_until: str | None = None


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


class MigrationError(RuntimeError):
    """A database written by an older version cannot be brought to the current invariants safely."""


class AuthorityAnchorRequired(RuntimeError):
    """The database is bound to an authority anchor; an instance opened without one cannot consume or change authority."""


class PermitConflict(RuntimeError):
    """A new permit would overlap a permit for the same intent that the venue can still consume."""


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

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        evidence_key: bytes | None = None,
        authority_anchor: AuthorityAnchor | None = None,
    ) -> None:
        self.path = str(path)
        # Optional external high-water mark of consumed authority; see faar.anchor.
        self._anchor = authority_anchor
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
                ambiguity_until TEXT,
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
            CREATE TABLE IF NOT EXISTS runtime_controls (
                scope TEXT PRIMARY KEY,
                halted INTEGER NOT NULL CHECK(halted IN (0,1)),
                reason TEXT,
                control_epoch INTEGER NOT NULL DEFAULT 1,
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
                expires_at TEXT,
                consumed_at TEXT,
                voided_at TEXT,
                UNIQUE(grant_id, grant_version, fence_token)
            );
            CREATE TABLE IF NOT EXISTS store_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS exposure_caps (
                scope TEXT PRIMARY KEY,
                max_turnover_usd TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        self._migrate_columns()
        self._create_dependent_indexes()
        self._bind_anchor_setting()

    def _bind_anchor_setting(self) -> None:
        """Remember durably that this database runs under an authority anchor.

        Once bound, an instance opened without an anchor (a misconfigured worker,
        an operator command that forgot `--anchor`) cannot issue, consume, or
        change authority: every such path would otherwise advance the database
        past the anchor unrecorded and make a later restore undetectable.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if self._anchor is not None:
                    self._conn.execute(
                        "INSERT INTO store_settings(key,value,updated_at) VALUES('anchor_required','1',?) "
                        "ON CONFLICT(key) DO UPDATE SET value='1', updated_at=excluded.updated_at",
                        (self._now(),),
                    )
                row = self._conn.execute("SELECT value FROM store_settings WHERE key='anchor_required'").fetchone()
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        self._anchor_required = row is not None and str(row["value"]) == "1"

    @property
    def anchor_required(self) -> bool:
        return self._anchor_required

    @property
    def has_anchor(self) -> bool:
        return self._anchor is not None

    def _anchor_missing(self) -> bool:
        return self._anchor_required and self._anchor is None

    def _require_anchor(self) -> None:
        if self._anchor_missing():
            raise AuthorityAnchorRequired(
                "this database is bound to an authority anchor; open the store with the same anchor"
            )

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
        ("intents", "ambiguity_until", "TEXT"),
        ("evidence", "event_mac", "TEXT"),
        ("evidence", "principal_id", "TEXT NOT NULL DEFAULT 'legacy:unknown'"),
        ("grants", "principal_id", "TEXT NOT NULL DEFAULT 'legacy:unknown'"),
        ("grants", "runtime_epoch", "INTEGER NOT NULL DEFAULT 1"),
        ("grants", "fence_counter", "INTEGER NOT NULL DEFAULT 0"),
        ("usage_reservations", "principal_id", "TEXT NOT NULL DEFAULT 'legacy:unknown'"),
        ("usage_reservations", "velocity_ts", "INTEGER"),
        ("risk_claims", "principal_id", "TEXT NOT NULL DEFAULT 'legacy:unknown'"),
        ("execution_permits", "consumed_at", "TEXT"),
        ("execution_permits", "expires_at", "TEXT"),
        ("execution_permits", "voided_at", "TEXT"),
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
                self._backfill_legacy_rows_locked()
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    @staticmethod
    def _parse_timestamp(value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)

    def _backfill_legacy_rows_locked(self) -> None:
        """Give rows written by older versions the values current invariants rely on.

        Caller owns the migration transaction. Every step is idempotent and fails
        closed: a row that cannot be brought into the current model makes the
        database unopenable by this version rather than silently exempt.
        """
        # Per-venue effect identity (I-11) only protects rows that sit in their real
        # venue namespace; a column default of '' would leave every legacy effect
        # claimable again by a new intent at the same venue.
        for row in self._conn.execute("SELECT intent_id,intent_json FROM intents WHERE venue=''").fetchall():
            try:
                venue = json.loads(row["intent_json"]).get("venue")
            except (ValueError, AttributeError):
                venue = None
            if not isinstance(venue, str) or not venue:
                raise MigrationError(f"intent {row['intent_id']} has no venue in its canonical payload; refusing to open")
            self._conn.execute("UPDATE intents SET venue=? WHERE intent_id=?", (venue, row["intent_id"]))
        # Sliding-window velocity counts rows by `velocity_ts`; legacy rows count
        # from their creation instant instead of vanishing from the window.
        for row in self._conn.execute("SELECT intent_id,created_at FROM usage_reservations WHERE velocity_ts IS NULL").fetchall():
            created = self._parse_timestamp(row["created_at"])
            if created is None:
                raise MigrationError(f"usage reservation for {row['intent_id']} has an unreadable created_at; refusing to open")
            self._conn.execute(
                "UPDATE usage_reservations SET velocity_ts=? WHERE intent_id=?", (int(created.timestamp()), row["intent_id"])
            )
        # An in-flight attempt that holds a permit whose expiry was never recorded
        # (a pre-0.4 worker) gets a conservative window so a new worker cannot trust
        # absence and resubmit while the venue may still honour that permit. Rows
        # without such a permit (including a 0.4 crash between begin_submission
        # and the permit record) transported nothing and need no window.
        for row in self._conn.execute(
            "SELECT i.intent_id,i.updated_at FROM intents i WHERE i.ambiguity_until IS NULL AND i.submission_count > 0 "
            "AND i.state IN ('SUBMITTED','UNKNOWN','RECONCILING') "
            "AND EXISTS (SELECT 1 FROM execution_permits p WHERE p.intent_id=i.intent_id AND p.expires_at IS NULL AND p.consumed_at IS NULL)"
        ).fetchall():
            updated = self._parse_timestamp(row["updated_at"])
            if updated is None:
                raise MigrationError(f"intent {row['intent_id']} has an unreadable updated_at; refusing to open")
            until = updated + timedelta(seconds=LEGACY_AMBIGUITY_WINDOW_SECONDS)
            self._conn.execute("UPDATE intents SET ambiguity_until=? WHERE intent_id=?", (until.isoformat(), row["intent_id"]))

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
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS ix_usage_principal_velocity_ts "
                    "ON usage_reservations(principal_id, velocity_ts, status)"
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

    def checkpoint(self) -> None:
        """Fold the WAL into the main database file.

        Operators must call this (or close every connection) before copying the
        file for a backup; a bare copy of a WAL-mode database misses every
        transaction still in the write-ahead log.
        """
        with self._lock:
            self._execute_with_busy_retry("PRAGMA wal_checkpoint(TRUNCATE)")

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
        self._require_anchor()
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
            if row is None:
                self._anchor_record(grant.grant_id, grant.version, 1, 0)

    # ---- external authority anchor -------------------------------------------------

    def _anchor_regressed(self, grant_id: str, version: int, epoch: int, fence: int) -> bool:
        """True when the row is behind its anchor. Raises AnchorUnavailable if the anchor cannot answer."""
        if self._anchor is None:
            return False
        try:
            mark = self._anchor.high_water(grant_id, version)
        except AnchorUnavailable:
            raise
        except Exception as exc:
            raise AnchorUnavailable(f"authority anchor failed: {type(exc).__name__}: {exc}") from exc
        return regressed((int(epoch), int(fence)), mark)

    def _anchor_record(self, grant_id: str, version: int, epoch: int, fence: int) -> None:
        if self._anchor is None:
            return
        try:
            self._anchor.record(grant_id, version, int(epoch), int(fence))
        except AnchorUnavailable:
            raise
        except Exception as exc:
            raise AnchorUnavailable(f"authority anchor failed: {type(exc).__name__}: {exc}") from exc

    def revoke_after_restore(self, grant_id: str, version: int) -> tuple[int, int]:
        """Operator-only recovery for a grant version whose authority state regressed.

        A restored database cannot know which permits and risk states were consumed
        in the lost history, so the only safe continuation is to close that grant
        version: its epoch is advanced past the anchored high-water mark (killing
        every permit ever issued under it) and it is REVOKED. New authority requires
        a new grant version. Returns the new (epoch, fence_counter).
        """
        self._require_anchor()
        with self.execution_guard(grant_id, version), self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT runtime_epoch,fence_counter FROM grants WHERE grant_id=? AND version=?",
                    (grant_id, version),
                ).fetchone()
                if row is None:
                    raise UnknownGrant(f"grant {grant_id}@{version} is not provisioned")
                mark = self._anchor.high_water(grant_id, version) if self._anchor is not None else None
                epoch = max(int(row["runtime_epoch"]), mark[0] if mark else 0) + 1
                fence = max(int(row["fence_counter"]), mark[1] if mark else 0)
                self._conn.execute(
                    "UPDATE grants SET runtime_status='REVOKED', runtime_epoch=?, fence_counter=? WHERE grant_id=? AND version=?",
                    (epoch, fence, grant_id, version),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            if self._anchor is not None:
                self._anchor.reset(grant_id, version, epoch, fence)
            return epoch, fence

    # ---- emergency controls (kill switch) ------------------------------------------

    @staticmethod
    def _validate_control_scope(scope: str) -> str | None:
        """Returns the principal for a principal scope, None for the global scope."""
        if scope == GLOBAL_CONTROL_SCOPE:
            return None
        if isinstance(scope, str) and scope.startswith(PRINCIPAL_CONTROL_PREFIX) and len(scope) > len(PRINCIPAL_CONTROL_PREFIX):
            return scope[len(PRINCIPAL_CONTROL_PREFIX):]
        raise ValueError("control scope must be 'global' or 'principal:<principal_id>'")

    def _active_halt_locked(self, principal_id: str) -> str | None:
        row = self._conn.execute(
            "SELECT scope FROM runtime_controls WHERE halted=1 AND (scope=? OR scope=?) "
            "ORDER BY CASE WHEN scope=? THEN 0 ELSE 1 END LIMIT 1",
            (GLOBAL_CONTROL_SCOPE, PRINCIPAL_CONTROL_PREFIX + principal_id, GLOBAL_CONTROL_SCOPE),
        ).fetchone()
        return None if row is None else str(row["scope"])

    def halt(self, scope: str, *, reason: str) -> int:
        """Emergency stop for every grant in `scope` ('global' or 'principal:<id>').

        Marks the scope halted and advances the runtime epoch of every affected grant
        in the same transaction, so permits already issued cannot be consumed even
        after `resume`. The per-grant in-process fence is deliberately not awaited:
        an emergency stop must complete while an adapter call is hung; the epoch
        check at permit consumption is the fence for in-flight attempts. Returns the
        number of grant versions fenced.
        """
        principal = self._validate_control_scope(scope)
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("a halt reason is required")
        self._require_anchor()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                now = self._now()
                self._conn.execute(
                    "INSERT INTO runtime_controls(scope,halted,reason,control_epoch,updated_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(scope) DO UPDATE SET halted=1, reason=excluded.reason, "
                    "control_epoch=runtime_controls.control_epoch+1, updated_at=excluded.updated_at",
                    (scope, 1, reason, 1, now),
                )
                if principal is None:
                    cur = self._conn.execute("UPDATE grants SET runtime_epoch=runtime_epoch+1")
                    rows = self._conn.execute("SELECT grant_id,version,runtime_epoch,fence_counter FROM grants").fetchall()
                else:
                    cur = self._conn.execute("UPDATE grants SET runtime_epoch=runtime_epoch+1 WHERE principal_id=?", (principal,))
                    rows = self._conn.execute(
                        "SELECT grant_id,version,runtime_epoch,fence_counter FROM grants WHERE principal_id=?", (principal,)
                    ).fetchall()
                fenced = cur.rowcount
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        for row in rows:
            self._anchor_record(str(row["grant_id"]), int(row["version"]), int(row["runtime_epoch"]), int(row["fence_counter"]))
        return fenced

    def resume(self, scope: str) -> None:
        """Lift a halt. Permits issued before the halt stay dead (their epoch is gone)."""
        self._validate_control_scope(scope)
        self._require_anchor()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    "UPDATE runtime_controls SET halted=0, control_epoch=control_epoch+1, updated_at=? WHERE scope=?",
                    (self._now(), scope),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"no control record for scope {scope!r}")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def controls(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM runtime_controls ORDER BY scope").fetchall()
        return [dict(r) for r in rows]

    # ---- exposure caps ---------------------------------------------------------------

    def set_exposure_cap(self, scope: str, max_turnover_usd: Decimal | None) -> None:
        """Operator ceiling on trailing-window turnover for a scope, independent of grants.

        `scope` is 'global' or 'principal:<id>'. The cap counts every HELD and
        COMMITTED reservation in the scope inside the trailing turnover window, so
        it bounds what the whole fleet can move through FAAR even if every grant
        is generous. `None` clears the cap. Tightening and loosening are both
        authority changes and require the anchor on an anchored database.
        """
        self._validate_control_scope(scope)
        self._require_anchor()
        if max_turnover_usd is not None:
            parsed = parse_bounded_decimal(max_turnover_usd)
            if parsed is None or parsed <= 0:
                raise ValueError("max_turnover_usd must be a positive bounded amount")
            max_turnover_usd = parsed
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if max_turnover_usd is None:
                    self._conn.execute("DELETE FROM exposure_caps WHERE scope=?", (scope,))
                else:
                    self._conn.execute(
                        "INSERT INTO exposure_caps(scope,max_turnover_usd,updated_at) VALUES(?,?,?) "
                        "ON CONFLICT(scope) DO UPDATE SET max_turnover_usd=excluded.max_turnover_usd, updated_at=excluded.updated_at",
                        (scope, format(max_turnover_usd, "f"), self._now()),
                    )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def exposure_caps(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM exposure_caps ORDER BY scope").fetchall()
        return [dict(r) for r in rows]

    def _exposure_caps_locked(self, principal_id: str) -> list[tuple[str, Decimal]]:
        rows = self._conn.execute(
            "SELECT scope,max_turnover_usd FROM exposure_caps WHERE scope=? OR scope=?",
            (GLOBAL_CONTROL_SCOPE, PRINCIPAL_CONTROL_PREFIX + principal_id),
        ).fetchall()
        return [(str(r["scope"]), Decimal(str(r["max_turnover_usd"]))) for r in rows]

    def _scope_turnover_locked(self, scope: str, principal_id: str, since_ts: int) -> Decimal:
        if scope == GLOBAL_CONTROL_SCOPE:
            rows = self._conn.execute(
                "SELECT amount_usd FROM usage_reservations WHERE status IN ('HELD','COMMITTED') AND velocity_ts > ?",
                (since_ts,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT amount_usd FROM usage_reservations WHERE principal_id=? AND status IN ('HELD','COMMITTED') AND velocity_ts > ?",
                (principal_id, since_ts),
            ).fetchall()
        return sum((Decimal(r["amount_usd"]) for r in rows), Decimal("0"))

    def is_halted(self, principal_id: str) -> str | None:
        with self._lock:
            return self._active_halt_locked(principal_id)

    # ---- operator queries ----------------------------------------------------------

    def list_grants(self, *, principal_id: str | None = None) -> list[dict]:
        with self._lock:
            if principal_id is None:
                rows = self._conn.execute(
                    "SELECT grant_id,version,principal_id,grant_hash,runtime_status,runtime_epoch,fence_counter,provisioned_at "
                    "FROM grants ORDER BY principal_id,grant_id,version"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT grant_id,version,principal_id,grant_hash,runtime_status,runtime_epoch,fence_counter,provisioned_at "
                    "FROM grants WHERE principal_id=? ORDER BY grant_id,version",
                    (principal_id,),
                ).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item["effective_status"] = self.get_grant_control(item["principal_id"], item["grant_id"], int(item["version"]))[0]
            out.append(item)
        return out

    def list_intents(
        self,
        *,
        state: IntentState | str | None = None,
        principal_id: str | None = None,
        limit: int = 200,
    ) -> list[StoredIntent]:
        clauses, params = [], []
        if state is not None:
            clauses.append("state=?")
            params.append(IntentState(state).value)
        if principal_id is not None:
            clauses.append("principal_id=?")
            params.append(principal_id)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"SELECT intent_id FROM intents{where} ORDER BY updated_at DESC LIMIT ?", (*params, int(limit))
            ).fetchall()
        return [self.get(str(r["intent_id"])) for r in rows]

    def held_usage(self, *, principal_id: str | None = None) -> list[dict]:
        """HELD reservations joined to their intent state; the budget an operator may be waiting on."""
        with self._lock:
            sql = (
                "SELECT u.intent_id,u.principal_id,u.grant_id,u.grant_version,u.amount_usd,u.created_at,i.state,i.submission_count,i.ambiguity_until "
                "FROM usage_reservations u JOIN intents i ON i.intent_id=u.intent_id WHERE u.status='HELD'"
            )
            params: tuple = ()
            if principal_id is not None:
                sql += " AND u.principal_id=?"
                params = (principal_id,)
            rows = self._conn.execute(sql + " ORDER BY u.created_at", params).fetchall()
        return [dict(r) for r in rows]

    def list_leases(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM intent_leases ORDER BY acquired_at").fetchall()
        return [dict(r) for r in rows]

    def void_unconsumed_permits(self, intent_id: str) -> int:
        """Kill every permit of the intent the venue has not consumed. Returns the count.

        Called by the runtime before it acts on authoritative absence (release or
        retry). Voiding and consumption are both single-row transactions, so either
        the venue consumed first (and the runtime then sees `permit_counts`
        consumed > 0) or the void wins and a late consumption is refused with
        `PERMIT_VOIDED`, independent of any clock.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                cur = self._conn.execute(
                    "UPDATE execution_permits SET voided_at=? WHERE intent_id=? AND consumed_at IS NULL AND voided_at IS NULL",
                    (self._now(), intent_id),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
        return int(cur.rowcount or 0)

    def voided_permit_count(self, intent_id: str) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS n FROM execution_permits WHERE intent_id=? AND voided_at IS NOT NULL", (intent_id,)
            ).fetchone()
        return int(row["n"] or 0)

    def permit_counts(self, intent_id: str) -> tuple[int, int]:
        """(issued, consumed) execution permits recorded for one intent."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) AS issued, SUM(CASE WHEN consumed_at IS NOT NULL THEN 1 ELSE 0 END) AS consumed "
                "FROM execution_permits WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
        return int(row["issued"] or 0), int(row["consumed"] or 0)

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
        """Effective runtime status of a grant version plus its epoch and fence counter.

        The effective status folds in the emergency controls and the external
        authority anchor: REGRESSED (datastore older than anchored authority) and
        HALTED (scope kill switch) are reported like any other non-ACTIVE status, so
        every caller that requires ACTIVE fails closed without special cases.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT principal_id,runtime_status,runtime_epoch,fence_counter FROM grants WHERE grant_id=? AND version=?",
                (grant_id, version),
            ).fetchone()
            if row is None:
                raise UnknownGrant(f"grant {grant_id}@{version} is not provisioned")
            if str(row["principal_id"]) != principal_id:
                raise GrantConflict("grant principal mismatch")
            status, epoch, fence = str(row["runtime_status"]), int(row["runtime_epoch"]), int(row["fence_counter"])
            halted = self._active_halt_locked(principal_id) is not None
        if self._anchor_missing():
            return "ANCHOR_REQUIRED", epoch, fence
        try:
            if self._anchor_regressed(grant_id, version, epoch, fence):
                return "REGRESSED", epoch, fence
        except AnchorUnavailable:
            return "ANCHOR_UNAVAILABLE", epoch, fence
        if status == "ACTIVE" and halted:
            return "HALTED", epoch, fence
        return status, epoch, fence

    def get_grant_status(self, principal_id: str, grant_id: str, version: int) -> str:
        return self.get_grant_control(principal_id, grant_id, version)[0]

    def set_grant_status(self, principal_id: str, grant_id: str, version: int, status: str) -> None:
        if status not in {"ACTIVE", "PAUSED", "REVOKED"}:
            raise ValueError("invalid grant runtime status")
        # v0.3: runtime_epoch is the distributed revocation fence. Every actual
        # lifecycle change increments it, invalidating permits issued under the
        # previous epoch even in another process.
        self._require_anchor()
        with self.execution_guard(grant_id, version), self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT principal_id,runtime_status,runtime_epoch,fence_counter FROM grants WHERE grant_id=? AND version=?",
                    (grant_id, version),
                ).fetchone()
                if row is None:
                    raise UnknownGrant(f"grant {grant_id}@{version} is not provisioned")
                if str(row["principal_id"]) != principal_id:
                    raise GrantConflict("grant principal mismatch")
                if self._anchor_regressed(grant_id, version, int(row["runtime_epoch"]), int(row["fence_counter"])):
                    raise AuthorityRegression(
                        f"grant {grant_id}@{version} authority state is older than its anchor; use revoke_after_restore"
                    )
                current = str(row["runtime_status"])
                if current == "REVOKED" and status != "REVOKED":
                    raise GrantConflict("revoked grant versions cannot be reactivated; provision a new version")
                new_epoch = int(row["runtime_epoch"])
                if current != status:
                    new_epoch += 1
                    self._conn.execute(
                        "UPDATE grants SET runtime_status=?, runtime_epoch=? WHERE grant_id=? AND version=?",
                        (status, new_epoch, grant_id, version),
                    )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            self._anchor_record(grant_id, version, new_epoch, int(row["fence_counter"]))

    def next_execution_fence(self, grant: CapabilityGrant) -> tuple[int, int]:
        """Atomically allocate a monotonically increasing fence for an ACTIVE grant.

        The fence counter is the per-grant-version count of authority events: it
        advances here (issuance) and again at consumption, and both values are
        pushed to the authority anchor.
        """
        self._require_anchor()
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
                if self._active_halt_locked(grant.principal_id) is not None:
                    raise GrantConflict("grant scope is halted")
                if self._anchor_regressed(grant.grant_id, grant.version, int(row["runtime_epoch"]), int(row["fence_counter"])):
                    raise GrantConflict("grant authority state regressed behind its anchor")
                counter = int(row["fence_counter"]) + 1
                epoch = int(row["runtime_epoch"])
                self._conn.execute(
                    "UPDATE grants SET fence_counter=? WHERE grant_id=? AND version=?",
                    (counter, grant.grant_id, grant.version),
                )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            self._anchor_record(grant.grant_id, grant.version, epoch, counter)
            return epoch, counter

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

    def _live_permits_locked(self, intent_id: str, grant: CapabilityGrant, now: datetime) -> list[str]:
        """Unconsumed permits for the intent that a venue may still accept at `now`."""
        skew = timedelta(seconds=grant.limits.max_clock_skew_seconds)
        live: list[str] = []
        for row in self._conn.execute(
            "SELECT permit_id,expires_at FROM execution_permits WHERE intent_id=? AND consumed_at IS NULL AND voided_at IS NULL AND expires_at IS NOT NULL",
            (intent_id,),
        ).fetchall():
            expires = self._parse_timestamp(row["expires_at"])
            if expires is not None and expires + skew > now:
                live.append(str(row["permit_id"]))
        return live

    def record_execution_permit(
        self,
        permit_id: str,
        intent: Intent,
        grant: CapabilityGrant,
        grant_epoch: int,
        fence_token: int,
        permit_hash: str,
        *,
        expires_at: datetime | None = None,
        now: datetime | None = None,
    ) -> None:
        """Record an issued permit and, atomically, the intent's ambiguity window.

        `expires_at` becomes the intent's `ambiguity_until` in the same transaction:
        from the moment a permit exists the venue may act on it, so absence of an
        effect is not authoritative until it has expired, whatever the adapter
        later reports (receipt, deterministic failure, exception, or nothing).
        With `now`, issuance is refused while an earlier permit for the same intent
        is still live (`PermitConflict`): one live permit per intent is the
        structural form of I-30.
        """
        if expires_at is not None and (expires_at.tzinfo is None or expires_at.utcoffset() is None):
            raise ValueError("expires_at must be timezone-aware")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                if now is not None:
                    live = self._live_permits_locked(intent.intent_id, grant, now)
                    if live:
                        raise PermitConflict(f"intent {intent.intent_id} already has a live permit: {live[0]}")
                self._conn.execute(
                    "INSERT INTO execution_permits(permit_id,intent_id,principal_id,grant_id,grant_version,grant_epoch,fence_token,permit_hash,issued_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        permit_id, intent.intent_id, intent.principal_id, grant.grant_id, grant.version, grant_epoch,
                        fence_token, permit_hash, self._now(), expires_at.isoformat() if expires_at is not None else None,
                    ),
                )
                if expires_at is not None:
                    self._conn.execute(
                        "UPDATE intents SET ambiguity_until=? WHERE intent_id=?",
                        (expires_at.isoformat(), intent.intent_id),
                    )
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

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
                    "SELECT rowid,* FROM execution_permits WHERE permit_id=?", (permit_id,)
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
                if row["voided_at"] is not None:
                    # The runtime acted on authoritative absence after this permit's
                    # window: whatever the venue's clock says, it is dead.
                    self._conn.execute("COMMIT")
                    return False, ("PERMIT_VOIDED",)
                # A later permit for the same intent supersedes this one: the runtime
                # only issues a retry permit once this one can no longer be honoured,
                # so a venue whose clock lags must still refuse it.
                superseded = self._conn.execute(
                    "SELECT 1 FROM execution_permits WHERE intent_id=? AND rowid > ? LIMIT 1",
                    (str(row["intent_id"]), int(row["rowid"])),
                ).fetchone()
                if superseded is not None:
                    self._conn.execute("COMMIT")
                    return False, ("PERMIT_SUPERSEDED",)

                grant_row = self._conn.execute(
                    "SELECT principal_id,runtime_status,runtime_epoch,fence_counter FROM grants WHERE grant_id=? AND version=?",
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
                if self._active_halt_locked(principal_id) is not None:
                    reasons.append("PERMIT_HALTED")
                if self._anchor_missing():
                    reasons.append("PERMIT_ANCHOR_REQUIRED")
                else:
                    try:
                        if self._anchor_regressed(grant_id, grant_version, int(grant_row["runtime_epoch"]), int(grant_row["fence_counter"])):
                            reasons.append("PERMIT_AUTHORITY_REGRESSED")
                    except AnchorUnavailable:
                        reasons.append("PERMIT_ANCHOR_UNAVAILABLE")
                if reasons:
                    self._conn.execute("COMMIT")
                    return False, tuple(reasons)

                self._conn.execute(
                    "UPDATE execution_permits SET consumed_at=? WHERE permit_id=? AND consumed_at IS NULL",
                    (self._now(), permit_id),
                )
                # Consumption is consumed authority: advance the fence counter so the
                # anchor also detects a restore taken between issuance and consumption.
                self._conn.execute(
                    "UPDATE grants SET fence_counter=fence_counter+1 WHERE grant_id=? AND version=?",
                    (grant_id, grant_version),
                )
                new_fence = int(self._conn.execute(
                    "SELECT fence_counter FROM grants WHERE grant_id=? AND version=?", (grant_id, grant_version)
                ).fetchone()["fence_counter"])
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            self._anchor_record(grant_id, grant_version, grant_epoch, new_fence)
            return True, ()

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

                # Scope exposure caps (operator control, independent of any grant).
                for scope, cap in self._exposure_caps_locked(intent.principal_id):
                    current = self._scope_turnover_locked(scope, intent.principal_id, velocity_ts - TURNOVER_WINDOW_SECONDS)
                    if current + amount > cap:
                        reasons.append("EXPOSURE_CAP_EXCEEDED")
                        break

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
            ambiguity_until=row["ambiguity_until"],
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
        commit_usage: bool = False,
        ambiguity_until: datetime | None = None,
    ) -> bool:
        """Compare-and-set the intent state.

        `release_usage=True` releases the intent's HELD reservation in the same
        transaction. Terminalizing and releasing as two autocommit statements leaves
        a crash window in which a provably never-submitted intent keeps consuming the
        grant's turnover and velocity budget forever. `commit_usage=True` commits it
        in the same transaction for the same reason on the FINALIZED path.

        `ambiguity_until` records the instant after which an in-flight submission can
        no longer be acted on by the venue (its permit expiry). Reconciliation must
        not treat absence as authoritative before it.
        """
        expected_set = {expected} if isinstance(expected, IntentState) else set(expected)
        if effect_id is not None and not isinstance(effect_id, str):
            raise ValueError("effect_id must be a string")
        if release_usage and commit_usage:
            raise ValueError("a transition cannot both release and commit usage")
        if ambiguity_until is not None and (ambiguity_until.tzinfo is None or ambiguity_until.utcoffset() is None):
            raise ValueError("ambiguity_until must be timezone-aware")
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
                if ambiguity_until is not None:
                    self._conn.execute(
                        "UPDATE intents SET ambiguity_until=? WHERE intent_id=?",
                        (ambiguity_until.isoformat(), intent_id),
                    )
                if release_usage:
                    self._conn.execute(
                        "UPDATE usage_reservations SET status='RELEASED', updated_at=? WHERE intent_id=? AND status='HELD'",
                        (ts, intent_id),
                    )
                if commit_usage:
                    self._conn.execute(
                        "UPDATE usage_reservations SET status='COMMITTED', updated_at=? WHERE intent_id=? AND status='HELD'",
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
                # A new attempt begins only after any previous attempt's ambiguity
                # window has closed, so the window is reset for this attempt.
                self._conn.execute(
                    "UPDATE intents SET state=?, submission_count=?, reason_codes='[]', ambiguity_until=NULL, updated_at=? WHERE intent_id=?",
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

    def assert_evidence_appendable(self, intent_id: str) -> None:
        """Raise `EvidenceIntegrityError` if the next append to this chain would be refused.

        The runtime calls this before it advances state so that a chain the store
        will not extend (legacy chain without a head, truncated tail) yields a
        machine-readable stop instead of a state transition without evidence.
        """
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                tail = self._conn.execute(
                    "SELECT COUNT(*) AS n, MAX(id) AS last_id FROM evidence WHERE intent_id=?", (intent_id,)
                ).fetchone()
                count = int(tail["n"])
                prev_hash = None
                if count:
                    prev_hash = self._conn.execute("SELECT event_hash FROM evidence WHERE id=?", (tail["last_id"],)).fetchone()["event_hash"]
                self._check_head_matches_tail(intent_id, count, prev_hash)
            finally:
                self._conn.execute("COMMIT")

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

    def rebuild_evidence_head(self, intent_id: str, *, allow_empty: bool = False) -> bool:
        """Operator-only migration: commit a head over a chain that predates head rows.

        Never called by the runtime. Requires the evidence key (which only the trusted
        runtime/operator holds) and refuses when the chain itself does not verify, so
        it cannot be used to launder a tampered prefix. A chain with zero events is
        refused unless `allow_empty` is set, in which case the adoption itself is
        recorded as the chain's first (keyed) event.
        """
        if self._evidence_key is None:
            raise ValueError("rebuild_evidence_head requires an evidence key")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                principal = self._conn.execute("SELECT principal_id FROM intents WHERE intent_id=?", (intent_id,)).fetchone()
                if principal is None:
                    raise KeyError(intent_id)
                if self._conn.execute("SELECT 1 FROM evidence_head WHERE intent_id=?", (intent_id,)).fetchone() is not None:
                    self._conn.execute("COMMIT")
                    return False
                rows = self._evidence_rows_locked(intent_id)
                ok, count, last_hash = self._verify_chain_rows(intent_id, rows)
                if ok and count == 0 and allow_empty:
                    self._append_evidence_in_txn(
                        intent_id, str(principal["principal_id"]), "evidence_head_adopted",
                        {"prior_events": 0, "operator_migration": True},
                    )
                    self._conn.execute("COMMIT")
                    return True
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

    def rebuild_evidence_heads(self, *, allow_empty: bool = False) -> dict[str, str]:
        """Operator-only bulk form of `rebuild_evidence_head` for a database upgrade.

        Returns one outcome per intent that had no head: `committed`,
        `adopted_empty`, `skipped_empty` or `refused:<detail>`.
        """
        with self._lock:
            missing = [
                str(r["intent_id"]) for r in self._conn.execute(
                    "SELECT intent_id FROM intents WHERE intent_id NOT IN (SELECT intent_id FROM evidence_head) ORDER BY intent_id"
                ).fetchall()
            ]
        outcomes: dict[str, str] = {}
        for intent_id in missing:
            try:
                events = len(self.evidence(intent_id))
                if events == 0 and not allow_empty:
                    outcomes[intent_id] = "skipped_empty"
                    continue
                self.rebuild_evidence_head(intent_id, allow_empty=allow_empty)
                outcomes[intent_id] = "adopted_empty" if events == 0 else "committed"
            except EvidenceIntegrityError as exc:
                outcomes[intent_id] = f"refused:{exc}"
        return outcomes

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
        return bool(self.evidence_status(intent_id)["valid"])

    def evidence_status(self, intent_id: str) -> dict:
        """Verify the per-intent hash chain (and, when keyed, its signed head).

        Fails closed: an unknown intent id is invalid rather than vacuously valid. The
        chain rows and the head row are read inside one read transaction so a
        concurrent append cannot produce a spurious tamper alarm. The `status`
        field distinguishes a pre-head legacy chain (`head_missing`, remedied by
        `rebuild_evidence_head`) from tampering (`chain_invalid`, `head_mismatch`).
        """
        keyed = self._evidence_key is not None

        def result(status: str, count: int) -> dict:
            return {"valid": status == "ok", "status": status, "events": count, "keyed": keyed}

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
            return result("unknown_intent", 0)

        ok, count, last_hash = self._verify_chain_rows(intent_id, events)
        if not ok:
            return result("chain_invalid", count)

        # Verify the signed head commitment to catch tail truncation and whole-chain
        # deletion. Only enforced when an evidence key is configured; without a key a
        # DB-level attacker can rewrite the head row too, so the chain-only guarantees
        # above are the ceiling. Every intent registered by this version owns a head
        # from birth, so "exists but has no events" is deletion, not an empty chain.
        # Rollback of the whole database to an older, validly signed snapshot is not
        # detectable without an external anchor (see THREAT_MODEL.md).
        if self._evidence_key is not None:
            if head is None:
                return result("chain_empty" if count == 0 else "head_missing", count)
            if count == 0 or not head["head_mac"]:
                return result("head_mismatch", count)
            if int(head["seq"]) != count - 1 or str(head["head_hash"]) != last_hash:
                return result("head_mismatch", count)
            expected_head_mac = self._head_mac(intent_id, count - 1, str(last_hash))
            if not hmac.compare_digest(str(expected_head_mac), str(head["head_mac"])):
                return result("head_mismatch", count)
        return result("ok", count)
