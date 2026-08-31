from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator

from .canonical import canonical_json
from .models import CapabilityGrant, Intent, IntentState, RiskSnapshot


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
    - UNIQUE(intent_id) binds one logical intent to one canonical payload.
    - BEGIN IMMEDIATE serializes grant-wide usage reservation in this reference DB.
    - compare-and-set state transitions prevent concurrent workers from submitting the
      same intent simultaneously.
    - per-grant execution guards make revocation linearizable inside one runtime
      process: once set_grant_status(..., REVOKED) returns, no later submission may
      begin under that grant version.
    - optional evidence HMACs detect database-only rewriting of the hash chain.

    A production distributed store must reproduce these semantics; SQLite itself is
    not the claimed production architecture.
    """

    def __init__(self, path: str | Path = ":memory:", *, evidence_key: bytes | None = None) -> None:
        self.path = str(path)
        self._lock = threading.RLock()
        self._grant_lock_guard = threading.Lock()
        self._grant_locks: dict[tuple[str, int], threading.RLock] = {}
        self._intent_lock_guard = threading.Lock()
        self._intent_locks: dict[str, threading.RLock] = {}
        self._intent_guard_local = threading.local()
        self._instance_id = uuid.uuid4().hex
        self._evidence_key = bytes(evidence_key) if evidence_key is not None else None
        if self._evidence_key is not None and len(self._evidence_key) < 16:
            raise ValueError("evidence_key must be at least 16 bytes")

        self._conn = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = FULL")
        self._conn.execute("PRAGMA busy_timeout = 30000")
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
                intent_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                intent_json TEXT NOT NULL,
                effect_id TEXT,
                reason_codes TEXT NOT NULL DEFAULT '[]',
                submission_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_effect_id_nonnull
              ON intents(effect_id) WHERE effect_id IS NOT NULL;
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

    def _migrate_columns(self) -> None:
        with self._lock:
            intent_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(intents)").fetchall()}
            if "submission_count" not in intent_cols:
                self._conn.execute("ALTER TABLE intents ADD COLUMN submission_count INTEGER NOT NULL DEFAULT 0")
            evidence_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(evidence)").fetchall()}
            if "event_mac" not in evidence_cols:
                self._conn.execute("ALTER TABLE evidence ADD COLUMN event_mac TEXT")
            grant_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(grants)").fetchall()}
            if "principal_id" not in grant_cols:
                self._conn.execute("ALTER TABLE grants ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy:unknown'")
            if "runtime_epoch" not in grant_cols:
                self._conn.execute("ALTER TABLE grants ADD COLUMN runtime_epoch INTEGER NOT NULL DEFAULT 1")
            if "fence_counter" not in grant_cols:
                self._conn.execute("ALTER TABLE grants ADD COLUMN fence_counter INTEGER NOT NULL DEFAULT 0")
            usage_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(usage_reservations)").fetchall()}
            if "principal_id" not in usage_cols:
                self._conn.execute("ALTER TABLE usage_reservations ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy:unknown'")
            risk_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(risk_claims)").fetchall()}
            if "principal_id" not in risk_cols:
                self._conn.execute("ALTER TABLE risk_claims ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy:unknown'")
            intent_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(intents)").fetchall()}
            if "principal_id" not in intent_cols:
                self._conn.execute("ALTER TABLE intents ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy:unknown'")
            evidence_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(evidence)").fetchall()}
            if "principal_id" not in evidence_cols:
                self._conn.execute("ALTER TABLE evidence ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy:unknown'")
            permit_cols = {row["name"] for row in self._conn.execute("PRAGMA table_info(execution_permits)").fetchall()}
            if "consumed_at" not in permit_cols:
                self._conn.execute("ALTER TABLE execution_permits ADD COLUMN consumed_at TEXT")

    def close(self) -> None:
        self._conn.close()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _grant_lock(self, grant_id: str, version: int) -> threading.RLock:
        key = (grant_id, version)
        with self._grant_lock_guard:
            lock = self._grant_locks.get(key)
            if lock is None:
                lock = threading.RLock()
                self._grant_locks[key] = lock
            return lock

    @contextmanager
    def execution_guard(self, grant_id: str, version: int) -> Iterator[None]:
        lock = self._grant_lock(grant_id, version)
        with lock:
            yield

    def _intent_lock(self, intent_id: str) -> threading.RLock:
        with self._intent_lock_guard:
            lock = self._intent_locks.get(intent_id)
            if lock is None:
                lock = threading.RLock()
                self._intent_locks[intent_id] = lock
            return lock

    @contextmanager
    def intent_guard(self, intent_id: str, *, wait_seconds: float = 5.0) -> Iterator[None]:
        """Serialize one intent's state machine across threads and processes.

        The database lease deliberately has no automatic TTL. If a process dies while
        owning it, subsequent workers fail-stuck with `IntentBusy`; an operator must
        reconcile external settlement and explicitly clear the stale lease. Automatic
        time-based takeover would reintroduce duplicate-execution risk.
        """
        local_lock = self._intent_lock(intent_id)
        with local_lock:
            active = getattr(self._intent_guard_local, "active", set())
            if intent_id in active:
                yield
                return

            owner = f"{self._instance_id}:{threading.get_ident()}"
            deadline = time.monotonic() + max(wait_seconds, 0.0)
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

    def reserve_usage(self, intent: Intent, grant: CapabilityGrant, risk: RiskSnapshot, now: datetime) -> tuple[bool, tuple[str, ...]]:
        """Atomically reserve grant-level turnover and action velocity.

        HELD reservations count against limits until reconciliation proves no effect
        and the reservation is explicitly released. This intentionally sacrifices
        availability under ambiguity to prevent concurrent oversubscription.
        """
        from decimal import Decimal, InvalidOperation

        raw = intent.payload.get("amount_usd", intent.payload.get("notional_usd", "0"))
        try:
            amount = Decimal(str(raw))
        except (InvalidOperation, ValueError, TypeError):
            amount = Decimal("0")
        if not amount.is_finite() or amount < 0:
            amount = Decimal("0")

        day_key = now.astimezone(timezone.utc).date().isoformat()
        bucket = None
        if grant.limits.action_window_seconds:
            bucket = int(now.timestamp()) // grant.limits.action_window_seconds

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
                max_claim = self._conn.execute(
                    "SELECT MAX(state_version) AS v FROM risk_claims WHERE grant_id=? AND grant_version=? AND risk_scope=?",
                    (grant.grant_id, grant.version, risk.scope),
                ).fetchone()["v"]
                if max_claim is not None and risk.state_version < int(max_claim):
                    reasons.append("RISK_STATE_VERSION_NOT_MONOTONIC")
                if grant.limits.max_daily_turnover_usd is not None:
                    rows = self._conn.execute(
                        "SELECT amount_usd FROM usage_reservations WHERE grant_id=? AND grant_version=? AND day_key=? AND status IN ('HELD','COMMITTED')",
                        (grant.grant_id, grant.version, day_key),
                    ).fetchall()
                    current = sum((Decimal(r["amount_usd"]) for r in rows), Decimal("0"))
                    if current + amount > grant.limits.max_daily_turnover_usd:
                        reasons.append("ATOMIC_DAILY_TURNOVER_EXCEEDED")

                if grant.limits.max_actions_per_window is not None and bucket is not None:
                    count = self._conn.execute(
                        "SELECT COUNT(*) AS n FROM usage_reservations WHERE grant_id=? AND grant_version=? AND velocity_bucket=? AND status IN ('HELD','COMMITTED')",
                        (grant.grant_id, grant.version, bucket),
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
                    "INSERT INTO usage_reservations(intent_id,principal_id,grant_id,grant_version,day_key,velocity_bucket,amount_usd,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (intent.intent_id, intent.principal_id, grant.grant_id, grant.version, day_key, bucket, format(amount, "f"), "HELD", ts, ts),
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
                        "INSERT INTO intents(intent_id,principal_id,intent_hash,state,intent_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                        (intent.intent_id, intent.principal_id, intent_hash, IntentState.PROPOSED.value, payload, now, now),
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
            raise KeyError(intent_id)
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
    ) -> bool:
        expected_set = {expected} if isinstance(expected, IntentState) else set(expected)
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
                self._conn.execute(
                    "UPDATE intents SET state=?, effect_id=?, reason_codes=?, updated_at=? WHERE intent_id=?",
                    (new_state.value, final_effect, json.dumps(list(reason_codes)), self._now(), intent_id),
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

    def add_evidence(self, intent_id: str, event_type: str, payload: dict) -> str:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                last = self._conn.execute(
                    "SELECT event_hash FROM evidence WHERE intent_id=? ORDER BY id DESC LIMIT 1",
                    (intent_id,),
                ).fetchone()
                prev_hash = last["event_hash"] if last else None
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
                principal = self._conn.execute("SELECT principal_id FROM intents WHERE intent_id=?", (intent_id,)).fetchone()
                if principal is None:
                    raise KeyError(intent_id)
                self._conn.execute(
                    "INSERT INTO evidence(intent_id,principal_id,event_type,payload_json,created_at,prev_hash,event_hash,event_mac) VALUES(?,?,?,?,?,?,?,?)",
                    (intent_id, principal["principal_id"], event_type, payload_json, created_at, prev_hash, event_hash, event_mac),
                )
                self._conn.execute("COMMIT")
                return event_hash
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def evidence(self, intent_id: str) -> list[dict]:
        with self._lock:
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

    def verify_evidence_chain(self, intent_id: str) -> bool:
        prev_hash = None
        for event in self.evidence(intent_id):
            if event["prev_hash"] != prev_hash:
                return False
            envelope = canonical_json({
                "intent_id": intent_id,
                "event_type": event["event_type"],
                "payload": event["payload"],
                "created_at": event["created_at"],
                "prev_hash": event["prev_hash"],
            })
            expected = hashlib.sha256(envelope.encode("utf-8")).hexdigest()
            if expected != event["event_hash"]:
                return False
            if self._evidence_key is not None:
                if not event["event_mac"]:
                    return False
                expected_mac = hmac.new(self._evidence_key, expected.encode("ascii"), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected_mac, str(event["event_mac"])):
                    return False
            prev_hash = event["event_hash"]
        return True
