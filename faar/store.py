from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
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
                grant_hash TEXT NOT NULL,
                grant_json TEXT NOT NULL,
                runtime_status TEXT NOT NULL CHECK(runtime_status IN ('ACTIVE','PAUSED','REVOKED')),
                provisioned_at TEXT NOT NULL,
                PRIMARY KEY(grant_id, version)
            );
            CREATE TABLE IF NOT EXISTS usage_reservations (
                intent_id TEXT PRIMARY KEY,
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
            CREATE TABLE IF NOT EXISTS intents (
                intent_id TEXT PRIMARY KEY,
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
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                intent_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                prev_hash TEXT,
                event_hash TEXT NOT NULL,
                event_mac TEXT,
                FOREIGN KEY(intent_id) REFERENCES intents(intent_id)
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

    def provision_grant(self, grant: CapabilityGrant, grant_hash: str) -> None:
        """Provision an immutable grant version from a separate authority domain."""
        payload = canonical_json(grant)
        with self.execution_guard(grant.grant_id, grant.version), self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT grant_hash FROM grants WHERE grant_id=? AND version=?",
                    (grant.grant_id, grant.version),
                ).fetchone()
                if row is None:
                    self._conn.execute(
                        "INSERT INTO grants(grant_id,version,grant_hash,grant_json,runtime_status,provisioned_at) VALUES(?,?,?,?,?,?)",
                        (grant.grant_id, grant.version, grant_hash, payload, grant.status.value, self._now()),
                    )
                elif row["grant_hash"] != grant_hash:
                    raise GrantConflict("grant_id/version already provisioned with a different capability envelope")
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def verify_grant(self, grant: CapabilityGrant, grant_hash: str) -> None:
        with self._lock:
            row = self._conn.execute(
                "SELECT grant_hash FROM grants WHERE grant_id=? AND version=?",
                (grant.grant_id, grant.version),
            ).fetchone()
            if row is None:
                raise UnknownGrant(f"grant {grant.grant_id}@{grant.version} is not provisioned")
            if row["grant_hash"] != grant_hash:
                raise GrantConflict("presented grant does not match provisioned capability envelope")

    def get_grant_status(self, grant_id: str, version: int) -> str:
        with self._lock:
            row = self._conn.execute(
                "SELECT runtime_status FROM grants WHERE grant_id=? AND version=?",
                (grant_id, version),
            ).fetchone()
            if row is None:
                raise UnknownGrant(f"grant {grant_id}@{version} is not provisioned")
            return str(row["runtime_status"])

    def set_grant_status(self, grant_id: str, version: int, status: str) -> None:
        if status not in {"ACTIVE", "PAUSED", "REVOKED"}:
            raise ValueError("invalid grant runtime status")
        # This guard is also held around adapter submission in FAARRuntime. The
        # linearization rule is explicit: an in-flight submission that acquired the
        # guard first may complete; once this method returns, no later submission can
        # begin under this grant version.
        with self.execution_guard(grant_id, version), self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT runtime_status FROM grants WHERE grant_id=? AND version=?",
                    (grant_id, version),
                ).fetchone()
                if row is None:
                    raise UnknownGrant(f"grant {grant_id}@{version} is not provisioned")
                current = str(row["runtime_status"])
                if current == "REVOKED" and status != "REVOKED":
                    raise GrantConflict("revoked grant versions cannot be reactivated; provision a new version")
                self._conn.execute(
                    "UPDATE grants SET runtime_status=? WHERE grant_id=? AND version=?",
                    (status, grant_id, version),
                )
                self._conn.execute("COMMIT")
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
                    "SELECT status FROM usage_reservations WHERE intent_id=?",
                    (intent.intent_id,),
                ).fetchone()
                if existing is not None:
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
                    "INSERT INTO risk_claims(grant_id,grant_version,risk_scope,state_version,intent_id,created_at) VALUES(?,?,?,?,?,?)",
                    (grant.grant_id, grant.version, risk.scope, risk.state_version, intent.intent_id, ts),
                )
                self._conn.execute(
                    "INSERT INTO usage_reservations(intent_id,grant_id,grant_version,day_key,velocity_bucket,amount_usd,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (intent.intent_id, grant.grant_id, grant.version, day_key, bucket, format(amount, "f"), "HELD", ts, ts),
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
                        "INSERT INTO intents(intent_id,intent_hash,state,intent_json,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                        (intent.intent_id, intent_hash, IntentState.PROPOSED.value, payload, now, now),
                    )
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
                self._conn.execute(
                    "INSERT INTO evidence(intent_id,event_type,payload_json,created_at,prev_hash,event_hash,event_mac) VALUES(?,?,?,?,?,?,?)",
                    (intent_id, event_type, payload_json, created_at, prev_hash, event_hash, event_mac),
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
