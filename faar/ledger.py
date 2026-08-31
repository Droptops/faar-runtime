"""Durable authority-ledger contract and SQLite reference implementation.

Postgres should implement the same operations with serializable transactions.
SQLite `BEGIN IMMEDIATE` is the reference fence, not a multi-region datastore.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Protocol

from .canonical import canonical_hash
from .models import SettlementStatus, utcnow
from .store import SQLiteIntentStore


class LedgerConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class EffectReceipt:
    intent_id: str
    principal_id: str
    effect_id: str
    permit_hash: str
    request_hash: str
    amount_usd: Decimal
    source_account: str
    beneficiary: str
    status: SettlementStatus
    recorded_at: datetime
    receipt_hash: str
    prev_receipt_hash: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", SettlementStatus(self.status))
        if self.amount_usd <= 0 or not self.amount_usd.is_finite():
            raise ValueError("receipt amount_usd must be a positive finite Decimal")


class AuthorityLedger(Protocol):
    store: SQLiteIntentStore

    def bind_account(self, principal_id: str, account_id: str) -> None: ...
    def get_account(self, principal_id: str) -> str | None: ...
    def set_balance(self, account_id: str, amount: Decimal) -> None: ...
    def get_balance(self, account_id: str) -> Decimal: ...
    def allow_beneficiary(self, account_id: str, beneficiary: str) -> None: ...
    def beneficiary_allowed(self, account_id: str, beneficiary: str) -> bool: ...
    def daily_spent(self, account_id: str, day_key: str) -> Decimal: ...
    def add_daily_spend(self, account_id: str, day_key: str, amount: Decimal) -> None: ...
    def record_lineage(
        self,
        *,
        permit_id: str,
        intent_id: str,
        grant_hash: str,
        authority_attestation_hash: str,
        risk_attestation_hash: str,
        issued_at: datetime,
    ) -> None: ...
    def get_receipt(self, intent_id: str) -> EffectReceipt | None: ...
    def commit_receipt(self, receipt: EffectReceipt) -> EffectReceipt: ...
    def transfer(self, *, source_account: str, beneficiary: str, amount: Decimal) -> None: ...
    def last_receipt_hash(self) -> str | None: ...


class SQLiteAuthorityLedger:
    """SQLite tables for v0.5 gateway/treasury state, sharing the intent-store file."""

    def __init__(self, store: SQLiteIntentStore) -> None:
        self.store = store
        with store._lock:
            store._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS account_bindings (
                    principal_id TEXT PRIMARY KEY,
                    account_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS treasury_accounts (
                    account_id TEXT PRIMARY KEY,
                    balance_usd TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS treasury_allowlist (
                    account_id TEXT NOT NULL,
                    beneficiary TEXT NOT NULL,
                    PRIMARY KEY(account_id, beneficiary)
                );
                CREATE TABLE IF NOT EXISTS treasury_daily_spend (
                    account_id TEXT NOT NULL,
                    day_key TEXT NOT NULL,
                    spent_usd TEXT NOT NULL,
                    PRIMARY KEY(account_id, day_key)
                );
                CREATE TABLE IF NOT EXISTS effect_receipts (
                    intent_id TEXT PRIMARY KEY,
                    principal_id TEXT NOT NULL,
                    effect_id TEXT NOT NULL UNIQUE,
                    permit_hash TEXT NOT NULL,
                    request_hash TEXT NOT NULL,
                    amount_usd TEXT NOT NULL,
                    source_account TEXT NOT NULL,
                    beneficiary TEXT NOT NULL,
                    status TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    receipt_hash TEXT NOT NULL,
                    prev_receipt_hash TEXT
                );
                CREATE TABLE IF NOT EXISTS authority_lineage (
                    permit_id TEXT PRIMARY KEY,
                    intent_id TEXT NOT NULL,
                    grant_hash TEXT NOT NULL,
                    authority_attestation_hash TEXT NOT NULL,
                    risk_attestation_hash TEXT NOT NULL,
                    issued_at TEXT NOT NULL
                );
                """
            )

    def bind_account(self, principal_id: str, account_id: str) -> None:
        with self.store._lock:
            self.store._conn.execute(
                "INSERT OR REPLACE INTO account_bindings(principal_id,account_id,created_at) VALUES(?,?,?)",
                (principal_id, account_id, utcnow().isoformat()),
            )

    def get_account(self, principal_id: str) -> str | None:
        with self.store._lock:
            row = self.store._conn.execute(
                "SELECT account_id FROM account_bindings WHERE principal_id=?",
                (principal_id,),
            ).fetchone()
        return None if row is None else row["account_id"]

    def set_balance(self, account_id: str, amount: Decimal) -> None:
        if amount < 0 or not amount.is_finite():
            raise ValueError("treasury balance must be finite and non-negative")
        with self.store._lock:
            self.store._conn.execute(
                "INSERT OR REPLACE INTO treasury_accounts(account_id,balance_usd,updated_at) VALUES(?,?,?)",
                (account_id, format(amount, "f"), utcnow().isoformat()),
            )

    def get_balance(self, account_id: str) -> Decimal:
        with self.store._lock:
            row = self.store._conn.execute(
                "SELECT balance_usd FROM treasury_accounts WHERE account_id=?",
                (account_id,),
            ).fetchone()
        if row is None:
            raise KeyError(account_id)
        return Decimal(row["balance_usd"])

    def allow_beneficiary(self, account_id: str, beneficiary: str) -> None:
        with self.store._lock:
            self.store._conn.execute(
                "INSERT OR IGNORE INTO treasury_allowlist(account_id,beneficiary) VALUES(?,?)",
                (account_id, beneficiary),
            )

    def beneficiary_allowed(self, account_id: str, beneficiary: str) -> bool:
        with self.store._lock:
            row = self.store._conn.execute(
                "SELECT 1 FROM treasury_allowlist WHERE account_id=? AND beneficiary=?",
                (account_id, beneficiary),
            ).fetchone()
        return row is not None

    def daily_spent(self, account_id: str, day_key: str) -> Decimal:
        with self.store._lock:
            row = self.store._conn.execute(
                "SELECT spent_usd FROM treasury_daily_spend WHERE account_id=? AND day_key=?",
                (account_id, day_key),
            ).fetchone()
        return Decimal("0") if row is None else Decimal(row["spent_usd"])

    def add_daily_spend(self, account_id: str, day_key: str, amount: Decimal) -> None:
        current = self.daily_spent(account_id, day_key)
        with self.store._lock:
            self.store._conn.execute(
                "INSERT OR REPLACE INTO treasury_daily_spend(account_id,day_key,spent_usd) VALUES(?,?,?)",
                (account_id, day_key, format(current + amount, "f")),
            )

    def record_lineage(
        self,
        *,
        permit_id: str,
        intent_id: str,
        grant_hash: str,
        authority_attestation_hash: str,
        risk_attestation_hash: str,
        issued_at: datetime,
    ) -> None:
        with self.store._lock:
            self.store._conn.execute(
                "INSERT OR REPLACE INTO authority_lineage(permit_id,intent_id,grant_hash,authority_attestation_hash,risk_attestation_hash,issued_at) VALUES(?,?,?,?,?,?)",
                (
                    permit_id, intent_id, grant_hash,
                    authority_attestation_hash, risk_attestation_hash,
                    issued_at.isoformat(),
                ),
            )

    def get_receipt(self, intent_id: str) -> EffectReceipt | None:
        with self.store._lock:
            row = self.store._conn.execute(
                "SELECT * FROM effect_receipts WHERE intent_id=?",
                (intent_id,),
            ).fetchone()
        if row is None:
            return None
        return EffectReceipt(
            intent_id=row["intent_id"],
            principal_id=row["principal_id"],
            effect_id=row["effect_id"],
            permit_hash=row["permit_hash"],
            request_hash=row["request_hash"],
            amount_usd=Decimal(row["amount_usd"]),
            source_account=row["source_account"],
            beneficiary=row["beneficiary"],
            status=row["status"],
            recorded_at=datetime.fromisoformat(row["recorded_at"]),
            receipt_hash=row["receipt_hash"],
            prev_receipt_hash=row["prev_receipt_hash"],
        )

    def last_receipt_hash(self) -> str | None:
        with self.store._lock:
            row = self.store._conn.execute(
                "SELECT receipt_hash FROM effect_receipts ORDER BY recorded_at DESC, receipt_hash DESC LIMIT 1"
            ).fetchone()
        return None if row is None else row["receipt_hash"]

    def commit_receipt(self, receipt: EffectReceipt) -> EffectReceipt:
        existing = self.get_receipt(receipt.intent_id)
        if existing is not None:
            if existing.effect_id != receipt.effect_id or existing.receipt_hash != receipt.receipt_hash:
                raise LedgerConflict("EFFECT_RECEIPT_CONFLICT")
            return existing
        with self.store._lock:
            self.store._conn.execute("BEGIN IMMEDIATE")
            try:
                self.store._conn.execute(
                    "INSERT INTO effect_receipts(intent_id,principal_id,effect_id,permit_hash,request_hash,amount_usd,source_account,beneficiary,status,recorded_at,receipt_hash,prev_receipt_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        receipt.intent_id, receipt.principal_id, receipt.effect_id,
                        receipt.permit_hash, receipt.request_hash, format(receipt.amount_usd, "f"),
                        receipt.source_account, receipt.beneficiary, receipt.status.value,
                        receipt.recorded_at.isoformat(), receipt.receipt_hash, receipt.prev_receipt_hash,
                    ),
                )
                self.store._conn.execute("COMMIT")
            except Exception:
                self.store._conn.execute("ROLLBACK")
                existing = self.get_receipt(receipt.intent_id)
                if existing is not None:
                    if existing.effect_id != receipt.effect_id:
                        raise LedgerConflict("EFFECT_RECEIPT_CONFLICT")
                    return existing
                raise
        return receipt

    def transfer(self, *, source_account: str, beneficiary: str, amount: Decimal) -> None:
        with self.store._lock:
            self.store._conn.execute("BEGIN IMMEDIATE")
            try:
                src = self.store._conn.execute(
                    "SELECT balance_usd FROM treasury_accounts WHERE account_id=?",
                    (source_account,),
                ).fetchone()
                dst = self.store._conn.execute(
                    "SELECT balance_usd FROM treasury_accounts WHERE account_id=?",
                    (beneficiary,),
                ).fetchone()
                if src is None or dst is None:
                    raise LedgerConflict("TREASURY_ACCOUNT_UNKNOWN")
                src_bal = Decimal(src["balance_usd"])
                if src_bal < amount:
                    raise LedgerConflict("TREASURY_INSUFFICIENT_FUNDS")
                now = utcnow().isoformat()
                self.store._conn.execute(
                    "UPDATE treasury_accounts SET balance_usd=?, updated_at=? WHERE account_id=?",
                    (format(src_bal - amount, "f"), now, source_account),
                )
                self.store._conn.execute(
                    "UPDATE treasury_accounts SET balance_usd=?, updated_at=? WHERE account_id=?",
                    (format(Decimal(dst["balance_usd"]) + amount, "f"), now, beneficiary),
                )
                self.store._conn.execute("COMMIT")
            except Exception:
                self.store._conn.execute("ROLLBACK")
                raise


def receipt_hash(payload: dict) -> str:
    return canonical_hash(payload)
