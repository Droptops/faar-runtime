from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from faar.canonical import canonical_hash
from faar.models import (
    CapabilityGrant,
    CapabilityLimits,
    EconomicPrimitive,
    GrantStatus,
    Intent,
    RiskSnapshot,
)
from faar.store import SQLiteIntentStore

PRINCIPAL = "principal:test"
EVIDENCE_KEY = b"evidence-test-key-32-bytes-long!!!!!"


def _velocity_grant() -> CapabilityGrant:
    return CapabilityGrant(
        principal_id=PRINCIPAL,
        grant_id="g", version=1, actor_id="a", status=GrantStatus.ACTIVE,
        allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_venues=frozenset({"v"}),
        allowed_assets=frozenset({"BTC", "USD"}),
        limits=CapabilityLimits(
            max_order_usd=Decimal("100"), max_daily_turnover_usd=Decimal("1000"),
            max_actions_per_window=1, action_window_seconds=100, max_slippage_bps=100,
        ),
    )


def _intent(intent_id: str, created_at: datetime) -> Intent:
    return Intent(
        principal_id=PRINCIPAL,
        intent_id=intent_id, actor_id="a", grant_id="g", grant_version=1,
        primitive=EconomicPrimitive.BUY, venue="v", created_at=created_at,
        expires_at=created_at + timedelta(seconds=30),
        payload={"base_asset": "BTC", "quote_asset": "USD", "notional_usd": "10"},
    )


class VelocityWindowTests(unittest.TestCase):
    def test_velocity_limit_is_sliding_not_tumbling(self):
        # limit = 1 action / 100s. Two reservations 1 second apart that straddle a
        # fixed tumbling-bucket boundary must NOT both succeed.
        store = SQLiteIntentStore(":memory:")
        grant = _velocity_grant()
        store.provision_grant(grant, canonical_hash(grant))
        # timestamp % 100 == 99, so t and t+1s fall in adjacent tumbling buckets.
        t0 = datetime(2026, 1, 1, 0, 1, 39, tzinfo=timezone.utc)
        t1 = t0 + timedelta(seconds=1)

        i0, i1 = _intent("intent_vel_0000000000001", t0), _intent("intent_vel_0000000000002", t1)
        store.register(i0, canonical_hash(i0))
        store.register(i1, canonical_hash(i1))

        ok0, _ = store.reserve_usage(i0, grant, RiskSnapshot(observed_at=t0, state_version=1), t0)
        ok1, reasons1 = store.reserve_usage(i1, grant, RiskSnapshot(observed_at=t1, state_version=2), t1)
        self.assertTrue(ok0)
        self.assertFalse(ok1)
        self.assertIn("ATOMIC_ACTION_VELOCITY_EXCEEDED", reasons1)

    def test_velocity_action_ages_out_of_window(self):
        # An action older than the window no longer counts against the limit.
        store = SQLiteIntentStore(":memory:")
        grant = _velocity_grant()
        store.provision_grant(grant, canonical_hash(grant))
        t0 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(seconds=101)

        i0, i1 = _intent("intent_vel_0000000000003", t0), _intent("intent_vel_0000000000004", t1)
        store.register(i0, canonical_hash(i0))
        store.register(i1, canonical_hash(i1))

        ok0, _ = store.reserve_usage(i0, grant, RiskSnapshot(observed_at=t0, state_version=1), t0)
        ok1, _ = store.reserve_usage(i1, grant, RiskSnapshot(observed_at=t1, state_version=2), t1)
        self.assertTrue(ok0)
        self.assertTrue(ok1)


class EvidenceHeadCommitmentTests(unittest.TestCase):
    def _seed(self, evidence_key):
        store = SQLiteIntentStore(":memory:", evidence_key=evidence_key)
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        i = Intent(
            principal_id=PRINCIPAL, intent_id="intent_evi_0000000000001", actor_id="a",
            grant_id="g", grant_version=1, primitive=EconomicPrimitive.PAY, venue="v",
            created_at=now, expires_at=now + timedelta(seconds=60),
            payload={"asset": "USDC", "amount_usd": "10", "target": "t"},
        )
        store.register(i, canonical_hash(i))
        for n in range(4):
            store.add_evidence(i.intent_id, f"event_{n}", {"n": n})
        return store, i.intent_id

    def test_keyed_chain_valid_for_intact_evidence(self):
        store, intent_id = self._seed(EVIDENCE_KEY)
        self.assertTrue(store.verify_evidence_chain(intent_id))

    def test_keyed_head_commitment_detects_tail_truncation(self):
        store, intent_id = self._seed(EVIDENCE_KEY)
        store._conn.execute(
            "DELETE FROM evidence WHERE id IN (SELECT id FROM evidence WHERE intent_id=? ORDER BY id DESC LIMIT 2)",
            (intent_id,),
        )
        self.assertFalse(store.verify_evidence_chain(intent_id))

    def test_keyed_head_commitment_detects_full_deletion(self):
        store, intent_id = self._seed(EVIDENCE_KEY)
        store._conn.execute("DELETE FROM evidence WHERE intent_id=?", (intent_id,))
        self.assertFalse(store.verify_evidence_chain(intent_id))

    def test_unkeyed_chain_verifies_prefix_only(self):
        # Without an evidence key the chain cannot detect tail truncation; document
        # that ceiling so the guarantee is not silently assumed.
        store, intent_id = self._seed(None)
        self.assertTrue(store.verify_evidence_chain(intent_id))
        store._conn.execute(
            "DELETE FROM evidence WHERE id IN (SELECT id FROM evidence WHERE intent_id=? ORDER BY id DESC LIMIT 2)",
            (intent_id,),
        )
        self.assertTrue(store.verify_evidence_chain(intent_id))


if __name__ == "__main__":
    unittest.main()
