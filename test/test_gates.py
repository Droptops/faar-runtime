from __future__ import annotations

import unittest
from datetime import timedelta
from decimal import Decimal

from faar.gates import evaluate_capability, evaluate_risk
from faar.models import CapabilityGrant, CapabilityLimits, EconomicPrimitive, GrantStatus, Intent, RiskSnapshot, Verdict
from support import NOW


class GateTests(unittest.TestCase):
    def test_risk_source_disagreement_fails_closed(self):
        grant = CapabilityGrant(
            principal_id="principal:test",
            grant_id="g", version=1, actor_id="a", status=GrantStatus.ACTIVE,
            allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_venues=frozenset({"v"}),
            allowed_assets=frozenset({"AAA", "USD"}),
            limits=CapabilityLimits(
                max_order_usd=Decimal("100"), max_daily_turnover_usd=Decimal("1000"),
                max_actions_per_window=10, action_window_seconds=60,
            ),
        )
        intent = Intent(
            principal_id="principal:test",
            intent_id="intent_1234567890123456", actor_id="a", grant_id="g", grant_version=1,
            primitive=EconomicPrimitive.BUY, venue="v", created_at=NOW,
            expires_at=NOW + timedelta(minutes=1), payload={"amount_usd": "10"},
        )
        risk = RiskSnapshot(observed_at=NOW, data_complete=True, source_count=2, sources_agree=False)
        decision = evaluate_risk(intent, grant, risk, NOW)
        self.assertEqual(Verdict.DEFER, decision.verdict)
        self.assertIn("RISK_SOURCES_CONTRADICTORY", decision.reason_codes)

    def test_nonfinite_risk_value_fails_closed(self):
        grant = CapabilityGrant(
            principal_id="principal:test",
            grant_id="g", version=1, actor_id="a", status=GrantStatus.ACTIVE,
            allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_venues=frozenset({"v"}),
            allowed_assets=frozenset({"AAA", "USD"}),
            limits=CapabilityLimits(
                max_order_usd=Decimal("100"), max_position_usd=Decimal("100"),
                max_daily_turnover_usd=Decimal("1000"), max_actions_per_window=10,
                action_window_seconds=60,
            ),
        )
        intent = Intent(
            principal_id="principal:test",
            intent_id="intent_nonfinite_000001", actor_id="a", grant_id="g", grant_version=1,
            primitive=EconomicPrimitive.BUY, venue="v", created_at=NOW,
            expires_at=NOW + timedelta(seconds=10), payload={"amount_usd": "10"},
        )
        risk = RiskSnapshot(observed_at=NOW, position_after_usd=Decimal("NaN"))
        decision = evaluate_risk(intent, grant, risk, NOW)
        self.assertEqual(Verdict.DEFER, decision.verdict)
        self.assertIn("POSITION_AFTER_USD_NONFINITE", decision.reason_codes)

    def test_money_moving_grant_cannot_be_unbounded(self):
        with self.assertRaisesRegex(ValueError, "max_order_usd"):
            CapabilityGrant(
                principal_id="principal:test",
                grant_id="g-unbounded-order", version=1, actor_id="a", status=GrantStatus.ACTIVE,
                allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_venues=frozenset({"v"}),
                allowed_assets=frozenset({"AAA", "USD"}),
                limits=CapabilityLimits(
                    max_daily_turnover_usd=Decimal("1000"),
                    max_actions_per_window=10, action_window_seconds=60,
                ),
            )

        with self.assertRaisesRegex(ValueError, "max_daily_turnover_usd"):
            CapabilityGrant(
                principal_id="principal:test",
                grant_id="g-unbounded-daily", version=1, actor_id="a", status=GrantStatus.ACTIVE,
                allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_venues=frozenset({"v"}),
                allowed_assets=frozenset({"AAA", "USD"}),
                limits=CapabilityLimits(
                    max_order_usd=Decimal("100"),
                    max_actions_per_window=10, action_window_seconds=60,
                ),
            )

    def test_grant_requires_explicit_scope_and_velocity(self):
        with self.assertRaisesRegex(ValueError, "allowed_assets"):
            CapabilityGrant(
                principal_id="principal:test",
                grant_id="g-no-assets", version=1, actor_id="a", status=GrantStatus.ACTIVE,
                allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_venues=frozenset({"v"}),
                limits=CapabilityLimits(
                    max_order_usd=Decimal("100"), max_daily_turnover_usd=Decimal("1000"),
                    max_actions_per_window=10, action_window_seconds=60,
                ),
            )
        with self.assertRaisesRegex(ValueError, "allowed_targets"):
            CapabilityGrant(
                principal_id="principal:test",
                grant_id="g-no-targets", version=1, actor_id="a", status=GrantStatus.ACTIVE,
                allowed_primitives=frozenset({EconomicPrimitive.SWAP}), allowed_venues=frozenset({"v"}),
                allowed_assets=frozenset({"AAA", "USD"}),
                limits=CapabilityLimits(
                    max_order_usd=Decimal("100"), max_daily_turnover_usd=Decimal("1000"),
                    max_actions_per_window=10, action_window_seconds=60,
                ),
            )
        with self.assertRaisesRegex(ValueError, "max_actions_per_window"):
            CapabilityGrant(
                principal_id="principal:test",
                grant_id="g-no-velocity", version=1, actor_id="a", status=GrantStatus.ACTIVE,
                allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_venues=frozenset({"v"}),
                allowed_assets=frozenset({"AAA", "USD"}),
                limits=CapabilityLimits(
                    max_order_usd=Decimal("100"), max_daily_turnover_usd=Decimal("1000"),
                ),
            )


    def test_falsy_asset_value_is_validated_against_allowlist(self):
        # A falsy-but-present asset value (integer 0) must not slip past the
        # allowed_assets scope by being treated as absent.
        grant = CapabilityGrant(
            principal_id="principal:test",
            grant_id="g", version=1, actor_id="a", status=GrantStatus.ACTIVE,
            allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_venues=frozenset({"v"}),
            allowed_assets=frozenset({"BTC", "USD"}),
            limits=CapabilityLimits(
                max_order_usd=Decimal("100"), max_daily_turnover_usd=Decimal("1000"),
                max_actions_per_window=10, action_window_seconds=60,
            ),
        )
        intent = Intent(
            principal_id="principal:test",
            intent_id="intent_falsy_asset_00001", actor_id="a", grant_id="g", grant_version=1,
            primitive=EconomicPrimitive.BUY, venue="v", created_at=NOW,
            expires_at=NOW + timedelta(seconds=10),
            payload={"base_asset": 0, "quote_asset": "USD", "amount_usd": "10"},
        )
        decision = evaluate_capability(intent, grant, NOW)
        self.assertEqual(Verdict.DENY, decision.verdict)
        self.assertTrue(any(r.startswith("ASSET_NOT_ALLOWED") for r in decision.reason_codes))

    def test_falsy_target_value_hits_denied_targets(self):
        # A falsy-but-present target (integer 0) must still be checked against
        # denied_targets rather than coalescing to None and skipping the check.
        grant = CapabilityGrant(
            principal_id="principal:test",
            grant_id="g", version=1, actor_id="a", status=GrantStatus.ACTIVE,
            allowed_primitives=frozenset({EconomicPrimitive.BUY}), allowed_venues=frozenset({"v"}),
            allowed_assets=frozenset({"BTC", "USD"}), denied_targets=frozenset({"0"}),
            limits=CapabilityLimits(
                max_order_usd=Decimal("100"), max_daily_turnover_usd=Decimal("1000"),
                max_actions_per_window=10, action_window_seconds=60,
            ),
        )
        intent = Intent(
            principal_id="principal:test",
            intent_id="intent_falsy_target_0001", actor_id="a", grant_id="g", grant_version=1,
            primitive=EconomicPrimitive.BUY, venue="v", created_at=NOW,
            expires_at=NOW + timedelta(seconds=10),
            payload={"base_asset": "BTC", "quote_asset": "USD", "amount_usd": "10", "target": 0},
        )
        decision = evaluate_capability(intent, grant, NOW)
        self.assertEqual(Verdict.DENY, decision.verdict)
        self.assertIn("TARGET_DENIED", decision.reason_codes)


if __name__ == "__main__":
    unittest.main()
