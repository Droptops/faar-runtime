from __future__ import annotations

import tempfile
import unittest
from datetime import timedelta
from decimal import Decimal

from faar.canonical import canonical_hash
from faar.models import CapabilityGrant, CapabilityLimits, EconomicPrimitive, GrantStatus, Intent, IntentState, RiskSnapshot
from faar.paper import PaperTradingVenue
from faar.runtime import FAARRuntime
from faar.settlement import MockSettlementVerifier
from faar.permits import ConstrainedPermitAuthority, ExecutionPermitVerifier
from faar.store import SQLiteIntentStore

from support import AUTH, NOW, PRINCIPAL, attest_pair, trust, verification_trust, permit_stack


class PaperVenueTests(unittest.TestCase):
    def setUp(self):
        f = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False); f.close()
        self.store = SQLiteIntentStore(f.name)
        self.grant = CapabilityGrant(
            principal_id=PRINCIPAL,
            grant_id="g-paper", version=1, actor_id="agent:q", status=GrantStatus.ACTIVE,
            allowed_primitives=frozenset({EconomicPrimitive.SWAP}),
            allowed_venues=frozenset({"paper-dex"}),
            allowed_assets=frozenset({"USDC", "MEME"}),
            allowed_targets=frozenset({"paper-router"}),
            limits=CapabilityLimits(
                max_order_usd=Decimal("75"), max_position_usd=Decimal("250"),
                max_daily_turnover_usd=Decimal("500"), max_daily_loss_usd=Decimal("100"),
                max_slippage_bps=75, max_price_impact_bps=100, max_market_data_age_seconds=10,
                max_risk_snapshot_age_seconds=5, max_intent_ttl_seconds=30,
                max_actions_per_window=20, action_window_seconds=60,
            ),
        )
        self.store.provision_grant(self.grant, canonical_hash(self.grant))
        self.trust = trust()
        self.permit_authority, self.permit_verifier = permit_stack(self.store, self.trust)
        self.venue = PaperTradingVenue(
            name="paper-dex", prices_usd={"MEME": Decimal("0.50")},
            permit_verifier=self.permit_verifier, clock=lambda: NOW, balances={"USDC": Decimal("1000")}
        )
        self.settlement = MockSettlementVerifier(self.venue)
        self.runtime = FAARRuntime(
            self.store, {"paper-dex": self.venue}, verification_trust(self.trust), self.permit_authority,
            {"paper-dex": self.settlement}, allow_test_time_override=True
        )
        self.risk = RiskSnapshot(
            observed_at=NOW, position_after_usd=Decimal("50"), daily_turnover_after_usd=Decimal("50"),
            daily_loss_usd=Decimal("0"), market_data_age_seconds=1,
            requested_slippage_bps=25, price_impact_bps=10, source_count=2, sources_agree=True,
        )

    def tearDown(self):
        self.store.close()

    def execute_case(self, i):
        aa, ra = attest_pair(self.trust, i, AUTH, self.risk)
        return self.runtime.process(
            i, AUTH, self.grant, self.risk,
            authority_attestation=aa, risk_attestation=ra, now=NOW,
        )

    def test_authorized_swap_changes_paper_balances_once(self):
        i = Intent(
            principal_id=PRINCIPAL,
            intent_id="paper_intent_00000000001", actor_id="agent:q", grant_id="g-paper", grant_version=1,
            primitive=EconomicPrimitive.SWAP, venue="paper-dex", created_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
            payload={"from_asset": "USDC", "to_asset": "MEME", "amount_usd": "50", "target": "paper-router"},
        )
        result = self.execute_case(i)
        self.assertEqual(IntentState.FINALIZED, result.state)
        self.assertEqual(Decimal("950"), self.venue.balances["USDC"])
        self.assertEqual(Decimal("100"), self.venue.balances["MEME"])
        self.execute_case(i)
        self.assertEqual(Decimal("950"), self.venue.balances["USDC"])
        self.assertEqual(Decimal("100"), self.venue.balances["MEME"])

    def test_insufficient_balance_fails_safe_and_releases_usage(self):
        self.venue.balances["USDC"] = Decimal("1")
        i = Intent(
            principal_id=PRINCIPAL,
            intent_id="paper_intent_00000000002", actor_id="agent:q", grant_id="g-paper", grant_version=1,
            primitive=EconomicPrimitive.SWAP, venue="paper-dex", created_at=NOW,
            expires_at=NOW + timedelta(seconds=30),
            payload={"from_asset": "USDC", "to_asset": "MEME", "amount_usd": "50", "target": "paper-router"},
        )
        result = self.execute_case(i)
        self.assertEqual(IntentState.FAILED_SAFE, result.state)
        usage = self.store.usage("g-paper", 1)
        self.assertEqual("RELEASED", usage[0]["status"])
        self.assertEqual(0, self.venue.successful_effect_count(i.intent_id))


if __name__ == "__main__":
    unittest.main()
