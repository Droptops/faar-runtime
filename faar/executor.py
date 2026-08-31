"""Verify-only execution plane.

This module must not import signer implementations or signing-key providers.
It constructs verifiers from serialized public descriptors and submits through
ExecutionGateway.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from decimal import Decimal
from pathlib import Path

from .descriptors import VerifierDescriptor, load_descriptor_bundle
from .gateway import ExecutionGateway, GatewayDenial, GatewayLimits
from .ledger import SQLiteAuthorityLedger
from .models import utcnow
from .parsing import parse_execution_request, parse_signed_permit
from .store import SQLiteIntentStore
from .treasury import MockTreasuryAdapter

# Import graph invariant: do not import faar.signing or faar.authority_service.


class VerifyOnlyExecutor:
    def __init__(
        self,
        ledger: SQLiteAuthorityLedger,
        descriptors: tuple[VerifierDescriptor, ...],
        *,
        daily_budget_usd: Decimal,
        clock=utcnow,
        allow_test_time_override: bool = False,
        treasury_mode: str = "SUCCESS",
    ) -> None:
        adapter = MockTreasuryAdapter(ledger, clock=clock, mode=treasury_mode)
        self.gateway = ExecutionGateway(
            ledger,
            descriptors,
            adapter,
            limits=GatewayLimits(daily_budget_usd=daily_budget_usd),
            clock=clock,
            allow_test_time_override=allow_test_time_override,
        )
        self.adapter = adapter

    def submit(self, request, permit, *, now: datetime | None = None):
        return self.gateway.submit(request, permit, now=now)


def executor_from_files(
    *,
    db: str,
    descriptors_path: str,
    daily_budget_usd: str = "500",
    allow_test_time_override: bool = False,
    treasury_mode: str = "SUCCESS",
) -> VerifyOnlyExecutor:
    store = SQLiteIntentStore(db)
    ledger = SQLiteAuthorityLedger(store)
    payload = json.loads(Path(descriptors_path).read_text())
    descriptors = load_descriptor_bundle(payload)
    return VerifyOnlyExecutor(
        ledger,
        descriptors,
        daily_budget_usd=Decimal(daily_budget_usd),
        allow_test_time_override=allow_test_time_override,
        treasury_mode=treasury_mode,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="faar-executor", description="FAAR verify-only execution plane")
    parser.add_argument("command", choices=["submit"])
    parser.add_argument("--db", required=True)
    parser.add_argument("--descriptors", required=True)
    parser.add_argument("--permit", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--daily-budget", default="500")
    parser.add_argument("--allow-test-time", action="store_true")
    parser.add_argument("--now", default=None)
    args = parser.parse_args(argv)
    executor = executor_from_files(
        db=args.db,
        descriptors_path=args.descriptors,
        daily_budget_usd=args.daily_budget,
        allow_test_time_override=args.allow_test_time,
    )
    permit = parse_signed_permit(json.loads(Path(args.permit).read_text()))
    request = parse_execution_request(json.loads(Path(args.request).read_text()))
    now = datetime.fromisoformat(args.now) if args.now else None
    try:
        receipt = executor.submit(request, permit, now=now)
    except GatewayDenial as exc:
        print(json.dumps({"ok": False, "reasons": list(exc.reasons)}))
        return 2
    print(json.dumps({
        "ok": True,
        "intent_id": receipt.intent_id,
        "effect_id": receipt.effect_id,
        "amount_usd": format(receipt.amount_usd, "f"),
        "beneficiary": receipt.beneficiary,
        "receipt_hash": receipt.receipt_hash,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
