"""Spawn worker for v0.5 executor isolation. Must not import faar.signing."""
from __future__ import annotations

import gc
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from faar.executor import executor_from_files
from faar.parsing import parse_execution_request, parse_signed_permit

NOW = datetime(2026, 8, 30, 18, 0, tzinfo=timezone.utc)


def run(job, conn) -> None:
    executor = executor_from_files(
        db=job["db"],
        descriptors_path=job["descriptors"],
        daily_budget_usd="500",
        allow_test_time_override=True,
    )
    permit = parse_signed_permit(json.loads(Path(job["permit"]).read_text()))
    request = parse_execution_request(json.loads(Path(job["request"]).read_text()))
    receipt = executor.submit(request, permit, now=NOW)
    private_keys = [obj for obj in gc.get_objects() if isinstance(obj, Ed25519PrivateKey)]
    conn.send({
        "effect_id": receipt.effect_id,
        "amount": format(receipt.amount_usd, "f"),
        "private_key_objects": len(private_keys),
        "signing_imported": "faar.signing" in sys.modules,
        "authority_imported": "faar.authority_service" in sys.modules,
    })
