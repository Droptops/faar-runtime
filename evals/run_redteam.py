#!/usr/bin/env python3
"""Targeted red-team regression matrix for FAAR v0.3.

The unit suite contains the detailed assertions. This script produces a compact,
reviewer-facing readout of the attack classes the implementation currently blocks.
"""

from __future__ import annotations

import json
import subprocess
import sys


ATTACK_CLASSES = [
    "forged authority attestation",
    "risk attestation replay across intents",
    "expired attestation",
    "raw transaction/calldata injection",
    "NaN/non-finite numeric payload",
    "stale and contradictory risk evidence",
    "duplicate intent with changed payload",
    "same risk-state version consumed by two intents",
    "concurrent turnover oversubscription",
    "timeout after economic effect",
    "non-authoritative NONE reconciliation",
    "retry after intent expiry",
    "risk change before resubmission",
    "settled result without effect identity",
    "effect identity changes during reconciliation",
    "same effect identity claimed by two intents",
    "revocation race at submission boundary",
    "grant-envelope substitution",
    "database evidence-MAC tampering",
    "agent rewrite of signed definition-of-done criteria",
    "mutable nested intent payload TOCTOU",
    "ordered-tuple canonical hash collision",
    "parser type-coercion / stringified boolean bypass",
    "authorization/risk expires while waiting on submission fence",
    "crash after budget reservation before state transition",
    "attestation signing-key role confusion",
    "caller-controlled security-clock rollback",
    "unknown execution-field confused-deputy smuggling",
    "target allowlist bypass by omission",
    "adapter missing exactly-once semantic contract",
    "model metadata leakage into execution adapter",
    "provision-time PAUSED vs mutable runtime lifecycle mismatch",
    "unbounded monetary grant construction",
    "extreme-decimal canonicalization resource exhaustion",
    "non-authoritative positive settlement claim",
    "settled amount exceeds authorized economic envelope",
    "non-authoritative settlement used to declare task done",
    "expired signed task-contract reuse",
    "adapter evidence shadowing normalized settlement fields",
    "future-dated signed task-contract use",
    "PAY settlement amount under/over-match",
    "execution permit request-hash broadening",
    "stale permit after pause/revoke epoch change",
    "single-use permit replay at capability gateway",
    "symmetric/private permit key leakage into execution gateway",
    "fresh retry risk-state reuse by another intent",
    "submitter receipt self-finalization",
    "settlement request-binding mismatch",
    "unexpected permit signer failure before adapter",
    "submitter deterministic failure hiding observed effect",
    "duplicate settlement verifier identity in quorum",
    "same verifier object counted twice in quorum",
    "observed effect rebound to different execution request",
    "durable cross-process same-intent lease contention",
    "untrusted evidence depth/width resource exhaustion",
    "signing-capable attestation trust entering runtime",
    "signing-capable attestation trust entering permit authority",
    "verify-only Ed25519 trust store cannot mint attestations",
    "settlement verifier and submitter object identity collapse",
]


def main() -> None:
    cmd = [sys.executable, "-m", "unittest", "discover", "-s", "test", "-p", "test_*.py"]
    completed = subprocess.run(cmd, capture_output=True, text=True)
    report = {
        "suite": "FAAR v0.3 targeted red-team matrix",
        "attack_classes": len(ATTACK_CLASSES),
        "classes": ATTACK_CLASSES,
        "unit_suite_exit_code": completed.returncode,
        "unit_suite_tail": (completed.stderr + completed.stdout).strip().splitlines()[-6:],
        "pass": completed.returncode == 0,
        "claim_boundary": "Regression evidence only; not a formal proof, production audit, or live-venue security claim.",
    }
    print(json.dumps(report, indent=2))
    if completed.returncode:
        raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
