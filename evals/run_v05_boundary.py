#!/usr/bin/env python3
"""Distributed-boundary eval for FAAR v0.5.

Regression evidence only. Not a production audit or live-money claim.
"""
from __future__ import annotations

import json
import subprocess
import sys

ATTACK_CLASSES = [
    "malicious verifier descriptor rejected at construction",
    "revoked descriptor cannot load into executor",
    "executor module graph does not import signer providers",
    "spawned executor process holds zero Ed25519 private keys",
    "authorized mock treasury PAY executes exactly once",
    "duplicate delivery replays the same effect receipt",
    "amount mutation is denied with no treasury movement",
    "beneficiary substitution is denied",
    "delayed execution after permit expiry is denied",
    "confused-deputy venue substitution is denied",
    "crash after treasury effect before receipt commit recovers once",
    "gateway daily budget is a machine-readable stop",
    "KMS/HSM provider is an unimplemented interface",
    "file-backed public descriptors contain no private material",
]


def main() -> None:
    cmd = [sys.executable, "-m", "unittest", "test_v05", "-v"]
    completed = subprocess.run(cmd, capture_output=True, text=True, cwd=".")
    # unittest discovery from repo root needs PYTHONPATH=test:.
    if completed.returncode != 0:
        cmd = [sys.executable, "-m", "unittest", "discover", "-s", "test", "-p", "test_v05.py", "-v"]
        completed = subprocess.run(cmd, capture_output=True, text=True)
    report = {
        "suite": "FAAR v0.5 distributed authority-boundary eval",
        "attack_classes": len(ATTACK_CLASSES),
        "classes": ATTACK_CLASSES,
        "unit_suite_exit_code": completed.returncode,
        "unit_suite_tail": (completed.stderr + completed.stdout).strip().splitlines()[-12:],
        "pass": completed.returncode == 0,
        "claim_boundary": "Subprocess/SQLite reference evidence only; not a production KMS or live-venue claim.",
    }
    print(json.dumps(report, indent=2))
    if completed.returncode:
        raise SystemExit(completed.returncode)


if __name__ == "__main__":
    main()
