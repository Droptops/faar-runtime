"""Deterministic failure-injection catalog for the FAAR v0.4 authority plane.

Faults are applied to the existing mock venue / runtime. This is not a live
network or OS crash simulator. Each case must fail closed.
"""
from __future__ import annotations

from enum import StrEnum

from .adapters import MockMode


class InjectedFault(StrEnum):
    TIMEOUT_BEFORE_ACCEPT = "TIMEOUT_BEFORE_ACCEPT"
    TIMEOUT_AFTER_ACCEPT = "TIMEOUT_AFTER_ACCEPT"
    PROCESS_CRASH = "PROCESS_CRASH"
    NETWORK_AMBIGUITY = "NETWORK_AMBIGUITY"
    STALE_VERIFIER = "STALE_VERIFIER"
    REVOKE_DURING_SUBMIT = "REVOKE_DURING_SUBMIT"
    PARTIAL_FILL = "PARTIAL_FILL"
    INCONSISTENT_PROVIDER = "INCONSISTENT_PROVIDER"
    DATASTORE_INTERRUPT = "DATASTORE_INTERRUPT"
    DUPLICATE_WORKER = "DUPLICATE_WORKER"


FAULT_TO_MOCK_MODE = {
    InjectedFault.TIMEOUT_BEFORE_ACCEPT: MockMode.TIMEOUT_BEFORE_EFFECT,
    InjectedFault.TIMEOUT_AFTER_ACCEPT: MockMode.TIMEOUT_AFTER_EFFECT,
    InjectedFault.PROCESS_CRASH: MockMode.TIMEOUT_AFTER_EFFECT,
    InjectedFault.NETWORK_AMBIGUITY: MockMode.AMBIGUOUS,
    InjectedFault.PARTIAL_FILL: MockMode.PARTIAL_FILL,
}
