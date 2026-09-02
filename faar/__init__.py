"""FAAR — Financial Agent Authority Router."""

from .models import (
    AuthorityDecision,
    CapabilityGrant,
    Decision,
    Intent,
    IntentState,
    RiskSnapshot,
    Verdict,
)
from .runtime import FAARRuntime, RuntimeResult

__all__ = [
    "AuthorityDecision",
    "CapabilityGrant",
    "Decision",
    "FAARRuntime",
    "Intent",
    "IntentState",
    "RiskSnapshot",
    "RuntimeResult",
    "Verdict",
]

__version__ = "0.3.1"
