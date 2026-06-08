"""Defense-in-depth detectors (L1–L5)."""

from ..config import Settings
from .base import Detector, safe_run
from .classifier import MLClassifier
from .patterns import PatternScanner
from .policy import PaymentPolicyGate
from .provenance import ProvenanceCheck
from .velocity import VelocityGate

__all__ = [
    "Detector",
    "safe_run",
    "PatternScanner",
    "MLClassifier",
    "PaymentPolicyGate",
    "ProvenanceCheck",
    "VelocityGate",
]


def default_detectors(settings: Settings | None = None) -> list[Detector]:
    """Return the standard L1–L5 detector stack in order.

    The same ``settings`` is threaded into every detector so a caller-supplied
    configuration (thresholds, asset decimals, the spend-ledger DB path) is honored
    by all layers — not just the engine. Passing None lets each detector fall back
    to the process-wide settings.
    """
    return [
        PatternScanner(settings),
        MLClassifier(settings),
        PaymentPolicyGate(settings),
        ProvenanceCheck(settings),
        VelocityGate(settings),
    ]
