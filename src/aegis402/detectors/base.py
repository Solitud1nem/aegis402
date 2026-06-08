"""Detector protocol and a safe runner.

Each detector is an independent class exposing ``run(intent) -> Signal``. Detectors
must not raise to the caller: a crash is converted by :func:`safe_run` into a
structured ``error`` signal so the engine can stay fail-closed (a failed detector
raises risk rather than silently passing).
"""

from __future__ import annotations

import logging
from typing import Protocol, runtime_checkable

from ..schemas import Intent, Signal

logger = logging.getLogger(__name__)


@runtime_checkable
class Detector(Protocol):
    """A single defense-in-depth layer."""

    layer: str

    def run(self, intent: Intent) -> Signal:
        """Inspect the intent and return a :class:`Signal`."""
        ...


def safe_run(detector: Detector, intent: Intent, *, fail_closed: bool) -> Signal:
    """Run a detector, converting any exception into an ``error`` signal.

    Args:
        detector: The detector to execute.
        intent: The normalized intent under inspection.
        fail_closed: If True, a detector failure yields a high-risk signal.

    Returns:
        The detector's signal, or an ``error`` signal on failure.
    """
    try:
        return detector.run(intent)
    except Exception as exc:  # noqa: BLE001 — deliberately broad: failure must be contained.
        logger.exception("Detector %s failed", getattr(detector, "layer", "?"))
        return Signal(
            layer=getattr(detector, "layer", "?"),
            score=0.7 if fail_closed else 0.0,
            reason=f"detector error: {exc!s}",
            evidence={"exception": type(exc).__name__},
            error=True,
        )
