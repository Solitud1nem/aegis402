"""Decision engine + fail-closed behaviour tests."""

from __future__ import annotations

from aegis402.config import Settings
from aegis402.engine import DecisionEngine
from aegis402.interceptor import build_intent
from aegis402.schemas import Intent, Signal, VerdictType

from .conftest import USDC, VENDOR


class _StubDetector:
    def __init__(
        self, layer: str, score: float, error: bool = False, applicable: bool = True
    ) -> None:
        self.layer = layer
        self._score = score
        self._error = error
        self._applicable = applicable

    def run(self, intent: Intent) -> Signal:
        if self._error:
            raise RuntimeError("boom")
        return Signal(
            layer=self.layer, score=self._score, reason="stub", applicable=self._applicable
        )


def _intent(amount: int = 5 * USDC):
    return build_intent({
        "user_request": f"Pay to {VENDOR}.",
        "untrusted_context": [],
        "payment_intent": {"recipient": VENDOR, "amount": amount, "asset": "USDC",
                           "network": "base-sepolia"},
    })


def test_strong_single_signal_blocks() -> None:
    engine = DecisionEngine(Settings(), detectors=[_StubDetector("L3", 0.95)])
    assert engine.evaluate(_intent()).verdict == VerdictType.BLOCK


def test_high_stakes_amount_forces_review() -> None:
    engine = DecisionEngine(Settings(high_stakes_limit=10 * USDC),
                            detectors=[_StubDetector("L1", 0.0)])
    assert engine.evaluate(_intent(50 * USDC)).verdict == VerdictType.REVIEW


def test_clean_signals_allow() -> None:
    engine = DecisionEngine(Settings(), detectors=[_StubDetector("L1", 0.0),
                                                   _StubDetector("L3", 0.0)])
    assert engine.evaluate(_intent()).verdict == VerdictType.ALLOW


def test_detector_crash_is_fail_closed() -> None:
    """A crashing detector becomes a high-risk error signal, not an exception."""
    engine = DecisionEngine(Settings(fail_closed=True),
                            detectors=[_StubDetector("L3", 0.0, error=True)])
    verdict = engine.evaluate(_intent())
    assert verdict.verdict in {VerdictType.BLOCK, VerdictType.REVIEW}
    assert any(s.error for s in verdict.triggered_layers)


def test_inactive_layer_does_not_dilute_aggregate() -> None:
    """#4 regression: an inapplicable (sleeping) layer must not lower the aggregate."""
    settings = Settings()
    base = DecisionEngine(settings, detectors=[_StubDetector("L3", 0.5)])
    with_sleeper = DecisionEngine(
        settings,
        detectors=[_StubDetector("L3", 0.5), _StubDetector("L5", 0.0, applicable=False)],
    )
    v_base = base.evaluate(_intent())
    v_sleep = with_sleeper.evaluate(_intent())
    assert v_sleep.score == v_base.score  # sleeper excluded from denominator


def test_applicable_zero_score_still_counts() -> None:
    """A layer that ran clean (applicable, score 0) is included and pulls risk down."""
    settings = Settings()
    one = DecisionEngine(settings, detectors=[_StubDetector("L3", 0.6)])
    with_clean = DecisionEngine(
        settings, detectors=[_StubDetector("L3", 0.6), _StubDetector("L1", 0.0)]
    )
    assert with_clean.evaluate(_intent()).score < one.evaluate(_intent()).score
