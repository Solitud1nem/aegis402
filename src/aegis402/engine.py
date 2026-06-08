"""Decision Engine — aggregate detector signals into a :class:`Verdict`.

Policy (configurable in :class:`~aegis402.config.Settings`):
* A *payment-grounded* layer (L3/L4/L5) at/above ``block_threshold``, or any
  fail-closed error, → BLOCK (one strong, payment-relevant signal is enough).
* A *text-only* layer (L1/L2) does NOT hard-block on its own: matching injection
  phrasing in untrusted context is not proof the payment was hijacked — the agent
  may have read poisoned text without acting on it. Such signals still flow into the
  weighted aggregate (and can reach REVIEW), and still BLOCK whenever a grounded
  layer corroborates (the usual case). This removes the "context merely quotes an
  injection phrase, but the payment is fully grounded" false positive.
* A weighted aggregate at/above ``review_threshold`` → REVIEW.
* Any payment at/above ``high_stakes_limit`` → at least REVIEW (human-in-the-loop).
* Otherwise → ALLOW.

The engine runs all detectors through :func:`~aegis402.detectors.base.safe_run`,
so a crashing detector becomes a fail-closed risk signal rather than an exception.
"""

from __future__ import annotations

from .config import Settings, get_settings
from .detectors import Detector, default_detectors, safe_run
from .schemas import Intent, Signal, Verdict, VerdictType

# Layers that reason over untrusted *text* rather than the *payment* itself. A strong
# hit here means "injection phrasing is present", not "the payment was redirected", so
# it is insufficient to hard-block a payment the grounded layers (L3/L4/L5) clear.
TEXT_ONLY_LAYERS = frozenset({"L1", "L2"})


class DecisionEngine:
    """Runs the detector stack and applies the verdict policy."""

    def __init__(
        self,
        settings: Settings | None = None,
        detectors: list[Detector] | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._detectors = (
            detectors if detectors is not None else default_detectors(self._settings)
        )

    def evaluate(self, intent: Intent) -> Verdict:
        """Inspect an intent with all detectors and return the aggregated verdict."""
        signals = [
            safe_run(d, intent, fail_closed=self._settings.fail_closed)
            for d in self._detectors
        ]
        return self._decide(intent, signals)

    def _aggregate_score(self, signals: list[Signal]) -> float:
        """Weighted mean over *applicable* layer scores.

        Disabled/degraded layers (``applicable=False``) are excluded from both
        numerator and denominator so a sleeping detector cannot dilute the risk.
        A layer that ran and found nothing (score 0, applicable) still counts.
        Falls back to a plain mean if the applicable layers carry no weight.
        """
        weights = self._settings.layer_weights
        active = [s for s in signals if s.applicable]
        if not active:
            return 0.0
        total_w = 0.0
        acc = 0.0
        for s in active:
            w = weights.get(s.layer, 0.0)
            total_w += w
            acc += w * s.score
        if total_w > 0:
            return min(acc / total_w, 1.0)
        return min(sum(s.score for s in active) / len(active), 1.0)

    def _decide(self, intent: Intent, signals: list[Signal]) -> Verdict:
        """Apply the verdict policy to a set of signals."""
        s = self._settings
        triggered = [sig for sig in signals if sig.score > 0.0 or sig.error]
        aggregate = self._aggregate_score(signals)

        # Hard block requires a payment-grounded layer at/above the threshold, or any
        # fail-closed error. A text-only layer (L1/L2) alone is not enough — see module
        # docstring and TEXT_ONLY_LAYERS — but its score still feeds the aggregate below.
        hard_block = [
            sig
            for sig in signals
            if sig.error
            or (sig.score >= s.block_threshold and sig.layer not in TEXT_ONLY_LAYERS)
        ]
        high_stakes = intent.payment_intent.amount >= s.high_stakes_limit
        # A single payment-grounded layer with moderate (review-band) suspicion warrants
        # a human look even when other clean layers would dilute it out of the aggregate —
        # e.g. an unaccountable recipient (L4) on an open-ended, no-allowlist payment.
        grounded_review = [
            sig
            for sig in signals
            if sig.layer not in TEXT_ONLY_LAYERS
            and s.review_threshold <= sig.score < s.block_threshold
        ]

        if hard_block:
            reasons = "; ".join(sig.reason for sig in hard_block)
            return Verdict(
                verdict=VerdictType.BLOCK,
                score=max(aggregate, max(sig.score for sig in hard_block)),
                triggered_layers=triggered,
                reason=f"hard block: {reasons}",
            )

        if aggregate >= s.review_threshold or high_stakes or grounded_review:
            if high_stakes:
                reason = "high-stakes amount → human review"
            elif grounded_review:
                reason = "; ".join(sig.reason for sig in grounded_review)
            else:
                reason = "elevated aggregate risk"
            return Verdict(
                verdict=VerdictType.REVIEW,
                score=max(aggregate, *(sig.score for sig in grounded_review), 0.0),
                triggered_layers=triggered,
                reason=reason,
            )

        return Verdict(
            verdict=VerdictType.ALLOW,
            score=aggregate,
            triggered_layers=triggered,
            reason="no blocking or review-level risk detected",
        )
