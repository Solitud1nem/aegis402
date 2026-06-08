"""L2 ML classifier — injection probability via a self-hosted model.

Wraps ``meta-llama/Prompt-Guard-86M`` (HuggingFace ``transformers``), loaded lazily
on first use and cached. If the model or its dependencies are unavailable, the
detector degrades gracefully: it returns a zero-risk, non-error signal annotated
as ``degraded`` so the engine keeps working on L1+L3+L4 (the offline demo path).
"""

from __future__ import annotations

import logging
from typing import Any

from ..config import Settings, get_settings
from ..schemas import Intent, Signal

logger = logging.getLogger(__name__)


class _ModelHolder:
    """Lazy, process-local singleton for the ML pipeline (no module globals)."""

    def __init__(self, model_name: str) -> None:
        self._model_name = model_name
        self._pipeline: Any | None = None
        self._available: bool | None = None

    def get(self) -> Any | None:
        """Return a text-classification pipeline, or None if unavailable."""
        if self._available is False:
            return None
        if self._pipeline is not None:
            return self._pipeline
        try:
            from transformers import pipeline

            self._pipeline = pipeline("text-classification", model=self._model_name)
            self._available = True
            logger.info("Loaded L2 model %s", self._model_name)
        except Exception:  # noqa: BLE001 — any failure means degrade, not crash.
            logger.warning("L2 model unavailable; degrading to L1+L3+L4", exc_info=True)
            self._available = False
            return None
        return self._pipeline


class MLClassifier:
    """L2 detector: probability that untrusted context contains injection."""

    layer = "L2"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._holder = _ModelHolder(self._settings.l2_model_name)

    def run(self, intent: Intent) -> Signal:
        """Classify untrusted context; degrade gracefully if the model is absent."""
        if not self._settings.l2_enabled:
            return Signal(
                layer=self.layer,
                score=0.0,
                reason="L2 disabled (offline mode)",
                evidence={"degraded": True},
                applicable=False,
            )

        pipe = self._holder.get()
        if pipe is None:
            return Signal(
                layer=self.layer,
                score=0.0,
                reason="L2 model unavailable; degraded to other layers",
                evidence={"degraded": True},
                applicable=False,
            )

        text = "\n".join(intent.untrusted_context).strip()
        if not text:
            return Signal(layer=self.layer, score=0.0, reason="no untrusted context to classify")

        # Prompt-Guard labels: BENIGN / INJECTION / JAILBREAK. Treat the latter two as risk.
        results = pipe(text[:4000], truncation=True)
        top = results[0] if isinstance(results, list) else results
        label = str(top.get("label", "")).upper()
        prob = float(top.get("score", 0.0))
        is_injection = label in {"INJECTION", "JAILBREAK", "LABEL_1", "LABEL_2"}
        risk = prob if is_injection else 0.0

        if risk >= self._settings.l2_threshold:
            return Signal(
                layer=self.layer,
                score=min(risk, 1.0),
                reason=f"ML classifier flags injection ({label}, p={prob:.2f})",
                evidence={"label": label, "prob": prob},
            )
        return Signal(
            layer=self.layer,
            score=0.0,
            reason=f"ML classifier: benign ({label}, p={prob:.2f})",
            evidence={"label": label, "prob": prob},
        )
