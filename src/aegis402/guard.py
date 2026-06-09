"""Guard facade — the single entry point used by both the CLI and the HTTP API.

Ties together the interceptor, decision engine and evidence log so callers hand in
raw input and get back a :class:`Verdict` with evidence already persisted.
"""

from __future__ import annotations

import logging
import threading
from contextlib import nullcontext
from typing import Any

from .config import Settings, get_settings
from .engine import DecisionEngine
from .evidence import EvidenceLog
from .interceptor import build_intent
from .ledger import SpendLedger
from .schemas import Intent, Verdict, VerdictType, resolve_spend_key

logger = logging.getLogger(__name__)


class Guard:
    """Inspect raw payment intents and render a persisted verdict."""

    def __init__(
        self,
        settings: Settings | None = None,
        engine: DecisionEngine | None = None,
        evidence: EvidenceLog | None = None,
        ledger: SpendLedger | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._engine = engine or DecisionEngine(self._settings)
        self._evidence = evidence or EvidenceLog(self._settings)
        self._ledger = ledger or SpendLedger(self._settings)
        # Serializes the stateful L5 critical section (ledger read inside evaluate →
        # decision → ledger write) so concurrent payments cannot each observe pre-write
        # headroom and both ALLOW past the cap. Per-process only.
        self._spend_lock = threading.Lock()

    def inspect(self, raw: dict[str, Any]) -> Verdict:
        """Normalize, evaluate and record a raw intent.

        On any unexpected failure the guard is fail-closed: it returns BLOCK rather
        than risk allowing a payment it could not fully vet.
        """
        try:
            intent = build_intent(raw)
        except Exception as exc:  # noqa: BLE001 — invalid input must not allow payment.
            logger.warning("Invalid intent rejected (fail-closed): %s", exc)
            return Verdict(
                verdict=VerdictType.BLOCK,
                score=1.0,
                reason=f"invalid input (fail-closed BLOCK): {exc!s}",
            )

        # L5 (velocity / budget) is check-then-act: the cap is read inside evaluate() and
        # the spend written by _record_spend(). When a stateful limit is in effect, hold a
        # lock across read→decide→write so two concurrent payments can't both see headroom
        # and ALLOW past the cap. Stateless intents (the default) take no lock.
        budget_set = intent.mandate is not None and intent.mandate.total_budget is not None
        stateful = self._settings.velocity_cap is not None or budget_set
        with self._spend_lock if stateful else nullcontext():
            verdict = self._engine.evaluate(intent)
            if verdict.verdict == VerdictType.ALLOW:
                self._record_spend(intent)
        if self._evidence.should_record(verdict):
            self._evidence.record(intent, verdict)
        return verdict

    def _record_spend(self, intent: Intent) -> None:
        """Append an allowed payment to the spend ledger when velocity is in use.

        Only records when a velocity cap or mandate budget is configured, so the
        default (feature-off) path writes nothing. A ledger failure must not flip an
        already-rendered ALLOW, so it is logged and swallowed.
        """
        budget_set = intent.mandate is not None and intent.mandate.total_budget is not None
        if self._settings.velocity_cap is None and not budget_set:
            return
        scope = resolve_spend_key(intent.mandate, self._settings.velocity_default_key)
        try:
            pi = intent.payment_intent
            self._ledger.record_spend(scope, pi.asset, pi.amount)
        except Exception:  # noqa: BLE001 — accounting must not break the verdict path.
            logger.warning("Spend-ledger write failed for scope=%s", scope)
