"""Guard facade — the single entry point used by both the CLI and the HTTP API.

Ties together the interceptor, decision engine and evidence log so callers hand in
raw input and get back a :class:`Verdict` with evidence already persisted.
"""

from __future__ import annotations

import logging
from typing import Any

from .config import Settings, get_settings
from .engine import DecisionEngine
from .evidence import EvidenceLog
from .interceptor import build_intent
from .ledger import SpendLedger
from .mandate_auth import verify_mandate
from .schemas import Intent, Signal, Verdict, VerdictType, resolve_spend_key

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

        self._bound_untrusted(intent)

        # Authenticate the mandate before any detector trusts it: a forged/escalated
        # mandate must never reach the (mandate-trusting) policy layers.
        mandate_block = self._check_mandate_auth(intent)
        if mandate_block is not None:
            if self._evidence.should_record(mandate_block):
                self._evidence.record(intent, mandate_block)
            return mandate_block

        verdict = self._engine.evaluate(intent)
        if verdict.verdict == VerdictType.ALLOW:
            verdict = self._reserve_or_block(intent, verdict)
        if self._evidence.should_record(verdict):
            self._evidence.record(intent, verdict)
        return verdict

    def _bound_untrusted(self, intent: Intent) -> None:
        """Truncate untrusted_context to the configured char budget before scanning.

        Bounds detector CPU on attacker-controlled bulk text (defense-in-depth atop the
        bounded regexes). Truncation can only weaken detection toward REVIEW (e.g. an
        address buried past the cap), never toward a silent ALLOW.
        """
        cap = self._settings.max_untrusted_chars
        kept: list[str] = []
        remaining = cap
        truncated = False
        for entry in intent.untrusted_context:
            if remaining <= 0:
                truncated = True
                break
            if len(entry) > remaining:
                kept.append(entry[:remaining])
                remaining = 0
                truncated = True
            else:
                kept.append(entry)
                remaining -= len(entry)
        if truncated:
            logger.warning(
                "Untrusted context exceeded %d chars; truncated for scanning.", cap
            )
            intent.untrusted_context = kept

    def _check_mandate_auth(self, intent: Intent) -> Verdict | None:
        """Fail-closed BLOCK when signed mandates are required and verification fails.

        Returns None to proceed. Enabled by ``Settings.require_signed_mandate``; the
        mandate is the trust anchor, so an unverifiable one is treated as untrusted input
        rather than honored.
        """
        if not self._settings.require_signed_mandate:
            return None
        secret = self._settings.mandate_hmac_secret
        if not secret:
            return self._fail_closed(
                "signed mandate required but no verification secret is configured"
            )
        if intent.mandate is None:
            return self._fail_closed("signed mandate required but none was provided")
        if not verify_mandate(intent.mandate, secret):
            return self._fail_closed("mandate signature missing or invalid")
        if intent.mandate.expires_at is None:
            # A valid signature alone is replayable forever (and unrevocable). Requiring an
            # expiry bounds the replay window in the signed-mandate posture; L3 then blocks
            # any payment past it. Full early revocation still needs a revocation list.
            return self._fail_closed(
                "signed mandate must carry an expiry (replay protection)"
            )
        return None

    @staticmethod
    def _fail_closed(reason: str) -> Verdict:
        """A fail-closed BLOCK verdict carrying ``reason``."""
        logger.warning("Mandate auth fail-closed BLOCK: %s", reason)
        return Verdict(
            verdict=VerdictType.BLOCK,
            score=1.0,
            reason=f"fail-closed BLOCK: {reason}",
        )

    def _reserve_or_block(self, intent: Intent, verdict: Verdict) -> Verdict:
        """Atomically book an ALLOWed payment against velocity / budget caps.

        When a stateful limit is configured, the spend is reserved in a single
        cross-process-serialized transaction (:meth:`SpendLedger.try_reserve`). This is
        the authoritative gate: the L5 read inside ``evaluate`` can be stale under
        concurrency, so a payment that the engine cleared can still lose the reservation
        race — in which case it is converted to a BLOCK rather than over-allowing past the
        cap. With no stateful limit there is nothing to record and the ALLOW stands.
        """
        budget = intent.mandate.total_budget if intent.mandate is not None else None
        if self._settings.velocity_cap is None and budget is None:
            return verdict
        scope = resolve_spend_key(intent.mandate, self._settings.velocity_default_key)
        pi = intent.payment_intent
        try:
            spend_id = self._ledger.try_reserve(
                scope,
                pi.asset,
                pi.amount,
                velocity_cap=self._settings.velocity_cap,
                window_seconds=self._settings.velocity_window_seconds,
                total_budget=budget,
            )
        except Exception:  # noqa: BLE001 — a ledger error must fail closed, not over-allow.
            logger.warning("Spend reservation failed for scope=%s (fail-closed)", scope)
            spend_id = None
        if spend_id is not None:
            # Surface the reservation id so the caller can reconcile (settle/void) if the
            # payment ultimately does or does not settle on-chain.
            return verdict.model_copy(update={"spend_id": spend_id})
        signal = Signal(
            layer="L5",
            score=self._settings.l5_signal_score,
            reason="velocity/budget cap reached (atomic reserve lost the race)",
            evidence={"scope": scope, "asset": pi.asset, "amount": pi.amount},
        )
        return Verdict(
            verdict=VerdictType.BLOCK,
            score=self._settings.l5_signal_score,
            triggered_layers=[signal],
            reason="hard block: velocity/budget cap reached",
        )

    def reconcile(self, spend_id: int, *, settled: bool) -> bool:
        """Reconcile a reserved spend once its on-chain fate is known.

        ``settled=True`` confirms it (stays counted); ``settled=False`` voids it (frees the
        window/budget headroom a never-settled payment would otherwise hold). Returns False
        for an unknown id. Closes the "approved ≠ settled" ghost-spend gap: without this a
        payment the guard ALLOWed but that never settled would over-block later payments.
        """
        if settled:
            return self._ledger.mark_settled(spend_id)
        return self._ledger.void(spend_id)

    def verify_evidence_chain(self) -> tuple[bool, str | None]:
        """Verify the evidence hash chain; ``(True, None)`` if intact, else the first
        broken record id. Lets an auditor detect in-place edits/deletions of the log."""
        return self._evidence.verify_chain()
