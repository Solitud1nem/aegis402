"""L5 velocity / budget gate — stateful rate and cumulative-spend limits.

Unlike the stateless L1–L4 detectors, L5 reads a :class:`~aegis402.ledger.SpendLedger`
of previously **allowed** payments to enforce two language-agnostic limits that a
single-payment check cannot see:

* **Velocity** — total spend in a trailing time window per ``(scope, asset)`` must
  stay under ``velocity_cap``. Defends against "death by a thousand cuts": many
  individually within-limit payments that aggregate past intent.
* **Total budget** — cumulative spend for the mandate scope must stay under
  ``mandate.total_budget`` (AP2-style budget).

The ``scope`` key derives from the trusted mandate identity (not an agent-controlled
field), so it cannot be reset from untrusted context. Both limits include the
*current* payment (prospective check) but the current payment is only written to the
ledger by the guard once it is ALLOWed.
"""

from __future__ import annotations

from ..config import Settings, get_settings
from ..ledger import SpendLedger
from ..schemas import Intent, Signal, resolve_spend_key


class VelocityGate:
    """L5 detector: enforces per-window velocity and cumulative mandate budget."""

    layer = "L5"

    def __init__(
        self, settings: Settings | None = None, ledger: SpendLedger | None = None
    ) -> None:
        self._settings = settings or get_settings()
        self._ledger = ledger or SpendLedger(self._settings)

    def run(self, intent: Intent) -> Signal:
        """Check the prospective payment against velocity and budget limits."""
        s = self._settings
        pi = intent.payment_intent
        scope = resolve_spend_key(intent.mandate, s.velocity_default_key)
        violations: list[dict[str, object]] = []
        score = 0.0
        evaluated = False  # whether any limit was actually in effect for this intent

        # 1. Velocity: trailing-window spend cap (config-driven; opt-in).
        if s.velocity_cap is not None:
            evaluated = True
            window = self._ledger.spent_in_window(
                scope, pi.asset, s.velocity_window_seconds
            )
            if window + pi.amount > s.velocity_cap:
                violations.append(
                    {
                        "check": "velocity_window",
                        "window_seconds": s.velocity_window_seconds,
                        "spent_in_window": window,
                        "amount": pi.amount,
                        "cap": s.velocity_cap,
                    }
                )
                score = max(score, s.l5_signal_score)

        # 2. Cumulative mandate budget (AP2-style; opt-in via mandate).
        mandate = intent.mandate
        if mandate and mandate.total_budget is not None:
            evaluated = True
            total = self._ledger.total_spent(scope, pi.asset)
            if total + pi.amount > mandate.total_budget:
                violations.append(
                    {
                        "check": "total_budget",
                        "spent_total": total,
                        "amount": pi.amount,
                        "budget": mandate.total_budget,
                    }
                )
                score = max(score, 0.9)

        if not violations:
            # When no limit is in effect the layer did not evaluate by substance, so it
            # is marked inapplicable and excluded from the aggregate (see engine).
            reason = (
                "velocity/budget within limits"
                if evaluated
                else "L5 inactive (no velocity cap or budget configured)"
            )
            return Signal(
                layer=self.layer, score=0.0, reason=reason, applicable=evaluated
            )

        reasons = ", ".join(str(v["check"]) for v in violations)
        return Signal(
            layer=self.layer,
            score=score,
            reason=f"velocity/budget violation(s): {reasons}",
            evidence={"violations": violations, "scope": scope},
        )
