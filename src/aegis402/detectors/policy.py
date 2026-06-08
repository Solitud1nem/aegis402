"""L3 payment-policy gate — language-agnostic checks on the payment itself.

This layer never reads the *meaning* of untrusted text; it reasons about the
numbers and addresses: mandate allowlist/limit, recipient substitution between
the owner's request and the agent's intent, amount overshoot, and the
"new address + large amount" risk pattern.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ..config import Settings, get_settings
from ..schemas import Intent, Signal
from ..text_extract import find_addresses, find_requested_amount


class PaymentPolicyGate:
    """L3 detector: validates the payment against mandate and the owner's request."""

    layer = "L3"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def run(self, intent: Intent) -> Signal:  # noqa: C901 — cohesive policy checks.
        """Evaluate policy violations and return an aggregated L3 signal."""
        pi = intent.payment_intent
        recipient_lc = pi.recipient.lower()
        violations: list[dict[str, object]] = []
        score = 0.0

        mandate = intent.mandate
        # 1. Allowlist violation (only meaningful when an allowlist is configured).
        allowlisted = True
        if mandate and mandate.allowlist:
            allow_lc = {a.lower() for a in mandate.allowlist}
            allowlisted = recipient_lc in allow_lc
            if not allowlisted:
                violations.append({"check": "allowlist", "recipient": pi.recipient})
                score = max(score, 0.85)

        # 2. Mandate per-payment limit.
        if mandate and mandate.limit is not None and pi.amount > mandate.limit:
            violations.append(
                {"check": "mandate_limit", "amount": pi.amount, "limit": mandate.limit}
            )
            score = max(score, 0.9)

        # 3. Recipient substitution: an address named in the owner's request that
        #    differs from where the agent is actually paying.
        requested_addrs = find_addresses(intent.user_request)
        if requested_addrs and recipient_lc not in requested_addrs:
            violations.append(
                {
                    "check": "recipient_substituted",
                    "requested": requested_addrs,
                    "intent_recipient": pi.recipient,
                }
            )
            score = max(score, 0.95)

        # 4. Amount overshoot vs the amount the owner asked for.
        requested_amount = find_requested_amount(
            intent.user_request,
            pi.asset,
            self._settings.asset_decimals,
            self._settings.default_decimals,
        )
        if requested_amount is not None:
            ceiling = int(requested_amount * (1 + self._settings.amount_delta_tolerance))
            if pi.amount > ceiling:
                violations.append(
                    {
                        "check": "amount_overshoot",
                        "requested": requested_amount,
                        "intent_amount": pi.amount,
                    }
                )
                score = max(score, 0.9)

        # 5. New (non-allowlisted) address receiving a high-stakes amount.
        if not allowlisted and pi.amount >= self._settings.high_stakes_limit:
            violations.append(
                {
                    "check": "new_address_large_amount",
                    "amount": pi.amount,
                    "high_stakes_limit": self._settings.high_stakes_limit,
                }
            )
            score = max(score, 0.7)

        # 6. Mandate expiry (TTL): a payment under an expired mandate is unauthorized.
        if mandate and mandate.expires_at is not None:
            expires_at = mandate.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if datetime.now(UTC) > expires_at:
                violations.append(
                    {"check": "mandate_expired", "expires_at": expires_at.isoformat()}
                )
                score = max(score, 0.9)

        if not violations:
            return Signal(layer=self.layer, score=0.0, reason="payment policy satisfied")

        reasons = ", ".join(str(v["check"]) for v in violations)
        return Signal(
            layer=self.layer,
            score=score,
            reason=f"policy violation(s): {reasons}",
            evidence={"violations": violations},
        )
