"""L4 provenance check — trace the origin of the payment recipient.

Core idea: a legitimate recipient is named (or implied) by the owner's trusted
request, not introduced by untrusted content. If the address the agent is paying
appears in ``untrusted_context`` but NOT in ``user_request``, the payment target
was likely sourced from poisoned data — a strong red flag.
"""

from __future__ import annotations

from ..config import Settings, get_settings
from ..schemas import Intent, Signal
from ..text_extract import find_addresses


class ProvenanceCheck:
    """L4 detector: flags recipients whose origin is untrusted context."""

    layer = "L4"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def run(self, intent: Intent) -> Signal:
        """Determine whether the recipient originated from untrusted context."""
        recipient_lc = intent.payment_intent.recipient.lower()
        in_request = recipient_lc in find_addresses(intent.user_request)

        untrusted_addrs = find_addresses("\n".join(intent.untrusted_context))
        in_untrusted = recipient_lc in untrusted_addrs

        # Allowlisted recipients are trusted by mandate regardless of text origin.
        mandate = intent.mandate
        allowlisted = bool(
            mandate and recipient_lc in {a.lower() for a in mandate.allowlist}
        )

        if in_untrusted and not in_request and not allowlisted:
            return Signal(
                layer=self.layer,
                score=0.9,
                reason="recipient originates from untrusted context, not the owner's request",
                evidence={"recipient": intent.payment_intent.recipient, "origin": "untrusted"},
            )

        if not in_request and not allowlisted and intent.user_request.strip():
            # Recipient is neither requested, allowlisted, nor traceable — weak flag.
            return Signal(
                layer=self.layer,
                score=0.35,
                reason="recipient not traceable to the owner's request or allowlist",
                evidence={"recipient": intent.payment_intent.recipient, "origin": "unknown"},
            )

        return Signal(layer=self.layer, score=0.0, reason="recipient provenance ok")
