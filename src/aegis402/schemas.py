"""Pydantic data models that flow through the guard.

The pipeline is: raw input → :class:`Intent` (normalized by the interceptor) →
``list[Signal]`` (from detectors) → :class:`Verdict` (from the engine).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class VerdictType(StrEnum):
    """Terminal decision for a payment intent."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class PaymentIntent(BaseModel):
    """What the agent is about to pay.

    Amount is an integer in the asset's minimal units (e.g. 6-dec USDC). Address
    fields are normalized to EIP-55 checksum by the interceptor.
    """

    recipient: str = Field(description="Destination address (checksum after normalization).")
    amount: int = Field(ge=0, description="Amount in minimal units; never a float.")
    asset: str = Field(description="Asset symbol or contract address, e.g. 'USDC'.")
    network: str = Field(description="Chain identifier, e.g. 'base-sepolia'.")


class Mandate(BaseModel):
    """Owner-set spending policy the payment must respect.

    Models an AP2-style mandate: a per-payment cap, a recipient allowlist, an
    optional cumulative budget across payments, and an optional expiry (TTL). The
    mandate is part of the trust boundary, so its identity is what scopes stateful
    velocity / budget accounting (see :meth:`spend_key`).
    """

    id: str | None = Field(
        default=None,
        description="Explicit mandate id (e.g. a signed-mandate reference). Optional.",
    )
    limit: int | None = Field(
        default=None, ge=0, description="Per-payment cap in minimal units, if any."
    )
    allowlist: list[str] = Field(
        default_factory=list, description="Permitted recipient addresses."
    )
    networks: list[str] = Field(
        default_factory=list,
        description="Permitted networks (chain ids); empty = unrestricted. An allowlisted "
        "recipient on an unlisted chain may be a different/attacker-controlled party.",
    )
    assets: list[str] = Field(
        default_factory=list,
        description="Permitted asset symbols/contracts; empty = unrestricted.",
    )
    total_budget: int | None = Field(
        default=None,
        ge=0,
        description="Cumulative spend cap across payments (minimal units); None disables.",
    )
    expires_at: datetime | None = Field(
        default=None,
        description="Mandate expiry (TTL). Payments after this instant are rejected.",
    )

    def spend_key(self) -> str:
        """Stable key scoping velocity/budget accounting to this mandate's identity.

        Uses an explicit ``id`` when set, otherwise a hash of the mandate's
        trust-relevant content (allowlist, limit, total_budget, expiry). Because it
        derives only from the trusted mandate, it cannot be altered from untrusted
        context — unlike the removed agent-controlled ``subject`` field.
        """
        if self.id:
            return self.id
        canonical = json.dumps(
            {
                "allowlist": sorted(a.lower() for a in self.allowlist),
                "networks": sorted(n.lower() for n in self.networks),
                "assets": sorted(a.lower() for a in self.assets),
                "limit": self.limit,
                "total_budget": self.total_budget,
                "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "m:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:32]


def resolve_spend_key(mandate: Mandate | None, default_key: str) -> str:
    """Resolve the ledger scope key for velocity / budget accounting.

    With a mandate, the key derives from the trusted mandate identity
    (:meth:`Mandate.spend_key`). Without one, a config-driven fixed server key is
    used: spend is then tracked globally per asset and cannot be attributed to a
    subject (documented limitation — see threat-model §5).
    """
    return mandate.spend_key() if mandate is not None else default_key


class Intent(BaseModel):
    """Normalized guard input: the payment plus the context that produced it."""

    user_request: str = Field(description="The owner's original, trusted instruction.")
    untrusted_context: list[str] = Field(
        default_factory=list,
        description="Untrusted sources the agent read (web, email, API responses).",
    )
    payment_intent: PaymentIntent
    mandate: Mandate | None = Field(default=None, description="Optional spending mandate.")


class Signal(BaseModel):
    """One detector's finding. Independent; never the sole point of failure."""

    layer: str = Field(description="Detector id, e.g. 'L1', 'L3'.")
    score: float = Field(ge=0.0, le=1.0, description="Risk in [0, 1]; higher is worse.")
    reason: str = Field(description="Human-readable explanation of the signal.")
    evidence: dict[str, Any] = Field(
        default_factory=dict, description="Structured supporting detail."
    )
    error: bool = Field(
        default=False, description="True if the detector failed (fail-closed risk)."
    )
    applicable: bool = Field(
        default=True,
        description=(
            "Whether the layer meaningfully evaluated this intent. False for "
            "disabled/degraded layers (e.g. L2 off, L5 with no limits set); such "
            "signals are excluded from the aggregate so a sleeping layer cannot "
            "dilute risk. A layer that ran and found nothing stays True (score 0 counts)."
        ),
    )


class Verdict(BaseModel):
    """Aggregated decision returned to the caller."""

    verdict: VerdictType
    score: float = Field(ge=0.0, le=1.0, description="Aggregated risk score.")
    triggered_layers: list[Signal] = Field(
        default_factory=list, description="Signals that contributed to the verdict."
    )
    evidence_id: str | None = Field(
        default=None, description="Evidence-log id for BLOCK/REVIEW outcomes."
    )
    reason: str = Field(default="", description="Short summary of why this verdict was reached.")
