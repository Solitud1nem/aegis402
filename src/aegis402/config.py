"""Runtime configuration for Aegis402.

All thresholds, weights, limits and paths live here (or in env / ``.env``) so that
nothing security-relevant is hardcoded across the codebase. Override any field with
an ``AEGIS_``-prefixed environment variable, e.g. ``AEGIS_HIGH_STAKES_LIMIT=5000000``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration object for the guard.

    Attributes group naturally into detector tuning, decision-engine policy and
    storage. Monetary values are integers in an asset's minimal units (e.g. 6-dec
    USDC: ``1000000`` == 1 USDC) — never floats.
    """

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Decision engine policy -------------------------------------------------
    block_threshold: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Any single layer score at/above this forces BLOCK.",
    )
    review_threshold: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Aggregated risk at/above this (but below block) forces REVIEW.",
    )
    high_stakes_limit: int = Field(
        default=100_000_000,
        ge=0,
        description="Payments at/above this (minimal units) always escalate to REVIEW.",
    )
    unanchored_recipient_score: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description=(
            "L4 score for a recipient with no traceable provenance (not in the request, "
            "not allowlisted, and absent from untrusted context). Defaults into the "
            "REVIEW band so an autonomous agent cannot silently pay an unaccountable "
            "address; set below 'review_threshold' to allow such payments."
        ),
    )
    layer_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "L1": 0.25,
            "L2": 0.30,
            "L3": 0.30,
            "L4": 0.15,
            "L5": 0.20,
        },
        description="Weights used to aggregate per-layer scores into overall risk.",
    )
    fail_closed: bool = Field(
        default=True,
        description="On detector error/timeout, treat as risk and lean to BLOCK.",
    )
    strict_mandate: bool = Field(
        default=False,
        description=(
            "Opt-in deployment posture for autonomous agents. When True, a payment whose "
            "mandate does not bound it with a per-payment 'limit' is escalated to REVIEW "
            "(never silent ALLOW): an unbounded payment must be confirmed by a human. Off "
            "by default so open-ended/no-mandate flows keep working; turn it on to require "
            "every autonomous payment to carry a cap. Rate limiting remains separate "
            "('velocity_cap')."
        ),
    )
    require_signed_mandate: bool = Field(
        default=False,
        description=(
            "Opt-in: every payment must carry a mandate with a valid HMAC signature over "
            "its canonical content (see mandate_auth). The mandate is the trust anchor, so "
            "without this a prompt-injected agent could forge a permissive mandate. When "
            "on, a missing/unsigned/invalid mandate — or no configured secret — fails "
            "closed to BLOCK. Off by default for back-compat."
        ),
    )
    mandate_hmac_secret: str | None = Field(
        default=None,
        description=(
            "Server-side secret (env AEGIS_MANDATE_HMAC_SECRET) used to verify mandate "
            "signatures. Lives only in config, never in the request payload. Required when "
            "require_signed_mandate is on."
        ),
    )
    max_untrusted_chars: int = Field(
        default=1_000_000,
        ge=0,
        description=(
            "Cap on total untrusted_context characters the detectors scan. Excess is "
            "truncated before evaluation so attacker-controlled bulk text cannot drive a "
            "CPU/DoS (defense-in-depth atop bounded regexes). Generous default; legitimate "
            "agent context is far smaller. A buried address dropped by truncation degrades "
            "L4 to REVIEW, never to a silent ALLOW."
        ),
    )

    # --- L1 pattern scanner -----------------------------------------------------
    l1_signal_score: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Score emitted when L1 matches a known injection pattern.",
    )

    # --- L2 ML classifier -------------------------------------------------------
    l2_model_name: str = Field(
        default="meta-llama/Prompt-Guard-86M",
        description="HuggingFace model id for the injection classifier.",
    )
    l2_enabled: bool = Field(
        default=False,
        description="Load the ML classifier. Off by default so the demo runs offline.",
    )
    l2_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Injection probability at/above this is reported by L2.",
    )

    # --- L3 payment policy ------------------------------------------------------
    amount_delta_tolerance: float = Field(
        default=0.0,
        ge=0.0,
        description="Allowed fractional overshoot of requested amount before flagging.",
    )
    default_decimals: int = Field(
        default=6,
        ge=0,
        description="Fallback decimals when an asset is not in 'asset_decimals'.",
    )
    asset_decimals: dict[str, int] = Field(
        default_factory=lambda: {"USDC": 6, "USDT": 6, "DAI": 18, "ETH": 18, "WETH": 18},
        description="Minimal-unit decimals per asset symbol (uppercased).",
    )

    # --- L5 velocity / budget ---------------------------------------------------
    velocity_window_seconds: int = Field(
        default=3600,
        ge=1,
        description="Trailing window (seconds) L5 sums spend over, per (mandate scope, asset).",
    )
    velocity_cap: int | None = Field(
        default=None,
        ge=0,
        description="Max spend per window per (mandate scope, asset), minimal units; None off.",
    )
    velocity_default_key: str = Field(
        default="__server_default__",
        description="Fixed ledger scope used when no mandate is present (global per asset).",
    )
    l5_signal_score: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Score emitted when L5 detects a velocity/budget breach.",
    )

    # --- Storage ----------------------------------------------------------------
    db_path: Path = Field(
        default=Path("aegis402.db"),
        description="SQLite path for the evidence log and allowlist.",
    )

    # --- Service ----------------------------------------------------------------
    host: str = Field(default="127.0.0.1", description="Bind host for the HTTP API.")
    port: int = Field(default=8402, ge=1, le=65535, description="Bind port for the HTTP API.")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a process-wide cached :class:`Settings` instance."""
    return Settings()
