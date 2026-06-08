"""End-to-end L5: many within-limit payments through the full Guard, then a block.

Exercises the whole path — interceptor → engine → L5 → spend-ledger append on ALLOW —
across repeated calls, asserting the "death by a thousand cuts" transition that no
single-payment check could catch.
"""

from __future__ import annotations

from pathlib import Path

from aegis402.config import Settings
from aegis402.guard import Guard
from aegis402.schemas import VerdictType

from .conftest import USDC, VENDOR


def _payment() -> dict:
    return {
        "user_request": f"Pay 20 USDC to {VENDOR} for the metered API.",
        "untrusted_context": ["Usage invoice: 20 USDC for this cycle."],
        "payment_intent": {
            "recipient": VENDOR,
            "amount": 20 * USDC,
            "asset": "USDC",
            "network": "base-sepolia",
        },
    }


def test_thousand_cuts_allows_until_window_cap(tmp_path: Path) -> None:
    """5 payments of 20 USDC ALLOW (sum 100 ≤ cap); the 6th (120 > 100) is blocked by L5."""
    settings = Settings(db_path=tmp_path / "e2e.db", velocity_cap=100 * USDC)
    guard = Guard(settings)

    verdicts = [guard.inspect(_payment()) for _ in range(6)]

    assert all(v.verdict == VerdictType.ALLOW for v in verdicts[:5])
    assert verdicts[5].verdict == VerdictType.BLOCK
    assert any(s.layer == "L5" for s in verdicts[5].triggered_layers)


def test_within_window_cap_all_allow(tmp_path: Path) -> None:
    """Three 20-USDC payments (sum 60 ≤ 100) all pass — no false positive."""
    settings = Settings(db_path=tmp_path / "e2e.db", velocity_cap=100 * USDC)
    guard = Guard(settings)

    verdicts = [guard.inspect(_payment()) for _ in range(3)]

    assert all(v.verdict == VerdictType.ALLOW for v in verdicts)
