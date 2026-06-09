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


def test_allow_surfaces_spend_id_and_void_frees_headroom(tmp_path: Path) -> None:
    """An ALLOW that books stateful spend returns a spend_id; voiding it (settlement
    failed) frees the window so a later payment that would have exceeded the cap passes."""
    settings = Settings(db_path=tmp_path / "rec.db", velocity_cap=100 * USDC)
    guard = Guard(settings)

    def pay() -> object:
        return guard.inspect({
            "user_request": f"Pay 60 USDC to {VENDOR}.",
            "untrusted_context": [],
            "payment_intent": {"recipient": VENDOR, "amount": 60 * USDC,
                               "asset": "USDC", "network": "base-sepolia"},
            "mandate": {"id": "agent-1", "allowlist": [VENDOR]},
        })

    first = pay()
    assert first.verdict == VerdictType.ALLOW
    assert isinstance(first.spend_id, int)
    # A second 60 (120 > 100) is blocked while the first reservation stands.
    assert pay().verdict == VerdictType.BLOCK
    # Void the first (it never settled) -> headroom freed -> the next 60 fits again.
    assert guard.reconcile(first.spend_id, settled=False) is True
    assert pay().verdict == VerdictType.ALLOW
    # Reconciling an unknown id is a no-op False.
    assert guard.reconcile(999_999, settled=False) is False


def test_asset_casing_does_not_split_velocity_window(tmp_path: Path) -> None:
    """Alternating the asset string's case/whitespace must not create fresh windows: the
    interceptor canonicalizes the asset, so the same token aggregates under one cap."""
    settings = Settings(db_path=tmp_path / "case.db", velocity_cap=100 * USDC)
    guard = Guard(settings)

    verdicts = []
    for asset in ("USDC", "usdc", "UsDc", "USDC "):
        verdicts.append(
            guard.inspect({
                "user_request": f"Pay 60 {asset} to {VENDOR}.",
                "untrusted_context": [],
                "payment_intent": {"recipient": VENDOR, "amount": 60 * USDC,
                                   "asset": asset, "network": "base-sepolia"},
                "mandate": {"id": "agent-1", "allowlist": [VENDOR]},
            }).verdict
        )

    assert verdicts[0] == VerdictType.ALLOW
    assert all(v == VerdictType.BLOCK for v in verdicts[1:]), verdicts


def test_concurrent_payments_do_not_overrun_cap(tmp_path: Path) -> None:
    """Check-then-act race: many parallel 60-USDC payments must not both ALLOW past a
    100-USDC cap. The guard's spend lock serializes read→decide→write, so total ALLOWed
    spend stays within the cap (here: exactly one payment fits)."""
    import threading

    settings = Settings(db_path=tmp_path / "race.db", velocity_cap=100 * USDC)
    guard = Guard(settings)

    def pay(out: list, i: int) -> None:
        # Self-consistent 60-USDC payment (no amount-overshoot vs the request); only L5
        # should gate it, so the cap (not another layer) decides how many ALLOW.
        p = {
            "user_request": f"Pay 60 USDC to {VENDOR} for the metered API.",
            "untrusted_context": [],
            "payment_intent": {"recipient": VENDOR, "amount": 60 * USDC,
                               "asset": "USDC", "network": "base-sepolia"},
        }
        out[i] = guard.inspect(p).verdict

    n = 8
    results: list = [None] * n
    threads = [threading.Thread(target=pay, args=(results, i)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    allows = sum(1 for v in results if v == VerdictType.ALLOW)
    assert allows == 1, f"expected exactly 1 ALLOW within the cap, got {allows}"
    assert allows * 60 * USDC <= 100 * USDC
