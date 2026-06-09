"""L5 velocity must hold across *processes*, not just threads.

A per-process lock cannot stop two uvicorn workers from each clearing the same
headroom. The fix is a database-level atomic reserve (BEGIN IMMEDIATE in
SpendLedger.try_reserve); this test drives real subprocesses against a shared DB and
asserts the cap is never over-allocated.
"""

from __future__ import annotations

import multiprocessing as mp
from collections import Counter
from pathlib import Path

import pytest

from aegis402.config import Settings
from aegis402.guard import Guard

from .conftest import USDC, VENDOR

CAP = 100 * USDC


def _pay(db_path: str, i: int) -> str:
    """Worker: one 60-USDC payment to an allowlisted vendor under a 100-USDC cap."""
    guard = Guard(Settings(db_path=Path(db_path), velocity_cap=CAP))
    verdict = guard.inspect(
        {
            "user_request": f"Pay 60 USDC to our vendor (invoice {i}).",
            "untrusted_context": [],
            "payment_intent": {"recipient": VENDOR, "amount": 60 * USDC,
                               "asset": "USDC", "network": "base-sepolia"},
            "mandate": {"id": "agent-1", "allowlist": [VENDOR]},
        }
    )
    return str(verdict.verdict.value)


def test_velocity_holds_across_processes(tmp_path: Path) -> None:
    try:
        ctx = mp.get_context("fork")
    except ValueError:  # pragma: no cover — non-fork platforms
        pytest.skip("fork start method unavailable")

    db = tmp_path / "mp.db"
    Guard(Settings(db_path=db, velocity_cap=CAP))  # create schema once

    n = 8
    with ctx.Pool(n) as pool:
        results = pool.starmap(_pay, [(str(db), i) for i in range(n)])

    counts = Counter(results)
    allows = counts.get("ALLOW", 0)
    # Only one 60-USDC payment fits under the 100-USDC cap; the rest must be blocked,
    # and the total ALLOWed spend must never exceed the cap.
    assert allows == 1, f"over-allow across processes: {counts}"
    assert allows * 60 * USDC <= CAP
