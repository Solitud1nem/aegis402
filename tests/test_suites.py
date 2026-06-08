"""Suite-level metrics — enforce the PRD success criteria.

Recall ≥ 80% on attacks, false-positive ≤ 10% on benign, latency ≤ 300ms/intent.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from aegis402.config import Settings
from aegis402.guard import Guard
from aegis402.schemas import VerdictType

SUITE_ROOT = Path(__file__).parent
ATTACKS = sorted((SUITE_ROOT / "attack_suite").glob("*.json"))
BENIGN = sorted((SUITE_ROOT / "benign_suite").glob("*.json"))


@pytest.fixture
def guard(tmp_path: Path) -> Guard:
    return Guard(Settings(db_path=tmp_path / "suite.db", l2_enabled=False))


def test_attack_suite_has_enough_cases() -> None:
    assert len(ATTACKS) >= 10


def test_benign_suite_has_enough_cases() -> None:
    assert len(BENIGN) >= 10


def test_attack_recall_meets_target(guard: Guard) -> None:
    blocked = sum(
        guard.inspect(json.loads(f.read_text())).verdict != VerdictType.ALLOW for f in ATTACKS
    )
    assert blocked / len(ATTACKS) >= 0.80


def test_benign_false_positive_within_target(guard: Guard) -> None:
    false_pos = sum(
        guard.inspect(json.loads(f.read_text())).verdict != VerdictType.ALLOW for f in BENIGN
    )
    assert false_pos / len(BENIGN) <= 0.10


def test_latency_within_budget(guard: Guard) -> None:
    for f in ATTACKS + BENIGN:
        raw = json.loads(f.read_text())
        t0 = time.perf_counter()
        guard.inspect(raw)
        assert (time.perf_counter() - t0) * 1000 <= 300
