"""Benchmark harness tests — corpus size and core-subset quality bounds."""

from __future__ import annotations

from pathlib import Path

from aegis402.benchmark import evaluate, load_dataset
from aegis402.config import Settings

DATASET = Path(__file__).resolve().parent.parent / "benchmarks" / "dataset"


def test_corpus_is_substantial() -> None:
    cases = load_dataset(DATASET)
    assert len(cases) >= 40
    labels = {m["label"] for m, _ in cases}
    assert labels == {"malicious", "benign"}
    assert any(m.get("hard") for m, _ in cases)  # honest hard cases present


def test_core_subset_meets_prd_bounds(tmp_path: Path) -> None:
    """Excluding by-design-hard cases, the guard should be strong: recall ≥80%, FPR ≤10%."""
    report = evaluate(DATASET, Settings(db_path=tmp_path / "b.db"))
    assert report.core.recall >= 0.80
    assert report.core.fpr <= 0.10


def test_benchmark_has_teeth(tmp_path: Path) -> None:
    """The corpus must actually be challenging — overall must not be a rigged 100/0."""
    report = evaluate(DATASET, Settings(db_path=tmp_path / "b.db"))
    # Hard cases exist, so overall recall < 1.0 or overall FPR > 0 (honest measurement).
    assert report.overall.recall < 1.0 or report.overall.fpr > 0.0
    assert report.latency_p95_ms <= 300
