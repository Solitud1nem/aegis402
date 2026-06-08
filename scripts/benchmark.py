"""Run the Aegis402 detection benchmark and write a report.

  uv run python benchmarks/_generate_dataset.py   # (re)materialize the corpus
  uv run python scripts/benchmark.py               # evaluate + write the report

Prints a rich summary, writes `docs/benchmark-results.md` (committed) and
`benchmarks/results.json`. Uses a throwaway temp DB so nothing leaks into the repo.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis402.benchmark import BenchmarkReport, Metrics, evaluate, to_markdown
from aegis402.config import Settings

ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "benchmarks" / "dataset"
REPORT_MD = ROOT / "docs" / "benchmark-results.md"
RESULTS_JSON = ROOT / "benchmarks" / "results.json"


def _metrics_row(table: Table, name: str, m: Metrics) -> None:
    table.add_row(
        name, str(m.n), f"{m.precision:.0%}", f"{m.recall:.0%}",
        f"{m.f1:.2f}", f"{m.fpr:.0%}",
    )


def main() -> None:
    console = Console()
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(db_path=Path(tmp) / "bench.db")
        report: BenchmarkReport = evaluate(DATASET, settings)

    table = Table("set", "n", "precision", "recall", "F1", "FPR")
    _metrics_row(table, "overall", report.overall)
    _metrics_row(table, "core (no hard)", report.core)
    console.print(Panel(table, title="Aegis402 benchmark"))

    cat = Table("category", "label", "n", "flagged", "hard")
    for c in report.per_category:
        cat.add_row(c.category, c.label, str(c.n), str(c.detected), "yes" if c.hard else "")
    console.print(cat)
    console.print(
        f"latency: p50 {report.latency_p50_ms:.0f}ms · p95 {report.latency_p95_ms:.0f}ms  "
        f"({report.total} cases)"
    )

    REPORT_MD.write_text(to_markdown(report), encoding="utf-8")
    RESULTS_JSON.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    console.print(f"[green]wrote {REPORT_MD.relative_to(ROOT)} and "
                  f"{RESULTS_JSON.relative_to(ROOT)}[/green]")


if __name__ == "__main__":
    main()
