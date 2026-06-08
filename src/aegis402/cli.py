"""Typer CLI for Aegis402 — demo and operations.

Commands:
* ``inspect <intent.json>`` — vet one intent, pretty-print the verdict (demo).
* ``replay <suite-dir>``    — run a directory of intents, report recall/FP/latency.
* ``serve``                 — run the HTTP API.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .config import get_settings
from .guard import Guard
from .schemas import Verdict, VerdictType

app = typer.Typer(help="Aegis402 — prompt-injection guard for agentic x402 payments.")
console = Console()

_VERDICT_STYLE = {
    VerdictType.ALLOW: "bold green",
    VerdictType.BLOCK: "bold red",
    VerdictType.REVIEW: "bold yellow",
}


def _render_verdict(verdict: Verdict, source: str) -> None:
    """Pretty-print a verdict with its triggered layers."""
    style = _VERDICT_STYLE[verdict.verdict]
    body = Table.grid(padding=(0, 1))
    body.add_row("verdict:", f"[{style}]{verdict.verdict.value}[/{style}]")
    body.add_row("score:", f"{verdict.score:.2f}")
    body.add_row("reason:", verdict.reason)
    if verdict.evidence_id:
        body.add_row("evidence:", verdict.evidence_id)
    if verdict.triggered_layers:
        layers = Table("layer", "score", "reason", box=None, pad_edge=False)
        for s in verdict.triggered_layers:
            layers.add_row(s.layer, f"{s.score:.2f}", s.reason)
        body.add_row("layers:", layers)
    console.print(Panel(body, title=f"Aegis402 · {source}", border_style=style))


@app.command()
def inspect(intent_path: Path = typer.Argument(..., help="Path to an intent JSON file.")) -> None:
    """Inspect a single intent file and print the verdict."""
    raw: dict[str, Any] = json.loads(intent_path.read_text())
    verdict = Guard().inspect(raw)
    _render_verdict(verdict, intent_path.name)
    raise typer.Exit(code=0 if verdict.verdict == VerdictType.ALLOW else 2)


@app.command()
def replay(
    suite_dir: Path = typer.Argument(..., help="Directory of *.json intents."),
    expect: str = typer.Option(
        "BLOCK", help="Expected non-ALLOW verdict for these cases (BLOCK/REVIEW/ALLOW)."
    ),
) -> None:
    """Run every intent in a directory and report detection metrics and latency."""
    guard = Guard()
    files = sorted(suite_dir.glob("*.json"))
    if not files:
        console.print(f"[red]no .json intents in {suite_dir}[/red]")
        raise typer.Exit(code=1)

    expected = VerdictType(expect.upper())
    benign = expected == VerdictType.ALLOW
    table = Table("case", "verdict", "score", "ms", "ok")
    hits = 0
    latencies: list[float] = []
    for f in files:
        raw = json.loads(f.read_text())
        t0 = time.perf_counter()
        v = guard.inspect(raw)
        dt = (time.perf_counter() - t0) * 1000
        latencies.append(dt)
        ok = (v.verdict == VerdictType.ALLOW) if benign else (v.verdict != VerdictType.ALLOW)
        hits += int(ok)
        mark = "[green]✓[/green]" if ok else "[red]✗[/red]"
        table.add_row(f.name, v.verdict.value, f"{v.score:.2f}", f"{dt:.0f}", mark)

    console.print(table)
    n = len(files)
    metric = "false-positive rate" if benign else "recall"
    rate = (n - hits) / n if benign else hits / n
    p95 = sorted(latencies)[int(0.95 * (n - 1))]
    console.print(
        Panel(
            f"cases: {n}\n"
            f"{metric}: {rate:.0%}\n"
            f"latency: avg {sum(latencies) / n:.0f}ms · p95 {p95:.0f}ms",
            title="replay summary",
        )
    )


@app.command()
def serve(
    host: str = typer.Option(None, help="Bind host (default from config)."),
    port: int = typer.Option(None, help="Bind port (default from config)."),
) -> None:
    """Run the HTTP API."""
    import uvicorn

    s = get_settings()
    uvicorn.run("aegis402.api:app", host=host or s.host, port=port or s.port)


@app.command()
def attest(
    out: Path = typer.Option(None, help="Write attestations to this file instead of stdout."),
) -> None:
    """Export the evidence log as EAS attestation payloads (stub, not on-chain)."""
    from .attestation import export_attestations
    from .evidence import EvidenceLog

    payloads = export_attestations(EvidenceLog())
    text = json.dumps(payloads, indent=2, sort_keys=True)
    if out is not None:
        out.write_text(text)
        console.print(f"[green]wrote {len(payloads)} attestation(s) to {out}[/green]")
    else:
        console.print_json(text)


if __name__ == "__main__":
    app()
