"""Demo: stateful L5 velocity — "death by a thousand cuts".

Each payment is individually within every per-payment limit, but they aggregate over
a trailing window. Aegis402 ALLOWs them until the cumulative spend would breach the
configured velocity cap, then BLOCKs via L5 — something no single-payment check sees.

Run:  uv run python scripts/demo_velocity.py
The ledger lives in a throwaway temp DB, so the script writes nothing to the repo.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from aegis402.config import Settings
from aegis402.guard import Guard
from aegis402.schemas import VerdictType

USDC = 1_000_000
VENDOR = "0x1111111111111111111111111111111111111111"

# Each payment (20 USDC) is far below the 100-USDC high-stakes line; only their
# trailing-window sum, capped at 100 USDC, can trip — and only at the 6th payment.
PAYMENT = 20 * USDC
CAP = 100 * USDC
ATTEMPTS = 6


def _payment() -> dict:
    return {
        "user_request": f"Pay 20 USDC to {VENDOR} for the metered API.",
        "untrusted_context": ["Usage invoice: 20 USDC for this billing cycle."],
        "payment_intent": {
            "recipient": VENDOR,
            "amount": PAYMENT,
            "asset": "USDC",
            "network": "base-sepolia",
        },
    }


def main() -> None:
    console = Console()
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(db_path=Path(tmp) / "velocity.db", velocity_cap=CAP)
        guard = Guard(settings)

        console.print(
            Panel(
                f"per-payment: 20 USDC  ·  velocity cap: {CAP // USDC} USDC / 1h window\n"
                f"each payment is individually fine; watch the cumulative sum.",
                title="L5 velocity demo — death by a thousand cuts",
            )
        )

        table = Table("#", "this payment", "cumulative", "verdict", "via")
        cumulative = 0
        for i in range(1, ATTEMPTS + 1):
            verdict = guard.inspect(_payment())
            allowed = verdict.verdict == VerdictType.ALLOW
            if allowed:
                cumulative += PAYMENT // USDC
            l5 = next((s for s in verdict.triggered_layers if s.layer == "L5"), None)
            style = "green" if allowed else "bold red"
            table.add_row(
                str(i),
                "20 USDC",
                f"{cumulative} USDC",
                f"[{style}]{verdict.verdict.value}[/{style}]",
                l5.reason if l5 else "-",
            )

        console.print(table)
        console.print(
            "[bold]→ the 6th payment is blocked by L5[/bold] — aggregate over time, "
            "not any single payment, is the attack surface."
        )


if __name__ == "__main__":
    main()
