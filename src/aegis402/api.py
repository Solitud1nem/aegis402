"""FastAPI surface for Aegis402.

Endpoints:
* ``POST /guard/inspect`` — the primary insertion point; raw intent → verdict.
* ``GET  /health``        — liveness plus whether the L2 model is enabled.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI

from .config import get_settings
from .guard import Guard
from .schemas import Intent, Verdict

app = FastAPI(title="Aegis402", version="0.1.0")
_guard = Guard()


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness probe with key runtime flags."""
    s = get_settings()
    return {"status": "ok", "l2_enabled": s.l2_enabled, "fail_closed": s.fail_closed}


@app.post("/guard/inspect", response_model=Verdict)
def inspect(intent: Intent) -> Verdict:
    """Inspect a payment intent and return ALLOW / BLOCK / REVIEW."""
    return _guard.inspect(intent.model_dump())
