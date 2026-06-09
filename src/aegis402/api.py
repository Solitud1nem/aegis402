"""FastAPI surface for Aegis402.

Endpoints:
* ``POST /guard/inspect``   — the primary insertion point; raw intent → verdict.
* ``POST /guard/reconcile`` — settle/void a reserved spend by its ``spend_id``.
* ``POST /mandate/revoke``  — revoke a signed mandate by its identity.
* ``GET  /evidence/verify`` — verify the evidence hash chain.
* ``GET  /health``          — liveness plus whether the L2 model is enabled.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from pydantic import BaseModel, Field

from .config import get_settings
from .guard import Guard
from .schemas import Intent, Verdict

app = FastAPI(title="Aegis402", version="0.1.0")
_guard = Guard()


class ReconcileRequest(BaseModel):
    """Reconcile a reserved spend once its on-chain outcome is known."""

    spend_id: int = Field(description="The Verdict.spend_id returned for an ALLOW.")
    settled: bool = Field(description="True = confirm settled; False = void (free headroom).")


class RevokeRequest(BaseModel):
    """Revoke a signed mandate by its identity (its spend_key)."""

    mandate_key: str = Field(description="The mandate's spend_key (explicit id or content hash).")
    reason: str = Field(default="", description="Optional audit note.")


@app.get("/health")
def health() -> dict[str, Any]:
    """Liveness probe with key runtime flags."""
    s = get_settings()
    return {"status": "ok", "l2_enabled": s.l2_enabled, "fail_closed": s.fail_closed}


@app.post("/guard/inspect", response_model=Verdict)
def inspect(intent: Intent) -> Verdict:
    """Inspect a payment intent and return ALLOW / BLOCK / REVIEW."""
    return _guard.inspect(intent.model_dump())


@app.post("/guard/reconcile")
def reconcile(req: ReconcileRequest) -> dict[str, Any]:
    """Settle or void a reserved spend so a never-settled payment frees its headroom."""
    ok = _guard.reconcile(req.spend_id, settled=req.settled)
    return {"ok": ok, "spend_id": req.spend_id, "settled": req.settled}


@app.post("/mandate/revoke")
def revoke_mandate(req: RevokeRequest) -> dict[str, Any]:
    """Revoke a signed mandate so the guard rejects it before expiry."""
    ok = _guard.revoke_mandate(req.mandate_key, req.reason)
    return {"ok": ok, "mandate_key": req.mandate_key}


@app.get("/evidence/verify")
def verify_evidence() -> dict[str, Any]:
    """Verify the evidence hash chain; report the first broken record if tampered."""
    ok, broken_id = _guard.verify_evidence_chain()
    return {"intact": ok, "first_broken_id": broken_id}
