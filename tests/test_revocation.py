"""Mandate revocation: a signed mandate can be rejected before it expires."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from aegis402.config import Settings
from aegis402.guard import Guard
from aegis402.mandate_auth import mandate_signature
from aegis402.revocation import RevocationStore
from aegis402.schemas import Mandate, VerdictType

from .conftest import USDC, VENDOR

SECRET = "owner-top-secret-key"
FUTURE = datetime(2099, 1, 1, tzinfo=UTC)


# --- store unit ------------------------------------------------------------------------


def test_store_revoke_and_query(tmp_path: Path) -> None:
    store = RevocationStore(Settings(db_path=tmp_path / "r.db"))
    assert store.is_revoked("agent-1") is False
    assert store.revoke("agent-1", "leaked") is True
    assert store.is_revoked("agent-1") is True
    assert "agent-1" in store.list_revoked()


def test_store_revoke_is_idempotent(tmp_path: Path) -> None:
    store = RevocationStore(Settings(db_path=tmp_path / "r.db"))
    assert store.revoke("agent-1") is True
    assert store.revoke("agent-1") is True
    assert store.list_revoked() == ["agent-1"]


# --- guard end-to-end ------------------------------------------------------------------


def _signed(mandate: Mandate) -> dict:
    mandate.signature = mandate_signature(mandate, SECRET)
    return mandate.model_dump(mode="json")


def _payment(mandate: dict) -> dict:
    return {
        "user_request": f"Pay 5 USDC to {VENDOR}.",
        "untrusted_context": [],
        "payment_intent": {"recipient": VENDOR, "amount": 5 * USDC,
                           "asset": "USDC", "network": "base-sepolia"},
        "mandate": mandate,
    }


def test_revoked_mandate_blocks(tmp_path: Path) -> None:
    guard = Guard(Settings(db_path=tmp_path / "g.db",
                           require_signed_mandate=True, mandate_hmac_secret=SECRET))
    mandate = Mandate(id="agent-1", allowlist=[VENDOR], limit=50 * USDC, expires_at=FUTURE)
    raw = _payment(_signed(mandate))

    assert guard.inspect(raw).verdict == VerdictType.ALLOW  # valid before revocation
    assert guard.revoke_mandate(mandate.spend_key(), "key leaked") is True
    assert guard.inspect(raw).verdict == VerdictType.BLOCK  # rejected after revocation


def test_revocation_targets_only_the_revoked_identity(tmp_path: Path) -> None:
    guard = Guard(Settings(db_path=tmp_path / "g.db",
                           require_signed_mandate=True, mandate_hmac_secret=SECRET))
    a = Mandate(id="agent-1", allowlist=[VENDOR], limit=50 * USDC, expires_at=FUTURE)
    b = Mandate(id="agent-2", allowlist=[VENDOR], limit=50 * USDC, expires_at=FUTURE)
    guard.revoke_mandate(a.spend_key())

    assert guard.inspect(_payment(_signed(a))).verdict == VerdictType.BLOCK
    assert guard.inspect(_payment(_signed(b))).verdict == VerdictType.ALLOW
