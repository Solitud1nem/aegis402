"""Mandate authentication: a compromised agent must not be able to forge/escalate the
trust anchor. Opt-in via Settings.require_signed_mandate + mandate_hmac_secret."""

from __future__ import annotations

from pathlib import Path

from aegis402.config import Settings
from aegis402.guard import Guard
from aegis402.mandate_auth import mandate_signature, verify_mandate
from aegis402.schemas import Mandate, VerdictType

from .conftest import ATTACKER, USDC, VENDOR

SECRET = "owner-top-secret-key"


# --- unit ------------------------------------------------------------------------------


def test_sign_then_verify_roundtrip() -> None:
    m = Mandate(allowlist=[VENDOR], limit=50 * USDC)
    m.signature = mandate_signature(m, SECRET)
    assert verify_mandate(m, SECRET) is True


def test_tampered_allowlist_fails_verification() -> None:
    """A signature minted for [VENDOR] must not validate once ATTACKER is appended."""
    signed = Mandate(allowlist=[VENDOR], limit=50 * USDC)
    sig = mandate_signature(signed, SECRET)
    forged = Mandate(allowlist=[VENDOR, ATTACKER], limit=50 * USDC, signature=sig)
    assert verify_mandate(forged, SECRET) is False


def test_raised_limit_fails_verification() -> None:
    signed = Mandate(allowlist=[VENDOR], limit=50 * USDC)
    forged = Mandate(allowlist=[VENDOR], limit=10_000 * USDC,
                     signature=mandate_signature(signed, SECRET))
    assert verify_mandate(forged, SECRET) is False


def test_missing_signature_is_invalid() -> None:
    assert verify_mandate(Mandate(allowlist=[VENDOR]), SECRET) is False


# --- guard end-to-end ------------------------------------------------------------------


def _guard(tmp_path: Path, **kw: object) -> Guard:
    return Guard(Settings(db_path=tmp_path / "ma.db", **kw))


def _payment(mandate: dict | None) -> dict:
    return {
        "user_request": f"Pay 5 USDC to {VENDOR}.",
        "untrusted_context": [],
        "payment_intent": {"recipient": VENDOR, "amount": 5 * USDC,
                           "asset": "USDC", "network": "base-sepolia"},
        "mandate": mandate,
    }


def _signed_mandate(**fields: object) -> dict:
    m = Mandate(**fields)  # type: ignore[arg-type]
    m.signature = mandate_signature(m, SECRET)
    return m.model_dump(mode="json")


def test_valid_signed_mandate_allows(tmp_path: Path) -> None:
    guard = _guard(tmp_path, require_signed_mandate=True, mandate_hmac_secret=SECRET)
    mandate = _signed_mandate(allowlist=[VENDOR], limit=50 * USDC)
    assert guard.inspect(_payment(mandate)).verdict == VerdictType.ALLOW


def test_forged_allowlist_blocks(tmp_path: Path) -> None:
    """Agent signs [VENDOR] but ships [VENDOR, ATTACKER] and pays ATTACKER -> BLOCK."""
    guard = _guard(tmp_path, require_signed_mandate=True, mandate_hmac_secret=SECRET)
    mandate = _signed_mandate(allowlist=[VENDOR], limit=50 * USDC)
    mandate["allowlist"] = [VENDOR, ATTACKER]  # tamper after signing
    raw = _payment(mandate)
    raw["payment_intent"]["recipient"] = ATTACKER
    assert guard.inspect(raw).verdict == VerdictType.BLOCK


def test_unsigned_mandate_blocks_when_required(tmp_path: Path) -> None:
    guard = _guard(tmp_path, require_signed_mandate=True, mandate_hmac_secret=SECRET)
    mandate = {"allowlist": [VENDOR], "limit": 50 * USDC}  # no signature
    assert guard.inspect(_payment(mandate)).verdict == VerdictType.BLOCK


def test_no_mandate_blocks_when_required(tmp_path: Path) -> None:
    guard = _guard(tmp_path, require_signed_mandate=True, mandate_hmac_secret=SECRET)
    assert guard.inspect(_payment(None)).verdict == VerdictType.BLOCK


def test_required_but_no_secret_fails_closed(tmp_path: Path) -> None:
    guard = _guard(tmp_path, require_signed_mandate=True)  # misconfig: no secret
    mandate = _signed_mandate(allowlist=[VENDOR], limit=50 * USDC)
    assert guard.inspect(_payment(mandate)).verdict == VerdictType.BLOCK


def test_disabled_by_default_unsigned_mandate_works(tmp_path: Path) -> None:
    """Back-compat: with the feature off, an unsigned mandate behaves as before."""
    guard = _guard(tmp_path)
    mandate = {"allowlist": [VENDOR], "limit": 50 * USDC}
    assert guard.inspect(_payment(mandate)).verdict == VerdictType.ALLOW
