"""L5 velocity / budget gate, mandate-scoping, and L3 mandate-TTL tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from aegis402.config import Settings
from aegis402.detectors.policy import PaymentPolicyGate
from aegis402.detectors.velocity import VelocityGate
from aegis402.interceptor import build_intent
from aegis402.ledger import SpendLedger
from aegis402.schemas import Mandate, resolve_spend_key

from .conftest import USDC, VENDOR


def _intent(raw_overrides: dict):
    base = {
        "user_request": f"Pay 5 USDC to {VENDOR}.",
        "untrusted_context": [],
        "payment_intent": {
            "recipient": VENDOR,
            "amount": 5 * USDC,
            "asset": "USDC",
            "network": "base-sepolia",
        },
    }
    base.update(raw_overrides)
    return build_intent(base)


def _mandate(**kw: object) -> dict:
    """A mandate dict whose ``id`` deterministically fixes the ledger scope."""
    return {"id": "agent-1", "allowlist": [VENDOR], **kw}


# --- mandate-scoping (security: scope cannot come from untrusted context) ----


def test_scope_derives_only_from_mandate_not_untrusted_fields() -> None:
    """Untrusted fields (request, context) must not influence the spend scope."""
    mandate = Mandate(id="agent-1", allowlist=[VENDOR])
    key = resolve_spend_key(mandate, "__server_default__")
    # The key is the mandate id regardless of any surrounding (untrusted) data.
    assert key == "agent-1"


def test_content_hash_scope_when_no_id_is_stable() -> None:
    """Without an id, equal mandate content yields one stable, prefixed key."""
    a = Mandate(allowlist=[VENDOR], limit=50 * USDC, total_budget=200 * USDC)
    b = Mandate(allowlist=[VENDOR], limit=50 * USDC, total_budget=200 * USDC)
    assert a.spend_key() == b.spend_key()
    assert a.spend_key().startswith("m:")


def test_content_hash_scope_changes_with_content() -> None:
    """Different mandate content → different scope (cannot collide budgets)."""
    a = Mandate(allowlist=[VENDOR], total_budget=200 * USDC)
    b = Mandate(allowlist=[VENDOR], total_budget=999 * USDC)
    assert a.spend_key() != b.spend_key()


def test_no_mandate_uses_fixed_server_key() -> None:
    """Without a mandate, spend is scoped to the configured fixed server key."""
    assert resolve_spend_key(None, "__server_default__") == "__server_default__"


# --- L5 velocity window ------------------------------------------------------


def test_velocity_window_breach_flagged(tmp_path: Path) -> None:
    settings = Settings(
        db_path=tmp_path / "v.db", velocity_cap=10 * USDC, velocity_window_seconds=3600
    )
    ledger = SpendLedger(settings)
    ledger.record_spend("agent-1", "USDC", 8 * USDC)
    gate = VelocityGate(settings, ledger)

    sig = gate.run(_intent({"mandate": _mandate()}))  # 8 + 5 = 13 > 10

    assert sig.score >= 0.9
    assert any(v["check"] == "velocity_window" for v in sig.evidence["violations"])


def test_velocity_window_within_cap_passes(tmp_path: Path) -> None:
    settings = Settings(
        db_path=tmp_path / "v.db", velocity_cap=10 * USDC, velocity_window_seconds=3600
    )
    ledger = SpendLedger(settings)
    ledger.record_spend("agent-1", "USDC", 3 * USDC)
    gate = VelocityGate(settings, ledger)

    sig = gate.run(_intent({"mandate": _mandate()}))  # 3 + 5 = 8 <= 10

    assert sig.score == 0.0


def test_velocity_window_excludes_old_spend(tmp_path: Path) -> None:
    settings = Settings(
        db_path=tmp_path / "v.db", velocity_cap=10 * USDC, velocity_window_seconds=3600
    )
    ledger = SpendLedger(settings)
    old = datetime.now(UTC) - timedelta(hours=2)
    ledger.record_spend("agent-1", "USDC", 8 * USDC, ts=old)  # outside window
    gate = VelocityGate(settings, ledger)

    sig = gate.run(_intent({"mandate": _mandate()}))  # only 5 in window

    assert sig.score == 0.0


def test_velocity_scoped_by_mandate(tmp_path: Path) -> None:
    """Spend under a different mandate scope does not count against this one."""
    settings = Settings(db_path=tmp_path / "v.db", velocity_cap=10 * USDC)
    ledger = SpendLedger(settings)
    ledger.record_spend("other-mandate", "USDC", 9 * USDC)
    gate = VelocityGate(settings, ledger)

    sig = gate.run(_intent({"mandate": _mandate()}))  # scope 'agent-1' unaffected

    assert sig.score == 0.0


def test_velocity_uses_server_key_without_mandate(tmp_path: Path) -> None:
    """No mandate → spend is scoped to the fixed server key (documented limit)."""
    settings = Settings(db_path=tmp_path / "v.db", velocity_cap=10 * USDC)
    ledger = SpendLedger(settings)
    ledger.record_spend(settings.velocity_default_key, "USDC", 8 * USDC)
    gate = VelocityGate(settings, ledger)

    sig = gate.run(_intent({}))  # no mandate → default scope → 8 + 5 > 10

    assert sig.score >= 0.9
    assert any(v["check"] == "velocity_window" for v in sig.evidence["violations"])


def test_velocity_disabled_by_default(tmp_path: Path) -> None:
    settings = Settings(db_path=tmp_path / "v.db")  # velocity_cap None
    ledger = SpendLedger(settings)
    ledger.record_spend("agent-1", "USDC", 1000 * USDC)
    gate = VelocityGate(settings, ledger)

    assert gate.run(_intent({"mandate": _mandate()})).score == 0.0


# --- L5 cumulative mandate budget -------------------------------------------


def test_total_budget_breach_flagged(tmp_path: Path) -> None:
    settings = Settings(db_path=tmp_path / "v.db")
    ledger = SpendLedger(settings)
    ledger.record_spend("agent-1", "USDC", 18 * USDC)
    gate = VelocityGate(settings, ledger)

    sig = gate.run(_intent({"mandate": _mandate(total_budget=20 * USDC)}))  # 18 + 5 > 20

    assert sig.score >= 0.9
    assert any(v["check"] == "total_budget" for v in sig.evidence["violations"])


def test_total_budget_within_cap_passes(tmp_path: Path) -> None:
    settings = Settings(db_path=tmp_path / "v.db")
    ledger = SpendLedger(settings)
    ledger.record_spend("agent-1", "USDC", 10 * USDC)
    gate = VelocityGate(settings, ledger)

    sig = gate.run(_intent({"mandate": _mandate(total_budget=20 * USDC)}))  # 10 + 5 <= 20

    assert sig.score == 0.0


# --- L3 mandate TTL ----------------------------------------------------------


def test_mandate_expired_flagged() -> None:
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    sig = PaymentPolicyGate().run(
        _intent({"mandate": {"allowlist": [VENDOR], "expires_at": past}})
    )
    assert any(v["check"] == "mandate_expired" for v in sig.evidence["violations"])
    assert sig.score >= 0.9


def test_mandate_not_expired_passes() -> None:
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    sig = PaymentPolicyGate().run(
        _intent({"mandate": {"allowlist": [VENDOR], "expires_at": future}})
    )
    assert not any(
        v["check"] == "mandate_expired" for v in sig.evidence.get("violations", [])
    )
