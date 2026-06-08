"""Spend-ledger reconciliation seam (#2): pending / settled / voided accounting."""

from __future__ import annotations

from pathlib import Path

from aegis402.config import Settings
from aegis402.ledger import SpendLedger, SpendStatus

from .conftest import USDC

SCOPE = "mandate-1"


def _ledger(tmp_path: Path) -> SpendLedger:
    return SpendLedger(Settings(db_path=tmp_path / "ledger.db"))


def test_record_returns_reconciliation_id(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    spend_id = ledger.record_spend(SCOPE, "USDC", 10 * USDC)
    assert isinstance(spend_id, int)


def test_pending_spend_counts(tmp_path: Path) -> None:
    """A freshly recorded (pending) payment counts toward spend — fail-safe."""
    ledger = _ledger(tmp_path)
    ledger.record_spend(SCOPE, "USDC", 10 * USDC)
    assert ledger.total_spent(SCOPE, "USDC") == 10 * USDC


def test_void_frees_headroom(tmp_path: Path) -> None:
    """Voiding an unsettled payment removes it from all accounting."""
    ledger = _ledger(tmp_path)
    keep = ledger.record_spend(SCOPE, "USDC", 10 * USDC)
    drop = ledger.record_spend(SCOPE, "USDC", 7 * USDC)
    assert ledger.total_spent(SCOPE, "USDC") == 17 * USDC

    assert ledger.void(drop) is True
    assert ledger.total_spent(SCOPE, "USDC") == 10 * USDC
    assert ledger.spent_in_window(SCOPE, "USDC", 3600) == 10 * USDC
    # The kept record is untouched.
    assert keep != drop


def test_settled_still_counts(tmp_path: Path) -> None:
    """Confirming settlement keeps the spend counted (only voiding frees it)."""
    ledger = _ledger(tmp_path)
    spend_id = ledger.record_spend(SCOPE, "USDC", 12 * USDC)
    assert ledger.mark_settled(spend_id) is True
    assert ledger.total_spent(SCOPE, "USDC") == 12 * USDC


def test_reconcile_unknown_id_returns_false(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    assert ledger.void(9999) is False
    assert ledger.mark_settled(9999) is False


def test_status_default_is_pending(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    ledger.record_spend(SCOPE, "USDC", 5 * USDC)
    rows = ledger._rows(SCOPE, "USDC")
    assert rows and rows[0].status == SpendStatus.PENDING
