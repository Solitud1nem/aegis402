"""Spend ledger — stateful record of allowed payments for velocity / budget checks.

The guard itself never executes a payment, so it cannot observe on-chain spend.
As a deterministic proxy, :class:`~aegis402.guard.Guard` appends an entry here for
every **ALLOW** verdict (the agent is then free to pay). The L5 velocity gate reads
this ledger to enforce per-window rate limits and cumulative mandate budgets.

Entries are keyed by ``(scope, asset)``: amounts in different assets are not
comparable, and ``scope`` is the mandate-derived spend key (see
:func:`~aegis402.schemas.resolve_spend_key`) — never an agent-controlled value.
Storage shares the same SQLite database as the evidence log.

**Reconciliation (approved ≠ settled).** A recorded payment is ``pending``: the guard
allowed it, but cannot see whether it actually settled on-chain. Counting pending spend
is the fail-safe choice (over-block, never over-allow). When the outcome is known, an
integrator reconciles via :meth:`SpendLedger.mark_settled` (confirm) or
:meth:`SpendLedger.void` (settlement failed → free the headroom). Voided rows are
excluded from all accounting. Surfacing the spend id through the guard/adapter so a
caller can reconcile is left to post-hackathon wiring.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from sqlmodel import Field, Session, SQLModel, create_engine, select

from .config import Settings, get_settings


class SpendStatus(StrEnum):
    """Lifecycle of a recorded spend."""

    PENDING = "pending"  # allowed by the guard; settlement not yet confirmed
    SETTLED = "settled"  # confirmed settled on-chain
    VOIDED = "voided"  # never settled / reversed — excluded from accounting


class SpendRecord(SQLModel, table=True):
    """One allowed payment, recorded for velocity / budget accounting."""

    __tablename__ = "spend_ledger"

    id: int | None = Field(default=None, primary_key=True)
    scope: str = Field(index=True)
    asset: str = Field(index=True)
    amount: int
    ts: str
    status: str = Field(default=SpendStatus.PENDING, index=True)


class SpendLedger:
    """SQLite-backed ledger of allowed spend, scoped by ``(scope, asset)``."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        path: Path = self._settings.db_path
        # Multithread-safe SQLite: the guard runs under a threadpool (FastAPI) and the
        # spend lock serializes pooled connections across threads (check_same_thread off);
        # busy timeout makes a contended writer wait instead of erroring ("database is
        # locked"), which would otherwise fail-closed into a spurious BLOCK.
        self._engine = create_engine(
            f"sqlite:///{path}",
            echo=False,
            connect_args={"timeout": 30, "check_same_thread": False},
        )
        SQLModel.metadata.create_all(self._engine)

    def record_spend(
        self, scope: str, asset: str, amount: int, ts: datetime | None = None
    ) -> int:
        """Append an allowed (``pending``) payment; return its reconciliation id."""
        when = (ts or datetime.now(UTC)).astimezone(UTC).isoformat()
        record = SpendRecord(scope=scope, asset=asset, amount=amount, ts=when)
        with Session(self._engine) as session:
            session.add(record)
            session.commit()
            session.refresh(record)
        assert record.id is not None  # populated by the DB on commit
        return record.id

    def _set_status(self, spend_id: int, status: SpendStatus) -> bool:
        """Transition a record's status; return False if the id is unknown."""
        with Session(self._engine) as session:
            record = session.get(SpendRecord, spend_id)
            if record is None:
                return False
            record.status = status
            session.add(record)
            session.commit()
        return True

    def mark_settled(self, spend_id: int) -> bool:
        """Confirm a payment settled. Returns False if the id is unknown."""
        return self._set_status(spend_id, SpendStatus.SETTLED)

    def void(self, spend_id: int) -> bool:
        """Void a payment that never settled, freeing its headroom. False if unknown."""
        return self._set_status(spend_id, SpendStatus.VOIDED)

    def _rows(self, scope: str, asset: str) -> list[SpendRecord]:
        """Active (non-voided) records for the scope/asset."""
        with Session(self._engine) as session:
            stmt = select(SpendRecord).where(
                SpendRecord.scope == scope,
                SpendRecord.asset == asset,
                SpendRecord.status != SpendStatus.VOIDED,
            )
            return list(session.exec(stmt).all())

    def total_spent(self, scope: str, asset: str) -> int:
        """Cumulative spend recorded for ``(scope, asset)``."""
        return sum(r.amount for r in self._rows(scope, asset))

    def spent_in_window(
        self,
        scope: str,
        asset: str,
        window_seconds: int,
        now: datetime | None = None,
    ) -> int:
        """Spend recorded for ``(scope, asset)`` within the trailing window."""
        cutoff = (now or datetime.now(UTC)) - timedelta(seconds=window_seconds)
        total = 0
        for r in self._rows(scope, asset):
            ts = datetime.fromisoformat(r.ts)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            if ts >= cutoff:
                total += r.amount
        return total
