"""Evidence log — tamper-evident record of BLOCK/REVIEW decisions.

Each non-ALLOW verdict (configurably also ALLOW) is persisted to SQLite with the
diff of *intended vs attempted* payment, which layers fired, and a sha256 of the
normalized input. Records export to JSON for a future on-chain EAS attestation.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Column
from sqlmodel import JSON, Field, Session, SQLModel, create_engine, select

from .config import Settings, get_settings
from .interceptor import input_hash
from .schemas import Intent, Verdict, VerdictType


class EvidenceRecord(SQLModel, table=True):
    """One persisted guard decision."""

    __tablename__ = "evidence"

    id: str = Field(primary_key=True)
    ts: str
    verdict: str
    score: float
    triggered_layers: list[dict[str, Any]] = Field(
        default_factory=list, sa_column=Column(JSON)
    )
    intended: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    attempted: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    input_hash: str
    reason: str = ""


class EvidenceLog:
    """SQLite-backed evidence store with JSON export."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        path: Path = self._settings.db_path
        # Multithread-safe SQLite (FastAPI threadpool): share pooled connections across
        # threads and wait on a busy lock rather than erroring.
        self._engine = create_engine(
            f"sqlite:///{path}",
            echo=False,
            connect_args={"timeout": 30, "check_same_thread": False},
        )
        SQLModel.metadata.create_all(self._engine)

    def record(self, intent: Intent, verdict: Verdict) -> str:
        """Persist a verdict and return its evidence id (set on the verdict too).

        ``intended`` captures any recipient/amount the owner named in the request;
        ``attempted`` is what the agent was about to pay — the audit-critical diff.
        """
        evidence_id = str(uuid.uuid4())
        pi = intent.payment_intent
        record = EvidenceRecord(
            id=evidence_id,
            ts=datetime.now(UTC).isoformat(),
            verdict=verdict.verdict.value,
            score=verdict.score,
            triggered_layers=[s.model_dump() for s in verdict.triggered_layers],
            intended={"user_request": intent.user_request},
            attempted=pi.model_dump(),
            input_hash=input_hash(intent),
            reason=verdict.reason,
        )
        with Session(self._engine) as session:
            session.add(record)
            session.commit()
        verdict.evidence_id = evidence_id
        return evidence_id

    def should_record(self, verdict: Verdict) -> bool:
        """ALLOW outcomes are not persisted; BLOCK/REVIEW always are."""
        return verdict.verdict in {VerdictType.BLOCK, VerdictType.REVIEW}

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        """Fetch a single evidence record by id."""
        with Session(self._engine) as session:
            return session.get(EvidenceRecord, evidence_id)

    def all_records(self) -> list[EvidenceRecord]:
        """Return every persisted evidence record (newest order is not guaranteed)."""
        with Session(self._engine) as session:
            return list(session.exec(select(EvidenceRecord)).all())

    def export_json(self) -> str:
        """Export all evidence records as a JSON array (EAS-attestation feed)."""
        return json.dumps(
            [r.model_dump() for r in self.all_records()], indent=2, sort_keys=True
        )
