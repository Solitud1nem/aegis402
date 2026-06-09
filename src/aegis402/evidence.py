"""Evidence log — tamper-evident record of BLOCK/REVIEW decisions.

Each non-ALLOW verdict (configurably also ALLOW) is persisted to SQLite with the
diff of *intended vs attempted* payment, which layers fired, and a sha256 of the
normalized input. Records export to JSON for a future on-chain EAS attestation.

Tamper-evidence is a **hash chain**: each record stores the hash of the previous
record plus a hash over its own content (``entry_hash``). Modifying, deleting or
reordering any record breaks the chain — :meth:`EvidenceLog.verify_chain` recomputes it
and points at the first broken link. (A determined host attacker can still re-chain from
the tampered point forward; pinning the chain head externally — e.g. the EAS attestation
roadmap — closes that. The chain alone defeats silent in-place edits.)
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Column, event
from sqlmodel import JSON, Field, Session, SQLModel, create_engine, select

from .config import Settings, get_settings
from .interceptor import input_hash
from .schemas import Intent, Verdict, VerdictType

_GENESIS = "0" * 64


def _entry_hash(content: dict[str, Any]) -> str:
    """Deterministic sha256 over a record's chained content (includes ``prev_hash``)."""
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _chain_content(
    *,
    seq: int,
    rec_id: str,
    ts: str,
    verdict: str,
    score: float,
    triggered_layers: list[dict[str, Any]],
    intended: dict[str, Any],
    attempted: dict[str, Any],
    input_hash_: str,
    reason: str,
    prev_hash: str,
) -> dict[str, Any]:
    """The exact field set hashed into ``entry_hash`` — identical at write and verify."""
    return {
        "seq": seq,
        "id": rec_id,
        "ts": ts,
        "verdict": verdict,
        "score": score,
        "triggered_layers": triggered_layers,
        "intended": intended,
        "attempted": attempted,
        "input_hash": input_hash_,
        "reason": reason,
        "prev_hash": prev_hash,
    }


class EvidenceRecord(SQLModel, table=True):
    """One persisted guard decision."""

    __tablename__ = "evidence"

    id: str = Field(primary_key=True)
    seq: int = Field(index=True)  # monotonic insertion order; defines the chain sequence
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
    prev_hash: str = _GENESIS  # entry_hash of the previous record (chain link)
    entry_hash: str = ""  # sha256 over this record's content + prev_hash


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
        # BEGIN IMMEDIATE on every transaction so the chain-append read (last entry_hash)
        # and the insert are serialized across threads/processes — otherwise two writers
        # could read the same tip and fork the chain. (Same recipe as the spend ledger.)
        @event.listens_for(self._engine, "connect")
        def _sqlite_autobegin_off(dbapi_conn: object, _rec: object) -> None:
            dbapi_conn.isolation_level = None  # type: ignore[attr-defined]

        @event.listens_for(self._engine, "begin")
        def _sqlite_begin_immediate(conn: object) -> None:
            conn.exec_driver_sql("BEGIN IMMEDIATE")  # type: ignore[attr-defined]

        SQLModel.metadata.create_all(self._engine)

    def record(self, intent: Intent, verdict: Verdict) -> str:
        """Persist a verdict and return its evidence id (set on the verdict too).

        ``intended`` captures any recipient/amount the owner named in the request;
        ``attempted`` is what the agent was about to pay — the audit-critical diff. The
        record is appended to the tamper-evident hash chain.
        """
        evidence_id = str(uuid.uuid4())
        pi = intent.payment_intent
        ts = datetime.now(UTC).isoformat()
        triggered = [s.model_dump() for s in verdict.triggered_layers]
        intended = {"user_request": intent.user_request}
        attempted = pi.model_dump()
        ih = input_hash(intent)
        with Session(self._engine) as session:
            # The SELECT runs inside the IMMEDIATE transaction (write lock already held),
            # so the chain tip cannot move between read and insert.
            tip = session.exec(
                select(EvidenceRecord).order_by(EvidenceRecord.seq.desc())
            ).first()
            seq = (tip.seq + 1) if tip is not None else 0
            prev_hash = tip.entry_hash if tip is not None else _GENESIS
            entry_hash = _entry_hash(
                _chain_content(
                    seq=seq, rec_id=evidence_id, ts=ts, verdict=verdict.verdict.value,
                    score=verdict.score, triggered_layers=triggered, intended=intended,
                    attempted=attempted, input_hash_=ih, reason=verdict.reason,
                    prev_hash=prev_hash,
                )
            )
            session.add(
                EvidenceRecord(
                    id=evidence_id, seq=seq, ts=ts, verdict=verdict.verdict.value,
                    score=verdict.score, triggered_layers=triggered, intended=intended,
                    attempted=attempted, input_hash=ih, reason=verdict.reason,
                    prev_hash=prev_hash, entry_hash=entry_hash,
                )
            )
            session.commit()
        verdict.evidence_id = evidence_id
        return evidence_id

    def verify_chain(self) -> tuple[bool, str | None]:
        """Recompute the hash chain over all records in sequence.

        Returns ``(True, None)`` if intact, else ``(False, <id of first broken record>)``.
        Detects in-place edits (content/entry_hash mismatch), deletions and reordering
        (prev_hash linkage breaks).
        """
        prev_hash = _GENESIS
        with Session(self._engine) as session:
            rows = list(
                session.exec(select(EvidenceRecord).order_by(EvidenceRecord.seq.asc()))
            )
        for r in rows:
            expected = _entry_hash(
                _chain_content(
                    seq=r.seq, rec_id=r.id, ts=r.ts, verdict=r.verdict, score=r.score,
                    triggered_layers=r.triggered_layers, intended=r.intended,
                    attempted=r.attempted, input_hash_=r.input_hash, reason=r.reason,
                    prev_hash=prev_hash,
                )
            )
            if r.prev_hash != prev_hash or r.entry_hash != expected:
                return (False, r.id)
            prev_hash = r.entry_hash
        return (True, None)

    def should_record(self, verdict: Verdict) -> bool:
        """ALLOW outcomes are not persisted; BLOCK/REVIEW always are."""
        return verdict.verdict in {VerdictType.BLOCK, VerdictType.REVIEW}

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        """Fetch a single evidence record by id."""
        with Session(self._engine) as session:
            return session.get(EvidenceRecord, evidence_id)

    def all_records(self) -> list[EvidenceRecord]:
        """Return every persisted evidence record in chain (insertion) order."""
        with Session(self._engine) as session:
            return list(
                session.exec(select(EvidenceRecord).order_by(EvidenceRecord.seq.asc())).all()
            )

    def export_json(self) -> str:
        """Export all evidence records as a JSON array (EAS-attestation feed)."""
        return json.dumps(
            [r.model_dump() for r in self.all_records()], indent=2, sort_keys=True
        )
