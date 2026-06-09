"""Mandate revocation store — revoke a signed mandate before it expires.

Signed mandates (:mod:`aegis402.mandate_auth`) are authenticated and expiry-bounded, but a
valid one stays replayable until it expires. This store lets the owner revoke a specific
mandate *identity* — its :meth:`~aegis402.schemas.Mandate.spend_key` (explicit ``id`` or a
hash of its content) — so the guard rejects it immediately, closing the early-revocation
gap. Only meaningful under ``require_signed_mandate``, where the mandate identity is
authenticated (otherwise an agent could just present a different, non-revoked mandate).

SQLite-backed (shares the guard's DB); the revoked key is the primary key, so revoking is
idempotent and survives restarts.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from sqlmodel import Field, Session, SQLModel, create_engine, select

from .config import Settings, get_settings


class RevocationRecord(SQLModel, table=True):
    """One revoked mandate identity."""

    __tablename__ = "mandate_revocations"

    key: str = Field(primary_key=True)  # the mandate's spend_key
    ts: str
    reason: str = ""


class RevocationStore:
    """SQLite-backed set of revoked mandate identities."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        path: Path = self._settings.db_path
        self._engine = create_engine(
            f"sqlite:///{path}",
            echo=False,
            connect_args={"timeout": 30, "check_same_thread": False},
        )
        SQLModel.metadata.create_all(self._engine)

    def revoke(self, key: str, reason: str = "", ts: datetime | None = None) -> bool:
        """Revoke a mandate identity. Idempotent: returns True whether newly added or
        already present (the end state — revoked — is what matters)."""
        when = (ts or datetime.now(UTC)).astimezone(UTC).isoformat()
        with Session(self._engine) as session:
            if session.get(RevocationRecord, key) is None:
                session.add(RevocationRecord(key=key, ts=when, reason=reason))
                session.commit()
        return True

    def is_revoked(self, key: str) -> bool:
        """True if ``key`` has been revoked."""
        with Session(self._engine) as session:
            return session.get(RevocationRecord, key) is not None

    def list_revoked(self) -> list[str]:
        """All revoked mandate keys."""
        with Session(self._engine) as session:
            return list(session.exec(select(RevocationRecord.key)).all())
