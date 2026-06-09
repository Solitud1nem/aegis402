"""Evidence log tamper-evidence: the hash chain detects edits, deletions, reordering."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from aegis402.config import Settings
from aegis402.evidence import EvidenceLog
from aegis402.schemas import Intent, Verdict, VerdictType

from .conftest import ATTACKER, USDC, VENDOR


def _log(tmp_path: Path) -> EvidenceLog:
    return EvidenceLog(Settings(db_path=tmp_path / "ev.db"))


def _intent() -> Intent:
    return Intent(
        user_request=f"Pay 5 USDC to {VENDOR}.",
        untrusted_context=[],
        payment_intent={"recipient": ATTACKER, "amount": 5 * USDC,
                        "asset": "USDC", "network": "base-sepolia"},
    )


def _verdict(reason: str) -> Verdict:
    return Verdict(verdict=VerdictType.BLOCK, score=0.9, reason=reason)


def _record_three(log: EvidenceLog) -> list[str]:
    return [log.record(_intent(), _verdict(f"r{i}")) for i in range(3)]


def test_chain_intact_after_appends(tmp_path: Path) -> None:
    log = _log(tmp_path)
    _record_three(log)
    assert log.verify_chain() == (True, None)


def test_inplace_edit_is_detected(tmp_path: Path) -> None:
    log = _log(tmp_path)
    ids = _record_three(log)
    con = sqlite3.connect(str(tmp_path / "ev.db"))
    con.execute("UPDATE evidence SET reason = ? WHERE id = ?", ("TAMPERED", ids[1]))
    con.commit()
    con.close()
    ok, broken = log.verify_chain()
    assert ok is False and broken == ids[1]


def test_deletion_is_detected(tmp_path: Path) -> None:
    log = _log(tmp_path)
    ids = _record_three(log)
    con = sqlite3.connect(str(tmp_path / "ev.db"))
    con.execute("DELETE FROM evidence WHERE id = ?", (ids[1],))
    con.commit()
    con.close()
    ok, broken = log.verify_chain()
    # The record after the gap has a prev_hash that no longer matches the recomputed tip.
    assert ok is False and broken == ids[2]


def test_rehashed_edit_still_breaks_linkage(tmp_path: Path) -> None:
    """Even if an attacker recomputes the edited record's own entry_hash, the *next*
    record's prev_hash no longer matches — the chain still breaks."""
    log = _log(tmp_path)
    ids = _record_three(log)
    import hashlib
    import json

    con = sqlite3.connect(str(tmp_path / "ev.db"))
    row = con.execute(
        "SELECT seq, ts, verdict, score, triggered_layers, intended, attempted, "
        "input_hash, prev_hash FROM evidence WHERE id = ?", (ids[1],)
    ).fetchone()
    seq, ts, verdict, score, tl, intended, attempted, ih, prev = row
    content = {
        "seq": seq, "id": ids[1], "ts": ts, "verdict": verdict, "score": score,
        "triggered_layers": json.loads(tl), "intended": json.loads(intended),
        "attempted": json.loads(attempted), "input_hash": ih, "reason": "TAMPERED",
        "prev_hash": prev,
    }
    new_hash = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    con.execute(
        "UPDATE evidence SET reason = ?, entry_hash = ? WHERE id = ?",
        ("TAMPERED", new_hash, ids[1]),
    )
    con.commit()
    con.close()
    ok, broken = log.verify_chain()
    # ids[1] now self-verifies, but ids[2].prev_hash points at the *old* hash -> break there.
    assert ok is False and broken == ids[2]
