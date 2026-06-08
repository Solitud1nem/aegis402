"""EAS attestation export (stub) tests."""

from __future__ import annotations

from aegis402.attestation import EAS_SCHEMA, evidence_to_attestation, export_attestations
from aegis402.config import Settings
from aegis402.evidence import EvidenceLog
from aegis402.guard import Guard


def test_attestation_shape_matches_schema(settings: Settings, attack_raw: dict) -> None:
    guard = Guard(settings)
    guard.inspect(attack_raw)  # produces one BLOCK evidence record
    log = EvidenceLog(settings)

    payloads = export_attestations(log)
    assert len(payloads) == 1
    att = payloads[0]
    assert att["schema"] == EAS_SCHEMA
    assert att["onchain"] is False

    field_names = [d["name"] for d in att["data"]]
    assert field_names == [
        "evidenceId", "timestamp", "verdict", "scoreBps", "inputHash", "reason"
    ]
    by_name = {d["name"]: d for d in att["data"]}
    assert by_name["verdict"]["value"] == "BLOCK"
    assert 0 <= by_name["scoreBps"]["value"] <= 10_000
    assert by_name["inputHash"]["value"].startswith("0x")
    assert len(by_name["inputHash"]["value"]) == 66  # 0x + 32 bytes


def test_score_encoding_is_basis_points(settings: Settings, attack_raw: dict) -> None:
    guard = Guard(settings)
    verdict = guard.inspect(attack_raw)
    record = EvidenceLog(settings).get(verdict.evidence_id or "")
    assert record is not None
    att = evidence_to_attestation(record)
    bps = next(d for d in att["data"] if d["name"] == "scoreBps")["value"]
    assert bps == round(record.score * 10_000)
