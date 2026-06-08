"""End-to-end guard + evidence-log tests."""

from __future__ import annotations

import json

from aegis402.config import Settings
from aegis402.evidence import EvidenceLog
from aegis402.guard import Guard
from aegis402.schemas import VerdictType


def test_attack_blocks_and_records(settings: Settings, attack_raw: dict) -> None:
    guard = Guard(settings)
    verdict = guard.inspect(attack_raw)
    assert verdict.verdict == VerdictType.BLOCK
    assert verdict.evidence_id is not None
    record = EvidenceLog(settings).get(verdict.evidence_id)
    assert record is not None
    assert record.attempted["recipient"] == attack_raw["payment_intent"]["recipient"]
    assert record.input_hash  # tamper-evident hash present


def test_benign_allows_and_is_not_recorded(settings: Settings, benign_raw: dict) -> None:
    guard = Guard(settings)
    verdict = guard.inspect(benign_raw)
    assert verdict.verdict == VerdictType.ALLOW
    assert verdict.evidence_id is None


def test_invalid_input_is_fail_closed_block(settings: Settings) -> None:
    verdict = Guard(settings).inspect({"user_request": "hi"})  # missing payment_intent
    assert verdict.verdict == VerdictType.BLOCK


def test_evidence_export_is_valid_json(settings: Settings, attack_raw: dict) -> None:
    guard = Guard(settings)
    guard.inspect(attack_raw)
    exported = json.loads(EvidenceLog(settings).export_json())
    assert isinstance(exported, list)
    assert exported and exported[0]["verdict"] == "BLOCK"
