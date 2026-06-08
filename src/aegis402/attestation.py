"""EAS attestation export (stub) — shape evidence for on-chain attestation later.

This is the interface seam called out in the roadmap: it turns an
:class:`~aegis402.evidence.EvidenceRecord` into the structure an
[EAS](https://attest.org) off-chain attestation expects (schema + typed fields),
*without* touching a chain or signing anything. A post-hackathon on-chain layer can
consume these payloads as-is and submit them via the EAS SDK.

Nothing here is consensus-critical; it is a pure, deterministic transform.
"""

from __future__ import annotations

from typing import Any

from .evidence import EvidenceLog, EvidenceRecord

# Human-readable EAS schema the evidence maps onto. Register this on-chain to obtain a
# schema UID; that UID then goes in ``ATTESTATION_SCHEMA_UID`` (config/env) post-hackathon.
EAS_SCHEMA = (
    "string evidenceId,uint64 timestamp,string verdict,"
    "uint16 scoreBps,bytes32 inputHash,string reason"
)


def _score_to_bps(score: float) -> int:
    """Encode a [0, 1] risk score as integer basis points (EAS has no floats)."""
    return max(0, min(10_000, round(score * 10_000)))


def _to_bytes32(hex_digest: str) -> str:
    """Return a 0x-prefixed 32-byte hex string for a sha256 digest."""
    h = hex_digest[2:] if hex_digest.startswith("0x") else hex_digest
    return "0x" + h[:64].rjust(64, "0")


def evidence_to_attestation(record: EvidenceRecord) -> dict[str, Any]:
    """Map one evidence record to an (unsigned) EAS off-chain attestation request.

    The ``data`` array mirrors :data:`EAS_SCHEMA` field-for-field so an on-chain
    submitter can ABI-encode it directly.
    """
    return {
        "schema": EAS_SCHEMA,
        "schemaUid": None,  # filled once the schema is registered on-chain
        "recipient": "0x0000000000000000000000000000000000000000",
        "revocable": True,
        "refUid": "0x" + "0" * 64,
        "data": [
            {"name": "evidenceId", "type": "string", "value": record.id},
            {"name": "timestamp", "type": "uint64", "value": record.ts},
            {"name": "verdict", "type": "string", "value": record.verdict},
            {"name": "scoreBps", "type": "uint16", "value": _score_to_bps(record.score)},
            {"name": "inputHash", "type": "bytes32", "value": _to_bytes32(record.input_hash)},
            {"name": "reason", "type": "string", "value": record.reason},
        ],
        "onchain": False,  # stub: not submitted, not signed
    }


def export_attestations(log: EvidenceLog) -> list[dict[str, Any]]:
    """Return EAS attestation payloads for every evidence record in ``log``."""
    return [evidence_to_attestation(r) for r in log.all_records()]
