"""Intent Interceptor — normalize raw agent input into a canonical :class:`Intent`.

Responsibilities:
* Coerce/validate the raw payload via Pydantic.
* Normalize recipient (and any addresses) to EIP-55 checksum so downstream
  comparisons are unambiguous; comparisons elsewhere are done in lowercase.
* Compute a stable hash of the normalized input for the tamper-evident evidence log.

The interceptor never signs anything and never holds keys.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from eth_utils import is_address, to_checksum_address

from .schemas import Intent


def _normalize_address(value: str) -> str:
    """Return the EIP-55 checksum form of an address, or the input unchanged.

    Non-address strings (e.g. an asset symbol) are returned as-is so the caller
    can still inspect them; validation of address-ness is the detectors' job.
    """
    candidate = value.strip()
    if is_address(candidate):
        return to_checksum_address(candidate)
    return candidate


def build_intent(raw: dict[str, Any]) -> Intent:
    """Validate and normalize a raw input dict into an :class:`Intent`.

    Args:
        raw: Untrusted JSON-shaped mapping with ``user_request``,
            ``untrusted_context``, ``payment_intent`` and optional ``mandate``.

    Returns:
        A normalized :class:`Intent` with checksum addresses.

    Raises:
        pydantic.ValidationError: If the payload does not match the schema.
    """
    intent = Intent.model_validate(raw)
    intent.payment_intent.recipient = _normalize_address(intent.payment_intent.recipient)
    if intent.mandate is not None:
        intent.mandate.allowlist = [_normalize_address(a) for a in intent.mandate.allowlist]
    return intent


def input_hash(intent: Intent) -> str:
    """Return a sha256 hex digest of the normalized intent for the evidence log."""
    canonical = json.dumps(
        intent.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
