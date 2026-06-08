"""Shared best-effort extraction of payment facts from free text.

Used by L3 (policy) and L4 (provenance) to recover what the *owner* actually
asked for — the recipient address and amount mentioned in ``user_request`` — and
to locate addresses appearing in untrusted context.

These are heuristics, not a parser: a miss means a check is skipped, never that an
attack is silently allowed (other layers still fire).
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

import regex as re

_HEX = r"[0-9a-fA-F]"
_ADDRESS = re.compile(rf"0x{_HEX}{{40}}")
# Separators an attacker can splice between hex digits to hide an address from a naive
# scan: ASCII whitespace (including the "\n" that joins context entries), zero-width /
# bidi controls, soft hyphen and hyphen. Recovering an address *through* these is what
# lets L4 provenance see a deliberately broken or split attacker address.
_SEP = r"[\s​-‏‪-‮⁠-⁤﻿­\-]"
# 0x followed by exactly 40 hex digits, each optionally wrapped in separators, not
# immediately continued by more hex (so a long hash isn't read as a 40-char prefix).
_ADDRESS_OBFUSCATED = re.compile(rf"0x{_SEP}*(?:{_HEX}{_SEP}*){{40}}(?!{_HEX})")
_STRIP_SEP = re.compile(_SEP)
# A number (with optional thousands separators / decimals) followed by an asset symbol,
# e.g. "5 USDC", "1,000.50 usdc", "2.5 ETH".
_AMOUNT_WITH_ASSET = re.compile(
    r"(?P<num>\d[\d,]*(?:\.\d+)?)\s*(?P<asset>[A-Za-z]{2,6})",
)


def find_addresses(text: str) -> list[str]:
    """Return all 0x-style addresses in ``text``, lowercased, order-preserving-unique.

    Two passes: clean addresses, then addresses obfuscated with interspersed separators
    (spaces, zero-width chars, hyphens) or split across joined context entries. The
    second pass strips separators and re-validates, so ``"0x A77a c1d0 …"`` and an
    address broken across a ``"\\n"`` boundary still resolve — closing the L4 provenance
    evasion where the attacker address is present in untrusted text but unparseable.
    Conservative by construction: a match needs ``0x`` plus exactly 40 hex digits with
    only separators between them, which ordinary prose does not produce.
    """
    seen: dict[str, None] = {}
    for m in _ADDRESS.finditer(text):
        seen.setdefault(m.group(0).lower(), None)
    for m in _ADDRESS_OBFUSCATED.finditer(text):
        candidate = _STRIP_SEP.sub("", m.group(0)).lower()
        if len(candidate) == 42:  # "0x" + 40 hex
            seen.setdefault(candidate, None)
    return list(seen)


def to_minimal_units(amount: Decimal, decimals: int) -> int:
    """Convert a human amount to integer minimal units (truncating fractional dust)."""
    return int(amount * (Decimal(10) ** decimals))


def find_requested_amount(
    text: str, asset: str, decimals_for: dict[str, int], default_decimals: int
) -> int | None:
    """Extract the amount the owner asked for, in minimal units, if discernible.

    Prefers a number explicitly attached to ``asset``; otherwise falls back to the
    first amount-with-asset match. Returns None when no amount is found.
    """
    asset_u = asset.upper()
    candidates: list[tuple[str, str]] = [
        (m.group("num"), m.group("asset").upper()) for m in _AMOUNT_WITH_ASSET.finditer(text)
    ]
    if not candidates:
        return None

    chosen: tuple[str, str] = next(
        (c for c in candidates if c[1] == asset_u), candidates[0]
    )
    num_str, matched_asset = chosen
    try:
        value = Decimal(num_str.replace(",", ""))
    except InvalidOperation:
        return None
    decimals = decimals_for.get(matched_asset, decimals_for.get(asset_u, default_decimals))
    return to_minimal_units(value, decimals)
