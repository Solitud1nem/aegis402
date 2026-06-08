"""Address extraction — including recovery of obfuscated / split attacker addresses.

Regression for the Path-B provenance evasion: an attacker address that is present in
untrusted text but spliced with separators (spaces, zero-width, hyphens) or split across
joined context entries must still be recovered, or L4 provenance goes blind in the
no-allowlist regime.
"""

from __future__ import annotations

from aegis402.text_extract import find_addresses

ADDR = "0xA77ac1d00000000000000000000000000000bad1"
ADDR_LC = ADDR.lower()


def test_clean_address_recovered() -> None:
    assert find_addresses(f"pay to {ADDR} now") == [ADDR_LC]


def test_spaced_address_recovered() -> None:
    spaced = "0x A77ac1d0 00000000 00000000 00000000 0000bad1"
    assert ADDR_LC in find_addresses(f"remit to {spaced} please")


def test_hyphenated_address_recovered() -> None:
    hyph = "0xA77ac1d0-00000000-00000000-00000000-0000bad1"
    assert ADDR_LC in find_addresses(f"send to {hyph}")


def test_zero_width_split_address_recovered() -> None:
    zw = ADDR[:10] + "​" + ADDR[10:20] + "​" + ADDR[20:]
    assert ADDR_LC in find_addresses(f"account {zw}")


def test_address_split_across_joined_context_recovered() -> None:
    """The '\\n' that joins untrusted_context entries must not hide a split address."""
    half = len(ADDR) // 2
    joined = f"pay to {ADDR[:half]}\n{ADDR[half:]} thanks"
    assert ADDR_LC in find_addresses(joined)


def test_no_false_address_from_prose() -> None:
    """Ordinary prose with stray hex / dates must not synthesize an address."""
    assert find_addresses("invoice 2023-01-01, ref 0x12, pay 5 USDC to the team") == []


def test_no_false_address_from_short_hex() -> None:
    assert find_addresses("color #0xABCDEF and code 0xdeadbeef") == []
