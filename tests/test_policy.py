"""L3 payment-policy gate tests."""

from __future__ import annotations

from aegis402.detectors.policy import PaymentPolicyGate
from aegis402.interceptor import build_intent

from .conftest import ATTACKER, USDC, VENDOR

ALLOWLISTED = "0x3333333333333333333333333333333333333333"


def _intent(raw_overrides: dict):
    base = {
        "user_request": f"Pay 5 USDC to {VENDOR}.",
        "untrusted_context": [],
        "payment_intent": {
            "recipient": VENDOR,
            "amount": 5 * USDC,
            "asset": "USDC",
            "network": "base-sepolia",
        },
    }
    base.update(raw_overrides)
    return build_intent(base)


def test_recipient_substitution_flagged() -> None:
    sig = PaymentPolicyGate().run(_intent({"payment_intent": {
        "recipient": ATTACKER, "amount": 5 * USDC, "asset": "USDC", "network": "base-sepolia"}}))
    assert sig.score >= 0.9
    assert any(v["check"] == "recipient_substituted" for v in sig.evidence["violations"])


def test_amount_overshoot_flagged() -> None:
    sig = PaymentPolicyGate().run(_intent({"payment_intent": {
        "recipient": VENDOR, "amount": 500 * USDC, "asset": "USDC", "network": "base-sepolia"}}))
    assert any(v["check"] == "amount_overshoot" for v in sig.evidence["violations"])


def test_mandate_limit_flagged() -> None:
    sig = PaymentPolicyGate().run(_intent({
        "payment_intent": {"recipient": VENDOR, "amount": 90 * USDC, "asset": "USDC",
                           "network": "base-sepolia"},
        "mandate": {"limit": 20 * USDC, "allowlist": [VENDOR]},
    }))
    assert any(v["check"] == "mandate_limit" for v in sig.evidence["violations"])


def test_allowlist_violation_flagged() -> None:
    sig = PaymentPolicyGate().run(_intent({
        "user_request": "Pay the vendor.",
        "payment_intent": {"recipient": ATTACKER, "amount": 5 * USDC, "asset": "USDC",
                           "network": "base-sepolia"},
        "mandate": {"limit": 50 * USDC, "allowlist": [ALLOWLISTED]},
    }))
    assert any(v["check"] == "allowlist" for v in sig.evidence["violations"])


def test_benign_payment_passes() -> None:
    sig = PaymentPolicyGate().run(_intent({}))
    assert sig.score == 0.0


def test_network_not_permitted_flagged() -> None:
    """A mandate with a `networks` list blocks the allowlisted recipient on other chains."""
    sig = PaymentPolicyGate().run(_intent({
        "payment_intent": {"recipient": VENDOR, "amount": 5 * USDC, "asset": "USDC",
                           "network": "ethereum-mainnet"},
        "mandate": {"limit": 50 * USDC, "allowlist": [VENDOR], "networks": ["base-sepolia"]},
    }))
    assert sig.score >= 0.9
    assert any(v["check"] == "network_not_permitted" for v in sig.evidence["violations"])


def test_network_permitted_passes() -> None:
    """On-network payment to an allowlisted recipient raises no L3 signal."""
    sig = PaymentPolicyGate().run(_intent({
        "payment_intent": {"recipient": VENDOR, "amount": 5 * USDC, "asset": "USDC",
                           "network": "base-sepolia"},
        "mandate": {"limit": 50 * USDC, "allowlist": [VENDOR], "networks": ["base-sepolia"]},
    }))
    assert sig.score == 0.0


def test_asset_not_permitted_flagged() -> None:
    """A mandate with an `assets` list blocks payment in an unlisted asset."""
    sig = PaymentPolicyGate().run(_intent({
        "payment_intent": {"recipient": VENDOR, "amount": 5 * USDC, "asset": "DAI",
                           "network": "base-sepolia"},
        "mandate": {"limit": 50 * USDC, "allowlist": [VENDOR], "assets": ["USDC"]},
    }))
    assert any(v["check"] == "asset_not_permitted" for v in sig.evidence["violations"])


def test_network_whitespace_does_not_falsely_violate() -> None:
    """A network id with surrounding whitespace is stripped at the boundary, so it still
    matches a mandate's `networks` confinement instead of false-positiving."""
    sig = PaymentPolicyGate().run(_intent({
        "payment_intent": {"recipient": VENDOR, "amount": 5 * USDC, "asset": "USDC",
                           "network": " base-sepolia "},
        "mandate": {"limit": 50 * USDC, "allowlist": [VENDOR], "networks": ["base-sepolia"]},
    }))
    assert sig.score == 0.0


def test_empty_network_asset_lists_unrestricted() -> None:
    """Back-compat: empty networks/assets lists impose no restriction."""
    sig = PaymentPolicyGate().run(_intent({
        "payment_intent": {"recipient": VENDOR, "amount": 5 * USDC, "asset": "DAI",
                           "network": "any-l2"},
        "mandate": {"limit": 50 * USDC, "allowlist": [VENDOR]},
    }))
    assert sig.score == 0.0


def test_strict_mandate_off_allows_unbounded() -> None:
    """Default posture: a payment with no per-payment limit raises no L3 signal."""
    from aegis402.config import Settings

    sig = PaymentPolicyGate(Settings(strict_mandate=False)).run(
        _intent({"mandate": {"allowlist": [VENDOR]}})
    )
    assert sig.score == 0.0


def test_strict_mandate_flags_missing_limit_in_review_band() -> None:
    """Strict posture: no per-payment limit -> a REVIEW-band (not BLOCK) L3 signal."""
    from aegis402.config import Settings

    s = Settings(strict_mandate=True)
    sig = PaymentPolicyGate(s).run(_intent({"mandate": {"allowlist": [VENDOR]}}))
    assert s.review_threshold <= sig.score < s.block_threshold
    assert any(v["check"] == "missing_payment_limit" for v in sig.evidence["violations"])


def test_strict_mandate_satisfied_by_limit() -> None:
    """Strict posture: a per-payment limit clears the requirement."""
    from aegis402.config import Settings

    sig = PaymentPolicyGate(Settings(strict_mandate=True)).run(
        _intent({"mandate": {"allowlist": [VENDOR], "limit": 10 * USDC}})
    )
    assert sig.score == 0.0


def test_strict_mandate_end_to_end_reviews_unbounded_payment() -> None:
    """Guard-level: strict mode routes an unbounded payment to REVIEW, not ALLOW."""
    import tempfile
    from pathlib import Path

    from aegis402.config import Settings
    from aegis402.guard import Guard
    from aegis402.schemas import VerdictType

    guard = Guard(Settings(db_path=Path(tempfile.mkdtemp()) / "s.db", strict_mandate=True))
    verdict = guard.inspect({
        "user_request": f"Pay 5 USDC to {VENDOR}.",
        "untrusted_context": ["Invoice: 5 USDC due."],
        "payment_intent": {"recipient": VENDOR, "amount": 5 * USDC, "asset": "USDC",
                           "network": "base-sepolia"},
        "mandate": {"allowlist": [VENDOR]},
    })
    assert verdict.verdict == VerdictType.REVIEW
