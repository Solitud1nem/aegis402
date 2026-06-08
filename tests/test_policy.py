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
