#!/usr/bin/env python3
"""Path B round 2 — boundary / state seams (not single-intent logic).

Probes things a single inspect() can't model: state races in L5, fields the guard
never constrains (network), and the L3/L4 empty-allowlist split.
"""
from __future__ import annotations

import tempfile
import threading
from pathlib import Path

from aegis402.config import Settings
from aegis402.guard import Guard

ATTACKER = "0xA77ac1d00000000000000000000000000000bad1"
LEGIT = "0x1111111111111111111111111111111111111111"
USDC = 1_000_000


def fresh_guard(**kw):
    tmp = Path(tempfile.mkdtemp(prefix="aegis_b_")) / "b.db"
    return Guard(Settings(db_path=tmp, **kw))


def v(o):
    return str(getattr(o.verdict, "value", o.verdict))


# ---- 1. L5 velocity TOCTOU: concurrent inspects read the window before any writes ----
def test_velocity_race():
    cap = 100 * USDC
    g = fresh_guard(velocity_cap=cap)
    mandate = {"limit": 200 * USDC, "allowlist": [LEGIT]}
    # Each payment is 60 USDC to an ALLOWLISTED recipient (so L3/L4 clear) -> only L5
    # should gate. With cap=100, at most ONE 60-USDC payment fits; a second must be caught.
    def one(results, i):
        # Self-consistent "60 USDC" request (no amount-overshoot vs intent); only L5 gates.
        intent = {
            "user_request": f"Pay 60 USDC to our vendor (invoice {i}).",
            "untrusted_context": [],
            "payment_intent": {"recipient": LEGIT, "amount": 60 * USDC,
                               "asset": "USDC", "network": "base-sepolia"},
            "mandate": mandate,
        }
        results[i] = v(g.inspect(intent))

    N = 8
    results = [None] * N
    threads = [threading.Thread(target=one, args=(results, i)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    allows = results.count("ALLOW")
    total_allowed = allows * 60 * USDC
    over = total_allowed > cap
    print(f"[velocity race] {N} concurrent 60-USDC payments, cap=100 USDC")
    print(f"   ALLOW={allows}  total allowed={total_allowed/USDC:.0f} USDC  "
          f"-> {'OVER CAP (race escape)' if over else 'within cap'}")
    # sequential control on a fresh ledger
    g2 = fresh_guard(velocity_cap=cap)
    seq = []
    for i in range(N):
        intent = {"user_request": f"Pay 60 USDC to our vendor (invoice {i}).",
                  "untrusted_context": [],
                  "payment_intent": {"recipient": LEGIT, "amount": 60 * USDC,
                                     "asset": "USDC", "network": "base-sepolia"},
                  "mandate": mandate}
        seq.append(v(g2.inspect(intent)))
    print(f"   sequential control: ALLOW={seq.count('ALLOW')} (expected 1)")
    return over


# ---- 2. network/asset confinement (fix #2): unrestricted by default, BLOCK when set ----
def test_network_binding():
    g = fresh_guard()
    def probe(mandate, net):
        return v(g.inspect({
            "user_request": "Pay our allowlisted vendor 50 USDC.",
            "untrusted_context": [],
            "payment_intent": {"recipient": LEGIT, "amount": 50 * USDC,
                               "asset": "USDC", "network": net},
            "mandate": mandate}))
    open_m = {"limit": 1000 * USDC, "allowlist": [LEGIT]}                       # no networks
    bound_m = {"limit": 1000 * USDC, "allowlist": [LEGIT], "networks": ["base-sepolia"]}
    print("[network binding] same allowlisted recipient, different networks:")
    print("   no networks set (back-compat = unrestricted):")
    for net in ("base-sepolia", "ethereum-mainnet", "attacker-l2"):
        print(f"      network={net:18} -> {probe(open_m, net)}")
    print("   networks=['base-sepolia'] (fix #2):")
    for net in ("base-sepolia", "ethereum-mainnet", "attacker-l2"):
        print(f"      network={net:18} -> {probe(bound_m, net)}")


# ---- 3. empty allowlist: L3 treats as 'allowlisted=True', L4 as 'not allowlisted' ----
def test_empty_allowlist():
    g = fresh_guard()
    mandate = {"limit": 1000 * USDC, "allowlist": []}
    # redirect to attacker, NOT in text, high-stakes amount
    intent = {"user_request": "Pay the invoice for hosting.",
              "untrusted_context": ["Invoice overdue."],
              "payment_intent": {"recipient": ATTACKER, "amount": 500 * USDC,
                                 "asset": "USDC", "network": "base-sepolia"},
              "mandate": mandate}
    print(f"[empty allowlist] limit set, allowlist=[], attacker recipient $500 -> {v(g.inspect(intent))}")


if __name__ == "__main__":
    race = test_velocity_race()
    print()
    test_network_binding()
    print()
    test_empty_allowlist()
