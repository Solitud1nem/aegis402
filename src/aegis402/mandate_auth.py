"""Mandate authentication — prove a mandate was issued by the owner, not forged by a
(possibly compromised) agent.

The mandate is Aegis's trust anchor (threat-model §1): the guard derives the allowlist,
per-payment limit, budget and network/asset confinement straight from it. If the agent
that hands the guard a mandate is taken over by prompt injection, nothing here stops it
from *fabricating* a permissive mandate — attacker in the allowlist, a huge limit — that
the guard would then dutifully honor. That is the single biggest assumption in the
threat model.

This module closes it (opt-in): the owner signs the mandate's canonical content with a
secret that lives only in server config (``Settings.mandate_hmac_secret``), never in the
untrusted payload. The guard verifies that signature before trusting the mandate. A
compromised agent can still *replay* the owner's genuine mandate (that is just the
owner's real policy, bounded by its own limit/expiry) but cannot mint a new one or
escalate an existing one — it does not hold the secret.

HMAC-SHA256 is symmetric and dependency-free. The natural upgrade is an asymmetric
scheme (owner keypair / signed AP2 mandate, recover the signer) so the guard needs only
a public key; the verification seam here is identical.
"""

from __future__ import annotations

import hashlib
import hmac

from .schemas import Mandate


def mandate_signature(mandate: Mandate, secret: str) -> str:
    """Return the hex HMAC-SHA256 the owner attaches as ``mandate.signature``.

    Helper for owners/tests to produce a signature; the guard only ever *verifies*.
    """
    return hmac.new(
        secret.encode("utf-8"), mandate.canonical_content().encode("utf-8"), hashlib.sha256
    ).hexdigest()


def verify_mandate(mandate: Mandate, secret: str) -> bool:
    """True iff ``mandate.signature`` is a valid HMAC over its canonical content.

    Constant-time comparison; a missing signature is invalid. Because the signature
    covers the full canonical content, any tampering (e.g. adding an address to the
    allowlist or raising the limit) invalidates it.
    """
    if not mandate.signature:
        return False
    expected = mandate_signature(mandate, secret)
    return hmac.compare_digest(expected, mandate.signature)
