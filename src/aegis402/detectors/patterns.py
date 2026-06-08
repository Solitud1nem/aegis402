"""L1 pattern scanner — fast, language-agnostic signatures of prompt injection.

Detects: classic override phrases ("ignore previous instructions"), hidden
zero-width / bidi control characters, HTML comments, and long base64 blobs in
untrusted context. Pure-CPU and sub-millisecond; works with the ML layer off.
"""

from __future__ import annotations

import regex as re

from ..config import Settings, get_settings
from ..schemas import Intent, Signal

# Known injection / jailbreak phrasings. Kept broad but specific enough to avoid
# matching ordinary prose. Case-insensitive, unicode-aware.
_INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", "override: ignore-instructions"),
    (r"disregard\s+(all\s+)?(previous|prior|the\s+above)", "override: disregard"),
    (r"forget\s+(everything|all|previous|prior)", "override: forget-context"),
    (r"you\s+are\s+now\s+(a|an|in)\b", "role-reassignment"),
    (r"new\s+(instructions?|task|system\s+prompt)\s*:", "injected-instructions"),
    (r"system\s+prompt\s*:", "fake-system-prompt"),
    (r"\bact\s+as\b.*\b(admin|root|developer|jailbreak)", "jailbreak: act-as"),
    (r"send\s+(all|everything|the\s+funds)\b", "exfil: send-funds"),
    (r"(transfer|pay|send)\b.{0,40}\b(instead|rather\s+than)\b", "redirect-payment"),
    (r"do\s+not\s+(tell|inform|alert|notify)\b", "stealth: suppress-notice"),
    (r"override\s+(the\s+)?(mandate|policy|limit|allowlist)", "policy-override"),
]

# Zero-width, bidi and other invisible control characters used to obfuscate text.
_HIDDEN_CHARS = re.compile(r"[​-‏‪-‮⁠-⁤﻿­]")
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")
_HEX_DIGITS = set("0123456789abcdefABCDEF")


def _is_hex_like(blob: str) -> bool:
    """True for a pure-hex run (optionally ``0x``-prefixed): an address or tx hash.

    Such runs are not encoded payloads and appear routinely in legitimate untrusted
    content, so the base64 scanner skips them to avoid false positives.
    """
    body = blob[2:] if blob[:2] in ("0x", "0X") else blob
    return bool(body) and all(c in _HEX_DIGITS for c in body)

_COMPILED: list[tuple[re.Pattern[str], str]] = [
    (re.compile(p, re.IGNORECASE), label) for p, label in _INJECTION_PATTERNS
]


class PatternScanner:
    """L1 detector: regex/signature scan over untrusted context."""

    layer = "L1"

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def run(self, intent: Intent) -> Signal:
        """Scan untrusted context for injection signatures and hidden characters."""
        hits: list[dict[str, str]] = []
        joined = "\n".join(intent.untrusted_context)

        for pattern, label in _COMPILED:
            m = pattern.search(joined)
            if m:
                hits.append({"type": label, "match": m.group(0)[:120]})

        if _HIDDEN_CHARS.search(joined):
            hits.append({"type": "hidden-unicode", "match": "zero-width/bidi control chars"})
        if _HTML_COMMENT.search(joined):
            hits.append({"type": "html-comment", "match": "instructions in HTML comment"})
        for m in _BASE64_BLOB.finditer(joined):
            blob = m.group(0)
            if _is_hex_like(blob):
                continue  # address / tx hash, not an encoded payload
            hits.append({"type": "base64-blob", "match": blob[:40] + "…"})
            break

        if not hits:
            return Signal(layer=self.layer, score=0.0, reason="no injection patterns found")

        return Signal(
            layer=self.layer,
            score=self._settings.l1_signal_score,
            reason=f"{len(hits)} injection pattern(s) in untrusted context",
            evidence={"hits": hits},
        )
