"""Pre-flight redaction for any payload heading to a remote LLM.

Two complementary defences:

  1. `redact_text` rewrites known-token shapes (AWS/GitHub/Stripe/Slack/Google/
     JWT/PEM/OpenAI/etc.) and any high-entropy substring (Shannon entropy
     >= 4.0 over >= 20 chars) to `<REDACTED:kind>`.
  2. `is_local_url` lets callers refuse to send to a non-loopback/non-private
     Ollama host. The remote-LLM-as-triage path was never meant to leave the
     box; this guards the edge configuration where someone points base_url
     at an internet host.

Both are intentionally over-eager — false positives produce `<REDACTED:...>`
in the model's view of a snippet, which is harmless (the model just gets less
context). False negatives are the bad outcome.
"""

from __future__ import annotations

import math
import re
from ipaddress import ip_address
from urllib.parse import urlparse

# -- known token shapes --------------------------------------------------------
# Each pattern is paired with the label that replaces it. Order matters only
# for cosmetic precedence — every pattern is applied independently.

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # AWS access keys
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<REDACTED:aws-key>"),
    # GitHub tokens (classic, fine-grained, OAuth, refresh)
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b"), "<REDACTED:github-token>"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "<REDACTED:github-pat>"),
    # Stripe
    (re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b"), "<REDACTED:stripe-key>"),
    # OpenAI / Anthropic-like
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "<REDACTED:llm-api-key>"),
    # Slack
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "<REDACTED:slack-token>"),
    # Google API
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "<REDACTED:google-api-key>"),
    # JWTs (three base64url segments)
    (re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b"),
     "<REDACTED:jwt>"),
    # PEM blocks (multi-line) — DOTALL so `.` crosses newlines
    (re.compile(r"-----BEGIN [A-Z0-9 ]+?-----.*?-----END [A-Z0-9 ]+?-----", re.DOTALL),
     "<REDACTED:pem-key>"),
    # Common assignment shapes: NAME=value where NAME hints at a secret.
    # We replace ONLY the value portion so the label stays readable.
    (re.compile(
        r"(?i)\b(?P<k>(?:api[_-]?key|secret|token|password|passwd|auth|bearer|"
        r"client[_-]?secret|access[_-]?token|refresh[_-]?token|private[_-]?key))"
        r"\s*[:=]\s*['\"]?(?P<v>[A-Za-z0-9+/=_\-\.]{16,})['\"]?"
    ), lambda m: f"{m.group('k')}=<REDACTED:secret-like>"),
)

# -- entropy heuristic ---------------------------------------------------------

_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_ENTROPY_THRESHOLD = 4.0
_ENTROPY_MIN_LEN = 20


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact_entropy(text: str) -> str:
    """Replace any contiguous [A-Za-z0-9+/=_-]{20+} substring whose Shannon
    entropy >= 4.0 with `<REDACTED:high-entropy>`. Heuristic — long
    not-secret identifiers like `internationalization_module_v2` are nowhere
    near 4.0 bits/char, so they survive. Hex digests, base64 secrets, and
    random API keys do not."""
    def _maybe_replace(m: re.Match[str]) -> str:
        tok = m.group(0)
        if len(tok) < _ENTROPY_MIN_LEN:
            return tok
        if _shannon_entropy(tok) >= _ENTROPY_THRESHOLD:
            return "<REDACTED:high-entropy>"
        return tok
    return _ENTROPY_TOKEN_RE.sub(_maybe_replace, text)


# -- public API ----------------------------------------------------------------


def redact_text(text: str | None) -> str:
    """Apply all known-token patterns + entropy heuristic. Idempotent; safe to
    call on already-redacted text (the `<REDACTED:...>` markers don't match)."""
    if not text:
        return text or ""
    out = text
    for pat, replacement in _PATTERNS:
        out = pat.sub(replacement, out)
    out = _redact_entropy(out)
    return out


def redact_obj(obj):
    """Recursively redact strings inside dicts/lists/tuples. Non-string scalars
    are returned unchanged. Used to scrub finding `extra` dicts before they go
    out over the wire."""
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_obj(v) for v in obj)
    return obj


# -- network policy ------------------------------------------------------------


def is_local_url(url: str | None) -> bool:
    """True iff the host portion of `url` is a loopback address, a docker
    internal host (`host.docker.internal`, `*.local`), or an RFC1918 / unique
    local address. Used to decide whether sending unredacted-ish content is
    permissible.

    Conservative: when in doubt (unparseable, no host), returns False so the
    caller treats it as remote."""
    if not url:
        return False
    try:
        parts = urlparse(url if "://" in url else f"http://{url}")
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if not host:
        return False
    if host in {"localhost", "host.docker.internal"}:
        return True
    if host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        ip = ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private or ip.is_link_local
