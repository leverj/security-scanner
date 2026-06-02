"""Deterministic, line-number-free fingerprint + marker (de)serialize.

The fingerprint is the source of truth for dedup. Line numbers are excluded so
reformatting/refactoring doesn't spawn duplicates. The marker is injected as an
HTML comment into every filed issue body so future runs can read it back.
"""

from __future__ import annotations

import hashlib
import re

from security_scan.models import Finding

MARKER_RE = re.compile(
    # Accept legacy `secscan:` marker too so issues filed by the pre-rename code
    # still match for dedup. New markers are written as `security-scan:` (see
    # inject_marker below).
    r"<!--\s*(?:security-scan|secscan):\s*fp=(?P<fp>fp_[a-f0-9]{16})\s+rule=(?P<rule>[^\s]+)\s+cat=(?P<cat>[a-z]+)\s*-->"
)


def _normalize_snippet(snippet: str) -> str:
    """Strip all whitespace so reformatting (indent, line breaks, spacing) doesn't change identity."""
    return re.sub(r"\s+", "", snippet)


def _snippet_or_secretfp(f: Finding) -> str:
    """Per-category stable basis for the fingerprint.

    - dependency: empty (rule_id = GHSA/CVE is already unique per package-advisory)
    - secret: scanner's own secret fingerprint (NEVER the raw secret)
    - sast: whitespace-normalized snippet or enclosing symbol name
    """
    if f.category == "dependency":
        return ""
    if f.category == "secret":
        secret_fp = f.extra.get("secret_fingerprint")
        if secret_fp:
            return f"secret:{secret_fp}"
        # Fall back to masked preview; raw secret must never reach here.
        return f"secret:{_normalize_snippet(f.masked_preview)}"
    # sast
    snippet = f.extra.get("snippet") or f.extra.get("symbol") or f.message
    return f"snip:{_normalize_snippet(snippet)}"


def compute_fingerprint(f: Finding) -> str:
    """Return `fp_<16 hex>` — deterministic, line-number-free.

    If the scanner emitted its own SARIF fingerprint (`f.sarif_fingerprint`), the
    caller should prefer that; this is the fallback identity.
    """
    basis = f"{f.rule_id}\0{f.file_path}\0{_snippet_or_secretfp(f)}"
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    return f"fp_{digest}"


def resolve_fingerprint(f: Finding) -> str:
    """Prefer the scanner's SARIF fingerprint when present (survives line drift);
    otherwise compute our deterministic one."""
    if f.sarif_fingerprint:
        # Namespaced so a SARIF-provided fp can never collide with a computed one
        # of the same hex shape.
        if f.sarif_fingerprint.startswith("fp_"):
            return f.sarif_fingerprint
        digest = hashlib.sha256(f.sarif_fingerprint.encode("utf-8")).hexdigest()[:16]
        return f"fp_{digest}"
    return compute_fingerprint(f)


def inject_marker(body: str, fp: str, f: Finding) -> str:
    """Append the hidden marker to an issue body. Code-owned, regardless of LLM prose."""
    marker = f"<!-- security-scan: fp={fp} rule={f.rule_id} cat={f.category} -->"
    if MARKER_RE.search(body):
        return MARKER_RE.sub(marker, body)
    sep = "\n\n" if body and not body.endswith("\n") else ""
    return f"{body}{sep}{marker}\n"


def parse_marker(body: str | None) -> dict | None:
    """Extract {fp, rule, cat} from an issue body, or None if absent/malformed."""
    if not body:
        return None
    m = MARKER_RE.search(body)
    if not m:
        return None
    return {"fp": m.group("fp"), "rule": m.group("rule"), "cat": m.group("cat")}
