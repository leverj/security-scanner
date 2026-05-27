"""Trufflehog runner — verified secret scanning.

Trufflehog actually CALLS the upstream API (GitHub, AWS, etc.) to validate that
a discovered token is live. The "Verified: true" findings are signal-rich and
warrant the highest severity treatment.

Trufflehog v3 emits JSONL (not SARIF). We carry the raw output through
RunnerResult.sarif as a wrapper dict so the existing pipeline can flow; the
normalize.py module recognizes the wrapper and parses it differently.
"""

from __future__ import annotations

from pathlib import Path

from . import RunnerResult, _run

_JSONL_WRAPPER_KEY = "_trufflehog_jsonl"


def run(root: Path, exclude: list[str] | None = None, binary: str = "trufflehog") -> RunnerResult:
    # NOTE: Trufflehog v3 has no flag for inline glob excludes (only
    # `--exclude-paths <file>` taking a path to a patterns file). Rather than
    # write a tempfile, we let trufflehog scan the whole tree and let
    # normalize._normalize_trufflehog filter excluded paths post-hoc.
    _ = exclude
    cmd = [
        binary,
        "filesystem",
        "--json",
        "--no-update",            # don't phone home to check for updates
        "--no-verification-cache",  # always verify fresh (no false-negatives from cache)
        str(root),
    ]

    try:
        rc, stdout, stderr = _run(cmd, cwd=root)
    except FileNotFoundError:
        return RunnerResult("trufflehog", None, False, f"binary not found: {binary}")
    except Exception as e:
        return RunnerResult("trufflehog", None, False, f"{type(e).__name__}: {e}")

    # Trufflehog returns 0 on success (with or without findings). Non-zero == failure.
    if rc != 0:
        return RunnerResult("trufflehog", None, False, f"exit {rc}: {stderr.strip()[:300]}")

    # Wrap the raw JSONL so the existing sarif-typed contract still flows;
    # normalize.py unwraps via the sentinel key.
    return RunnerResult("trufflehog", {_JSONL_WRAPPER_KEY: stdout}, True, None)
