"""Gitleaks runner. Reads SARIF from stdout via --report-path -."""

from __future__ import annotations

import json
from pathlib import Path

from . import RunnerResult, _run


def run(root: Path, binary: str = "gitleaks") -> RunnerResult:
    cmd = [
        binary,
        "detect",
        "--source", str(root),
        "--report-format", "sarif",
        "--report-path", "-",
    ]

    try:
        rc, stdout, stderr = _run(cmd, cwd=root)
    except FileNotFoundError:
        return RunnerResult("gitleaks", None, False, f"binary not found: {binary}")
    except Exception as e:
        return RunnerResult("gitleaks", None, False, f"{type(e).__name__}: {e}")

    # Gitleaks exit codes are version-dependent:
    #   v7 and earlier: 0 = no leaks, 77 = leaks found
    #   v8+:            0 = no leaks, 1 = leaks found  (configurable via --exit-code)
    # The deciding question is "did the scanner produce parseable SARIF?", not the
    # exit code. Try to parse stdout first; if it parses, treat as success regardless
    # of rc. Only fall back to "failed" when both stdout is unparseable AND rc != 0.
    try:
        sarif = json.loads(stdout)
        return RunnerResult("gitleaks", sarif, True, None)
    except (json.JSONDecodeError, ValueError) as parse_err:
        if rc == 0:
            # Empty/no-output success is still a failure to produce SARIF.
            return RunnerResult("gitleaks", None, False, f"parse error: {parse_err}")
        return RunnerResult("gitleaks", None, False, f"exit {rc}: {stderr.strip()[:200]}")
