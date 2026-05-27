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

    # rc 0 = no secrets, rc 77 = secrets found (both success); anything else = failure.
    if rc not in (0, 77):
        return RunnerResult("gitleaks", None, False, f"exit {rc}: {stderr.strip()[:200]}")

    try:
        sarif = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as e:
        return RunnerResult("gitleaks", None, False, f"parse error: {e}")

    return RunnerResult("gitleaks", sarif, True, None)
