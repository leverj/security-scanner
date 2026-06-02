"""Semgrep runner. Static analysis only; bundled rules; no metrics."""

from __future__ import annotations

import json
from pathlib import Path

from . import RunnerResult, _run


def run(
    root: Path,
    rules_dir: Path | str,
    exclude: list[str] | None = None,
    binary: str = "semgrep",
) -> RunnerResult:
    cmd = [
        binary,
        "scan",
        "--config", str(rules_dir),
        "--sarif",
        "--metrics=off",
        "--quiet",
    ]
    for pat in exclude or []:
        cmd += ["--exclude", pat]
    cmd.append(str(root))

    try:
        rc, stdout, stderr = _run(cmd, cwd=root)
    except FileNotFoundError:
        return RunnerResult("semgrep", None, False, f"binary not found: {binary}")
    except Exception as e:
        return RunnerResult("semgrep", None, False, f"{type(e).__name__}: {e}")

    # rc 0 = no findings, rc 1 = findings (both success); >=2 = failure.
    if rc >= 2:
        return RunnerResult("semgrep", None, False, f"exit {rc}: {stderr.strip()[:200]}")

    try:
        sarif = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as e:
        return RunnerResult("semgrep", None, False, f"parse error: {e}")

    return RunnerResult("semgrep", sarif, True, None)
