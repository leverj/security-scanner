"""OSV-Scanner runner. Lockfile-only; never invokes installers."""

from __future__ import annotations

import json
from pathlib import Path

from . import RunnerResult, _run


def run(root: Path, exclude: list[str] | None = None, binary: str = "osv-scanner") -> RunnerResult:
    cmd = [binary, "--format", "sarif", "--skip-git", "--recursive"]
    for pat in exclude or []:
        cmd += ["--paths-to-ignore", pat]
    cmd.append(str(root))

    try:
        rc, stdout, stderr = _run(cmd, cwd=root)
    except FileNotFoundError:
        return RunnerResult("osv", None, False, f"binary not found: {binary}")
    except Exception as e:
        return RunnerResult("osv", None, False, f"{type(e).__name__}: {e}")

    # rc 0 = no vulns, rc 1 = vulns found (both success); >=2 = failure.
    if rc >= 2:
        return RunnerResult("osv", None, False, f"exit {rc}: {stderr.strip()[:200]}")

    try:
        sarif = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as e:
        return RunnerResult("osv", None, False, f"parse error: {e}")

    return RunnerResult("osv", sarif, True, None)
