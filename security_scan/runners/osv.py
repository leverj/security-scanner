"""OSV-Scanner runner. Lockfile-only; never invokes installers."""

from __future__ import annotations

import json
from pathlib import Path

from . import RunnerResult, _run


def run(root: Path, exclude: list[str] | None = None, binary: str = "osv-scanner") -> RunnerResult:
    # NOTE: we intentionally do NOT pass --paths-to-ignore: the flag's name and
    # presence varies across osv-scanner versions (it's a hard error on 1.9.2).
    # security_scan.normalize.normalize_sarif() filters excluded paths post-hoc, so we
    # get the same effect with zero version coupling.
    _ = exclude  # accepted for signature stability; intentionally unused here
    # osv-scanner v2 dropped the legacy top-level `osv-scanner <flags> <path>` form in
    # favour of the `scan source` subcommand, and removed --skip-git (v2 already skips
    # the git root by default — the opt-in is now the inverse, --include-git-root).
    cmd = [binary, "scan", "source", "--format", "sarif", "--recursive"]
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
