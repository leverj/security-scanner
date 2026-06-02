"""Trivy runner — comprehensive supply-chain scanner.

Covers vulnerabilities (language packages + OS packages), secrets, IaC
misconfigurations, and license issues in a single invocation. Outputs SARIF
natively; each result carries a rule tag indicating its sub-category, which
normalize.py reads to assign one of: dependency | secret | iac | license.

Lockfile/source-only — Trivy never executes repo code.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import RunnerResult, _run


def run(root: Path, exclude: list[str] | None = None, binary: str = "trivy") -> RunnerResult:
    cmd = [
        binary,
        "fs",
        "--format", "sarif",
        "--quiet",
        "--scanners", "vuln,secret,misconfig,license",
        # Don't download a fresh DB on every run — the Dockerfile preloads it during
        # build, and the user can rebuild the image to refresh.
        "--skip-db-update",
        "--skip-java-db-update",
        # Be silent about progress to keep stderr clean (we still capture it on error).
        "--no-progress",
    ]
    for pat in exclude or []:
        # Trivy accepts directory patterns; strip the trailing slash since trivy is fussy.
        cmd += ["--skip-dirs", pat.rstrip("/")]
    cmd.append(str(root))

    try:
        rc, stdout, stderr = _run(cmd, cwd=root)
    except FileNotFoundError:
        return RunnerResult("trivy", None, False, f"binary not found: {binary}")
    except Exception as e:
        return RunnerResult("trivy", None, False, f"{type(e).__name__}: {e}")

    # Trivy's exit code semantics vary with --exit-code; default is 0 regardless of
    # findings. Trust the SARIF parse, same pattern as gitleaks v8.
    try:
        sarif = json.loads(stdout)
        return RunnerResult("trivy", sarif, True, None)
    except (json.JSONDecodeError, ValueError) as parse_err:
        if rc == 0:
            return RunnerResult("trivy", None, False, f"parse error: {parse_err}")
        return RunnerResult("trivy", None, False, f"exit {rc}: {stderr.strip()[:300]}")
