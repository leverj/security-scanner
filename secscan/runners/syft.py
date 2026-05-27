"""Syft runner — produces a CycloneDX SBOM artifact for the scanned tree.

Unlike the other scanners, Syft does not file sub-issues. It writes the SBOM
to disk so it can be archived/uploaded by the caller. RunnerResult.sarif
carries a small metadata dict (path + component count + format) so the
orchestrator can log a one-line summary and downstream Slack digests can
reference it.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import RunnerResult, _run

SYFT_SENTINEL = "_syft_sbom"


def run(
    root: Path,
    output_path: Path,
    output_format: str = "cyclonedx-json",
    binary: str = "syft",
) -> RunnerResult:
    """Generate an SBOM at `output_path` in the requested format.

    output_format: cyclonedx-json | spdx-json | syft-json | github-json (etc.)
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    cmd = [
        binary,
        "scan",
        f"dir:{root}",
        "-o", f"{output_format}={output_path}",
        "--quiet",
    ]

    try:
        rc, stdout, stderr = _run(cmd, cwd=root)
    except FileNotFoundError:
        return RunnerResult("syft", None, False, f"binary not found: {binary}")
    except Exception as e:
        return RunnerResult("syft", None, False, f"{type(e).__name__}: {e}")

    if rc != 0 or not output_path.is_file():
        return RunnerResult("syft", None, False, f"exit {rc}: {stderr.strip()[:300]}")

    components = _count_components(output_path, output_format)
    meta = {
        SYFT_SENTINEL: {
            "path": str(output_path),
            "format": output_format,
            "components": components,
        }
    }
    return RunnerResult("syft", meta, True, None)


def _count_components(sbom_path: Path, fmt: str) -> int:
    """Best-effort component count for the summary line. 0 on any parse trouble."""
    try:
        data = json.loads(sbom_path.read_text())
    except (OSError, json.JSONDecodeError):
        return 0
    if "cyclonedx" in fmt:
        return len(data.get("components") or [])
    if "spdx" in fmt:
        return len(data.get("packages") or [])
    if "syft" in fmt:
        return len(data.get("artifacts") or [])
    return 0
