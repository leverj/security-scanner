"""Gitleaks runner. Writes SARIF to a tempfile and reads it back.

Gitleaks v7 accepted `--report-path -` as a stdout sentinel; v8 silently writes
zero bytes to stdout with that flag and only honors a real file path. We use a
NamedTemporaryFile inside the scan root so the report is always retrievable and
the version doesn't matter.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from . import RunnerResult, _run


def run(root: Path, binary: str = "gitleaks") -> RunnerResult:
    # Put the tempfile inside `root` (which is the cloned repo dir) so it shares
    # the same filesystem and is wiped along with the clone on container exit.
    tf = tempfile.NamedTemporaryFile(
        mode="w+", suffix=".sarif", dir=str(root), delete=False
    )
    report_path = Path(tf.name)
    tf.close()

    try:
        cmd = [
            binary,
            "detect",
            "--source", str(root),
            "--report-format", "sarif",
            "--report-path", str(report_path),
        ]

        try:
            rc, stdout, stderr = _run(cmd, cwd=root)
        except FileNotFoundError:
            return RunnerResult("gitleaks", None, False, f"binary not found: {binary}")
        except Exception as e:
            return RunnerResult("gitleaks", None, False, f"{type(e).__name__}: {e}")

        # Trust the report file, not the exit code (v7 used rc=77, v8 uses rc=1,
        # both mean "leaks found" — i.e. a successful scan).
        if not report_path.is_file() or report_path.stat().st_size == 0:
            # Gitleaks writes a stub SARIF even on zero findings; an empty/missing
            # file means the scanner didn't run to completion.
            return RunnerResult(
                "gitleaks", None, False,
                f"exit {rc}: no SARIF report written ({stderr.strip()[:200]})",
            )

        try:
            sarif = json.loads(report_path.read_text())
        except (json.JSONDecodeError, ValueError) as e:
            return RunnerResult("gitleaks", None, False, f"parse error: {e}")

        return RunnerResult("gitleaks", sarif, True, None)
    finally:
        try:
            report_path.unlink()
        except OSError:
            pass
