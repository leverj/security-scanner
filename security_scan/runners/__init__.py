"""Scanner runner contract. Invokes pre-installed binaries, returns parsed SARIF."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RunnerResult:
    scanner: str
    sarif: dict | None
    completed: bool
    error: str | None = None


def _run(cmd: list[str], cwd: Path, timeout: int = 600) -> tuple[int, str, str]:
    """Wrap subprocess.run. Returns (returncode, stdout, stderr). Never logs args."""
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr
