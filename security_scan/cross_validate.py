"""Cross-validate Codex and Gemma findings.

Each tool's findings are reviewed by the other:
  - For every Codex finding → ask Gemma (via Ollama): "real issue?" → verdict.
  - For every Gemma finding → ask Codex (via subprocess): "real issue?" → verdict.

Verdicts:
  - "real"           — validator agrees, keep severity as-is
  - "false_positive" — validator disagrees, downgrade severity one notch (high→medium,
                       medium→low, low→info; critical stays critical because the cost
                       of missing a real critical is too high to auto-downgrade).
  - "uncertain"      — validator couldn't decide; severity unchanged, flag with note.

The verdict + reason is written to `finding.extra["cross_validation"]` so the
project board (and humans) see both opinions. Findings are NEVER suppressed —
the project board is the single source of triage truth.

Why each tool is good for what:
  - Codex (cloud, ChatGPT subscription) is better at deep multi-file reasoning,
    framework idioms, and subtle business-logic / auth bugs. Use it as the
    primary depth scanner and as a "second opinion" on Gemma's flags.
  - Gemma (local Ollama, free) is fast, has no quota, and is reliable at
    pattern-shaped findings. Use it as the high-volume validator AND as a
    pattern-scale primary scanner.

So when both are enabled: Codex is the heavyweight detective, Gemma is the
fast peer reviewer. Each catches the other's blind spots.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import requests

from security_scan.models import SEVERITY_ORDER, Finding

# Severity downgrade ladder. Critical is intentionally NOT downgraded — the
# asymmetry is deliberate (worst case for FP-on-critical is one extra issue
# in the board; worst case for missed-real-critical is a shipped RCE).
_DOWNGRADE = {
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
    "critical": "critical",
}

_REVIEW_PROMPT = """You are a senior security reviewer. Another tool has flagged this finding.
Decide whether it is a real, exploitable issue or a false positive.

Finding:
{finding_json}

File excerpt (if available):
{snippet}

Answer with strict JSON only:
{{
  "verdict": "real" | "false_positive" | "uncertain",
  "reason": "one sentence, plain English"
}}

Be skeptical: if the finding is speculative, depends on caller behavior you
can't see, or describes a generic best-practice without exploit impact,
mark it false_positive. If you genuinely can't tell from the excerpt, say
uncertain. Otherwise: real."""


def cross_validate(
    findings: list[Finding],
    *,
    repo_dir: Path,
    codex_enabled: bool,
    gemma_enabled: bool,
    codex_binary: str = "codex",
    codex_model: str | None = None,
    codex_timeout: int = 300,
    ollama_url: str = "http://host.docker.internal:11434",
    gemma_model: str = "gemma4:26b",
    gemma_keep_alive: str = "5m",
    gemma_timeout: int = 180,
) -> list[Finding]:
    """Mutate `findings` in place with a `cross_validation` extra and possibly
    a downgraded severity. Returns the same list for convenience.

    Both tools must be enabled for cross-validation to do anything meaningful —
    if only one ran, there's nothing to compare against. If both ran but one
    is unreachable at validation time we silently skip that direction.
    """
    if not (codex_enabled and gemma_enabled):
        return findings

    codex_available = shutil.which(codex_binary) is not None
    gemma_reachable = _ping_ollama(ollama_url)

    for f in findings:
        if f.scanner == "codex" and gemma_reachable:
            verdict, reason = _gemma_verdict(
                f, repo_dir=repo_dir, url=ollama_url, model=gemma_model,
                keep_alive=gemma_keep_alive, timeout=gemma_timeout,
            )
            _apply_verdict(f, validator="gemma", verdict=verdict, reason=reason)
        elif f.scanner == "gemma" and codex_available:
            verdict, reason = _codex_verdict(
                f, repo_dir=repo_dir, binary=codex_binary,
                model=codex_model, timeout=codex_timeout,
            )
            _apply_verdict(f, validator="codex", verdict=verdict, reason=reason)
    return findings


def _apply_verdict(f: Finding, *, validator: str, verdict: str, reason: str) -> None:
    verdict = verdict.lower() if isinstance(verdict, str) else "uncertain"
    if verdict not in ("real", "false_positive", "uncertain"):
        verdict = "uncertain"
    original_severity = f.severity
    if verdict == "false_positive":
        f.severity = _DOWNGRADE.get(f.severity, f.severity)
    f.extra = {
        **(f.extra or {}),
        "cross_validation": {
            "validator": validator,
            "verdict": verdict,
            "reason": (reason or "").strip()[:300],
            "original_severity": original_severity,
        },
    }


# ---- Gemma verdict (Ollama) -----------------------------------------------


def _ping_ollama(url: str) -> bool:
    try:
        r = requests.get(f"{url.rstrip('/')}/api/tags", timeout=5)
        return r.status_code < 500
    except requests.RequestException:
        return False


def _gemma_verdict(
    f: Finding, *, repo_dir: Path, url: str, model: str, keep_alive: str, timeout: int,
) -> tuple[str, str]:
    snippet = _read_snippet(repo_dir, f.file_path, f.line) or (f.extra or {}).get("snippet", "")
    prompt = _REVIEW_PROMPT.format(
        finding_json=json.dumps(_finding_summary(f), indent=2),
        snippet=(str(snippet)[:1200] or "(unavailable)"),
    )
    try:
        r = requests.post(
            f"{url.rstrip('/')}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "format": "json",
                "stream": False,
                "keep_alive": keep_alive,
            },
            timeout=timeout,
        )
        r.raise_for_status()
        content = ((r.json() or {}).get("message") or {}).get("content") or ""
        data = json.loads(content) if content else {}
    except (requests.RequestException, ValueError, json.JSONDecodeError) as e:
        print(f"cross-validate: gemma review failed for {f.rule_id}: {e}", file=sys.stderr)
        return ("uncertain", "validator unavailable")
    verdict = str((data or {}).get("verdict", "uncertain"))
    reason = str((data or {}).get("reason", ""))
    return (verdict, reason)


# ---- Codex verdict (subprocess) -------------------------------------------


def _codex_verdict(
    f: Finding, *, repo_dir: Path, binary: str, model: str | None, timeout: int,
) -> tuple[str, str]:
    snippet = _read_snippet(repo_dir, f.file_path, f.line) or (f.extra or {}).get("snippet", "")
    prompt = _REVIEW_PROMPT.format(
        finding_json=json.dumps(_finding_summary(f), indent=2),
        snippet=(str(snippet)[:1200] or "(unavailable)"),
    )
    with tempfile.TemporaryDirectory(prefix="codex-validate-") as td:
        schema = Path(td) / "schema.json"
        out = Path(td) / "out.json"
        schema.write_text(json.dumps({
            "type": "object",
            "required": ["verdict", "reason"],
            "properties": {
                "verdict": {"type": "string", "enum": ["real", "false_positive", "uncertain"]},
                "reason": {"type": "string"},
            },
        }))
        cmd = [
            binary, "exec",
            "-s", "read-only",
            "-C", str(repo_dir),
            "--color", "never",
            "--ephemeral",
            "--skip-git-repo-check",
            "--output-schema", str(schema),
            "-o", str(out),
        ]
        if model:
            cmd += ["-m", model]
        cmd.append(prompt)
        try:
            r = subprocess.run(
                cmd, cwd=str(repo_dir), capture_output=True, text=True,
                timeout=timeout, check=False, env={**os.environ},
            )
        except subprocess.TimeoutExpired:
            return ("uncertain", "validator timeout")
        except Exception as e:
            print(f"cross-validate: codex review failed for {f.rule_id}: {e}", file=sys.stderr)
            return ("uncertain", "validator unavailable")
        if r.returncode != 0 or not out.is_file():
            return ("uncertain", "validator failed")
        try:
            data = json.loads(out.read_text() or "{}")
        except json.JSONDecodeError:
            return ("uncertain", "validator parse error")
    verdict = str((data or {}).get("verdict", "uncertain"))
    reason = str((data or {}).get("reason", ""))
    return (verdict, reason)


# ---- helpers --------------------------------------------------------------


def _finding_summary(f: Finding) -> dict:
    """The factual fields we hand to a validator. NEVER include raw secrets — the
    Finding model masks those already, but be defensive."""
    return {
        "scanner": f.scanner,
        "category": f.category,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "file": f.file_path,
        "line": f.line,
        "title": f.title,
        "message": f.message,
        "masked_preview": f.masked_preview,
    }


def _read_snippet(repo_dir: Path, file_path: str, line: int | None, ctx: int = 6) -> str:
    """Pull a small context window around `line` from the cloned repo. Returns
    empty string on any read failure (the validator can still decide from the
    finding's message)."""
    if not file_path:
        return ""
    p = repo_dir / file_path
    try:
        if not p.is_file():
            return ""
        lines = p.read_text(errors="ignore").splitlines()
    except OSError:
        return ""
    if not lines:
        return ""
    line = max(1, int(line or 1))
    start = max(0, line - 1 - ctx)
    end = min(len(lines), line - 1 + ctx + 1)
    return "\n".join(f"{i + 1:4d}: {lines[i]}" for i in range(start, end))


# Ensure SEVERITY_ORDER import is actually used downstream — keeps the linter happy
# while signaling that this module respects the canonical severity vocabulary.
assert "critical" in SEVERITY_ORDER
