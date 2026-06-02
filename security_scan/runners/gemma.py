"""Gemma SAST runner — uses local Ollama to scan source files for security issues.

Symmetric with `codex.py`: takes the cloned repo, picks security-relevant source
files (capped to keep the prompt bounded), feeds them to Gemma 4 with a strict
JSON output contract, and returns a synthetic SARIF doc.

Why a separate runner from triage.py: triage is post-processing (validate / write
prose for findings produced by other scanners). This is primary detection — Gemma
is the producer, not the reviewer.

Hard caps protect against runaway prompts on large repos:
  - max_files          — number of files in one prompt batch
  - max_file_bytes     — per-file content cap (truncated mid-line if needed)
  - max_total_bytes    — total prompt-content cap across all selected files
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path

import requests

from security_scan.redact import is_local_url, redact_text

from . import RunnerResult

# Extensions worth feeding to the model. Mirrors security_scan/detect._SEMGREP_EXTS with
# a few SQL/HCL/TF additions since LLM reading isn't limited to semgrep's parsers.
_SOURCE_EXTS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".pyw",
    ".rb",
    ".go",
    ".java", ".kt", ".kts", ".scala",
    ".swift",
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
    ".rs",
    ".php",
    ".sql",
    ".sh", ".bash",
    ".tf", ".hcl",
    ".yaml", ".yml",
    ".env", ".envrc",
}

_ALWAYS_SKIP_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", "dist", "build", "target",
    ".venv", ".next", ".nuxt", ".tox", ".pytest_cache", ".mypy_cache",
    "coverage", "htmlcov",
}

_SEVERITY_TO_NUMERIC = {
    "critical": "9.5",
    "high":     "7.5",
    "medium":   "5.5",
    "low":      "3.5",
    "info":     "1.5",
}
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

_SYSTEM_PROMPT = (
    "You are a security code reviewer. Read each file's contents carefully. "
    "Return ONLY a JSON object: {\"findings\": [...]}. Each finding has fields: "
    "file (repo-relative), line (1-based integer), rule_id (short kebab-case), "
    "severity (critical|high|medium|low|info), title (one short sentence), "
    "message (2-4 sentences), snippet (short code excerpt).\n\n"
    "Focus on real security issues only: injection, auth bypass, hardcoded "
    "credentials, unsafe deserialization, SSRF, path traversal, broken access "
    "control, misconfigured CORS/CSP, weak crypto, insecure randomness for "
    "tokens. Skip style nits, performance, dead code, and findings without a "
    "concrete file:line locator.\n\n"
    "Calibrate severity by impact, not surprise:\n"
    "  critical: RCE, auth bypass, live exposed credentials\n"
    "  high:     SQLi/XSS/SSRF with user-reachable surface\n"
    "  medium:   logic flaws, weak crypto, bounded-impact misconfig\n"
    "  low:      defense-in-depth, hardening\n"
    "  info:     observations\n\n"
    "If a file has no real security issues, simply omit it from the list. "
    "If nothing across all files has issues, return {\"findings\": []}."
)


def run(
    repo_dir: Path,
    base_url: str = "http://host.docker.internal:11434",
    model: str = "gemma4:26b",
    keep_alive: str = "5m",
    timeout: int = 1800,
    max_files: int = 60,
    max_file_bytes: int = 12_000,
    max_total_bytes: int = 200_000,
    exclude: list[str] | None = None,
) -> RunnerResult:
    """Walk `repo_dir`, batch source files into a single Gemma prompt, parse the JSON.

    Returns a SARIF dict on success; on any HTTP/parse failure returns completed=False
    with a short error string. Like every other runner, partial failure contributes
    zero findings — never blanket "all clear".
    """
    if not is_local_url(base_url):
        return RunnerResult(
            "gemma", None, False,
            f"refusing to send source to non-local Ollama at {base_url!r}; "
            "set gemma.base_url to a loopback/private host",
        )

    files = _select_files(repo_dir, exclude or [], max_files, max_file_bytes, max_total_bytes)
    if not files:
        # Empty repo or all files filtered out — treat as a no-op success.
        return RunnerResult("gemma", _empty_sarif(), True, None)

    user_content = _build_user_prompt(files, repo_dir)

    try:
        r = requests.post(
            f"{base_url.rstrip('/')}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": _SYSTEM_PROMPT},
                    {"role": "user", "content": user_content},
                ],
                "format": "json",
                "stream": False,
                "keep_alive": keep_alive,
            },
            timeout=timeout,
        )
    except requests.RequestException as e:
        return RunnerResult("gemma", None, False, f"ollama unreachable: {e}")

    if r.status_code >= 400:
        return RunnerResult("gemma", None, False, f"ollama http {r.status_code}: {r.text[:200]}")

    try:
        body = r.json() or {}
        content = (body.get("message") or {}).get("content") or ""
        data = json.loads(content) if content else {}
    except (ValueError, json.JSONDecodeError) as e:
        return RunnerResult("gemma", None, False, f"parse error: {e}")

    raw_findings = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(raw_findings, list):
        return RunnerResult("gemma", None, False, "output schema mismatch: 'findings' not a list")

    sarif = _to_sarif(raw_findings)
    return RunnerResult("gemma", sarif, True, None)


def _select_files(
    repo_dir: Path, exclude: list[str],
    max_files: int, max_file_bytes: int, max_total_bytes: int,
) -> list[tuple[str, str]]:
    """Pick up to `max_files` source files, capping each at `max_file_bytes` and the
    total at `max_total_bytes`. Returns a list of (repo_relative_path, content) pairs.
    Prefers files under common security-relevant paths (auth/, routes/, api/, etc.)."""
    candidates: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo_dir):
        # Prune always-skip dirs and user excludes.
        kept = []
        for n in dirnames:
            if n in _ALWAYS_SKIP_DIRS:
                continue
            rel = os.path.relpath(os.path.join(dirpath, n), repo_dir).replace(os.sep, "/")
            if _excluded(rel, exclude):
                continue
            kept.append(n)
        dirnames[:] = kept
        for fname in filenames:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _SOURCE_EXTS:
                continue
            p = Path(dirpath) / fname
            candidates.append(p)

    # Rank: security-suggestive path segments float to the top.
    def _rank(p: Path) -> tuple[int, str]:
        rel = str(p.relative_to(repo_dir)).replace(os.sep, "/").lower()
        score = 0
        for kw in ("auth", "login", "session", "token", "secret", "crypto", "password",
                   "route", "router", "api", "handler", "controller", "middleware",
                   "policy", "permission", "rbac", "acl",
                   "sql", "query", "db", "database",
                   "config", ".env", "secret"):
            if kw in rel:
                score -= 1
        return (score, rel)

    candidates.sort(key=_rank)

    out: list[tuple[str, str]] = []
    total = 0
    for p in candidates:
        if len(out) >= max_files:
            break
        try:
            raw = p.read_text(errors="ignore")
        except OSError:
            continue
        if len(raw) > max_file_bytes:
            raw = raw[:max_file_bytes] + "\n... (truncated)"
        if total + len(raw) > max_total_bytes:
            break
        rel = str(p.relative_to(repo_dir)).replace(os.sep, "/")
        out.append((rel, raw))
        total += len(raw)
    return out


def _excluded(rel: str, patterns: list[str]) -> bool:
    """Lightweight prefix/glob exclusion. We mirror detect._is_excluded loosely
    rather than importing it, to keep the runner standalone."""
    import fnmatch
    if not rel:
        return False
    for pat in patterns:
        if not pat:
            continue
        if pat.endswith("/"):
            prefix = pat.rstrip("/")
            if rel == prefix or rel.startswith(prefix + "/"):
                return True
            continue
        if fnmatch.fnmatch(rel, pat):
            return True
    return False


def _build_user_prompt(files: Iterable[tuple[str, str]], repo_dir: Path) -> str:
    parts = [
        f"Repository root: {repo_dir.name}",
        f"Files to review: {sum(1 for _ in files)}",
        "",
        "Each file is delimited by `===== FILE: <path> =====` markers.",
        "Cite line numbers as you see them in the content below "
        "(1-based, counting from the first line shown).",
        "",
    ]
    # files might be a generator above; re-list to iterate twice
    file_list = list(files)
    parts[1] = f"Files to review: {len(file_list)}"
    # Redact known-token shapes + high-entropy substrings from every file body
    # before the prompt leaves the box. Even though Ollama is meant to be local,
    # defence-in-depth: if someone points base_url at a remote host (or proxies
    # traffic), hardcoded credentials shouldn't slip out of source files.
    for rel, content in file_list:
        parts.append(f"===== FILE: {rel} =====")
        parts.append(redact_text(content))
        parts.append("")
    parts.append("Return JSON only.")
    return "\n".join(parts)


def _empty_sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "gemma"}}, "results": []}],
    }


def _to_sarif(findings: list[dict]) -> dict:
    rules: list[dict] = []
    results: list[dict] = []
    seen: dict[str, dict] = {}

    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "medium").lower()
        if sev not in _SEVERITY_TO_NUMERIC:
            sev = "medium"
        rid_raw = str(f.get("rule_id") or "gemma-finding").strip()
        rid = rid_raw if rid_raw.startswith("gemma.") else f"gemma.{rid_raw}"
        title = str(f.get("title") or rid).strip()
        message = str(f.get("message") or "").strip()
        file_path = str(f.get("file") or "").strip()
        if not file_path:
            continue
        line_val = f.get("line")
        try:
            line = int(line_val) if line_val is not None else 1
        except (TypeError, ValueError):
            line = 1
        snippet = (str(f.get("snippet")) if f.get("snippet") else "")[:400]

        if rid not in seen:
            entry = {
                "id": rid,
                "name": title,
                "properties": {
                    "security-severity": _SEVERITY_TO_NUMERIC[sev],
                    "scanner": "gemma",
                },
            }
            seen[rid] = entry
            rules.append(entry)

        results.append({
            "ruleId": rid,
            "level": _SEVERITY_TO_LEVEL[sev],
            "message": {"text": message or title},
            "properties": {
                "title": title,
                "security-severity": _SEVERITY_TO_NUMERIC[sev],
                "scanner": "gemma",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path},
                    "region": {
                        "startLine": max(1, line),
                        "snippet": {"text": snippet} if snippet else {},
                    },
                },
            }],
        })

    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gemma", "rules": rules}},
            "results": results,
        }],
    }
