"""Codex SAST runner — shells out to the locally-installed `codex` CLI.

Uses the user's existing ChatGPT/Codex subscription (no API key); auth is
managed by `codex login` outside this tool. We invoke `codex exec` in
non-interactive mode with `--output-schema` to force a JSON-only response
and `-o <file>` to capture it cleanly.

The result is wrapped in a synthetic SARIF doc so the existing normalize.py
pipeline can consume it like any other scanner.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import RunnerResult

# Map our severity vocabulary to a numeric security-severity used by the SARIF
# normalizer (it expects CVSS-style numerics under properties.security-severity).
_SEVERITY_TO_NUMERIC = {
    "critical": "9.5",
    "high":     "7.5",
    "medium":   "5.5",
    "low":      "3.5",
    "info":     "1.5",
}

# SARIF "level" mapping. Anything >= high is an error, medium is warning, low/info are notes.
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}

# JSON schema for codex's structured output. The schema is strict by design —
# extra fields are allowed (Codex sometimes adds them) but the required ones must be present.
_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": True,
    "required": ["findings"],
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "additionalProperties": True,
                "required": ["file", "rule_id", "severity", "title", "message"],
                "properties": {
                    "file":     {"type": "string"},
                    "line":     {"type": ["integer", "null"]},
                    "rule_id":  {"type": "string"},
                    "severity": {"type": "string",
                                 "enum": ["critical", "high", "medium", "low", "info"]},
                    "title":    {"type": "string"},
                    "message":  {"type": "string"},
                    "snippet":  {"type": ["string", "null"]},
                },
            },
        },
    },
}

_PROMPT = """You are a security code reviewer. Audit this repository for security vulnerabilities.

Focus on:
  1. Injection — SQL, NoSQL, command, template, XSS, LDAP, prototype pollution.
  2. Auth/authz bypass and missing access-control checks.
  3. Hardcoded secrets / keys / tokens in source (not the ones loaded from env).
  4. Unsafe deserialization, eval, dynamic code execution, unsafe reflection.
  5. SSRF, path traversal, file-upload mishandling.
  6. Misconfigured CORS, CSP, cookies, security headers, TLS.
  7. Race conditions, TOCTOU, insecure randomness for security tokens.
  8. Broken access control, IDOR, insecure direct object reference patterns.
  9. Cloud/provider-specific misconfiguration (RLS off, public buckets, etc.)
 10. Supply-chain risk visible in source (post-install scripts, runtime fetches).

DO NOT report:
  - Style issues, performance, dead code, generic best-practices.
  - Findings without a concrete file:line locator you can cite.
  - Hypothetical issues that depend on caller behavior outside the repo.
  - Test code unless the issue is real production risk (e.g. test data with real secrets).

Skip these directories entirely: node_modules, .git, __pycache__, vendor, archive,
dist, build, target, .venv, .next, .nuxt.

Each finding needs:
  - file        (repo-relative path)
  - line        (best estimate; null if truly unknown)
  - rule_id     (short kebab-case id you invent, e.g. "auth.missing-csrf-check")
  - severity    (one of: critical, high, medium, low, info)
  - title       (one short imperative sentence)
  - message     (2-4 sentences: what's wrong, why it's a security issue, how to fix)
  - snippet     (a SHORT identifying code excerpt; 1-3 lines max)

Calibrate severity by impact:
  - critical: RCE, auth bypass, exposed live credentials
  - high:     SQLi/XSS/SSRF with user-reachable surface
  - medium:   logic flaws, weak crypto, misconfig with bounded impact
  - low:      hardening / defense-in-depth
  - info:     documentation/comment-only observations

Return ONLY the JSON object matching the supplied schema. No prose, no preamble."""


def run(
    repo_dir: Path,
    binary: str = "codex",
    model: str | None = None,
    timeout: int = 1200,
    extra_args: list[str] | None = None,
) -> RunnerResult:
    """Invoke codex on `repo_dir` and return its findings as a SARIF doc.

    Failure modes (all return completed=False with a clear error string):
      - binary missing on PATH
      - user not logged in (codex emits an auth-error message)
      - codex exits non-zero
      - codex writes no output file or an unparseable file
      - schema enforcement fails (no `findings` key)

    The runner is safe — codex is invoked with `-s read-only` so it cannot
    modify the cloned repo, and `--ephemeral` so no session metadata persists.
    """
    if shutil.which(binary) is None:
        return RunnerResult("codex", None, False, f"binary not found: {binary}")

    with tempfile.TemporaryDirectory(prefix="codex-security_scan-") as td:
        schema_path = Path(td) / "schema.json"
        output_path = Path(td) / "output.json"
        schema_path.write_text(json.dumps(_SCHEMA))

        cmd = [
            binary, "exec",
            "-s", "read-only",
            "-C", str(repo_dir),
            "--color", "never",
            "--ephemeral",
            "--skip-git-repo-check",
            "--output-schema", str(schema_path),
            "-o", str(output_path),
        ]
        if model:
            cmd += ["-m", model]
        if extra_args:
            cmd += list(extra_args)
        cmd.append(_PROMPT)

        try:
            r = subprocess.run(
                cmd,
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                # Don't inherit security_scan's env wholesale — keep CODEX_HOME etc., but
                # strip anything that might confuse the agent. Codex reads its own
                # config from ~/.codex/.
                env={**os.environ},
            )
        except subprocess.TimeoutExpired:
            return RunnerResult("codex", None, False, f"timeout after {timeout}s")
        except FileNotFoundError:
            return RunnerResult("codex", None, False, f"binary not found: {binary}")
        except Exception as e:
            return RunnerResult("codex", None, False, f"{type(e).__name__}: {e}")

        if r.returncode != 0:
            err = (r.stderr or r.stdout or "").strip()
            # Detect auth failure (most common user-actionable error) and surface clearly.
            if "not logged in" in err.lower() or "auth" in err.lower():
                return RunnerResult(
                    "codex", None, False,
                    "codex auth failed — run `codex login` first",
                )
            return RunnerResult("codex", None, False, f"exit {r.returncode}: {err[:300]}")

        if not output_path.is_file():
            return RunnerResult(
                "codex", None, False,
                "codex completed but wrote no output file (model may have refused the task)",
            )

        try:
            data = json.loads(output_path.read_text() or "{}")
        except json.JSONDecodeError as e:
            return RunnerResult("codex", None, False, f"output parse error: {e}")

    findings = data.get("findings") or []
    if not isinstance(findings, list):
        return RunnerResult("codex", None, False, "output schema mismatch: 'findings' not a list")

    sarif = _to_sarif(findings)
    return RunnerResult("codex", sarif, True, None)


def _to_sarif(findings: list[dict]) -> dict:
    """Translate codex's JSON to the SARIF shape normalize.py expects.

    rule_id is namespaced with `codex.` so it never collides with semgrep /
    osv / trivy rule ids in fingerprints or labels.
    """
    rules: list[dict] = []
    results: list[dict] = []
    seen_rules: dict[str, dict] = {}

    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity") or "medium").lower()
        if sev not in _SEVERITY_TO_NUMERIC:
            sev = "medium"
        rid_raw = str(f.get("rule_id") or "codex-finding").strip()
        rid = rid_raw if rid_raw.startswith("codex.") else f"codex.{rid_raw}"
        title = str(f.get("title") or rid).strip()
        message = str(f.get("message") or "").strip()
        file_path = str(f.get("file") or "").strip()
        line_val = f.get("line")
        try:
            line = int(line_val) if line_val is not None else 1
        except (TypeError, ValueError):
            line = 1
        snippet = (str(f.get("snippet")) if f.get("snippet") else "")[:400]

        # Skip findings without a usable path — fingerprint needs one.
        if not file_path:
            continue

        if rid not in seen_rules:
            rule_entry = {
                "id": rid,
                "name": title,
                "properties": {
                    "security-severity": _SEVERITY_TO_NUMERIC[sev],
                    "scanner": "codex",
                },
            }
            seen_rules[rid] = rule_entry
            rules.append(rule_entry)

        results.append({
            "ruleId": rid,
            "level": _SEVERITY_TO_LEVEL[sev],
            "message": {"text": message or title},
            "properties": {
                "title": title,
                "security-severity": _SEVERITY_TO_NUMERIC[sev],
                "scanner": "codex",
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
            "tool": {"driver": {"name": "codex", "rules": rules}},
            "results": results,
        }],
    }
