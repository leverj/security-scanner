"""Supply-chain risk runner — default backend: Socket.dev CLI.

Covers attack patterns OSV-Scanner can't: typosquats, install-script execution,
capability changes between versions, maintainer takeover, known malware. Socket
analyses the lockfiles' declared packages against its registry-wide reputation
data; the source code stays local.

Lockfile-only mode: only the dep list crosses the trust boundary into Socket.
Source files are never uploaded.

Failure modes (all return completed=False with a clear error):
  - SOCKET_API_KEY env unset
  - `socket` binary not on PATH
  - socket CLI exits non-zero (e.g., auth failure, network unreachable)
  - socket emits unparseable JSON
  - no lockfiles found  -> completed=True with empty SARIF (no-op, not an error)
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from . import RunnerResult, _run

# Map Socket's severity tiers to our 5-tier scale. Socket uses
# "critical|high|middle|low" (sic — "middle" not "medium").
_TIER_TO_SEVERITY = {
    "critical": "critical",
    "high":     "high",
    "middle":   "medium",
    "medium":   "medium",
    "low":      "low",
    "info":     "info",
}

# A loose probe for "is there anything for socket to scan here?" — we don't
# enumerate every supported ecosystem; we just want a fast no-op when the
# repo has zero recognizable manifests. Socket itself does the real
# detection.
_LOCKFILE_GLOBS = [
    # npm / pnpm / yarn
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    # python
    "requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock",
    # ruby, go, rust, java, .net, php, dart, swift
    "Gemfile.lock", "go.mod", "Cargo.lock", "pom.xml", "build.gradle",
    "packages.lock.json", "composer.lock", "pubspec.lock",
    "Package.resolved", "Podfile.lock",
]


def run(
    root: Path,
    binary: str = "socket",
    api_key_env: str = "SOCKET_API_KEY",
    timeout: int = 600,
    issue_types: list[str] | None = None,
    exclude: list[str] | None = None,
) -> RunnerResult:
    _ = exclude  # normalize.py post-filters excluded paths
    if not _any_lockfile(root):
        return RunnerResult("supply_chain", _empty_sarif(), True, None)

    if shutil.which(binary) is None:
        return RunnerResult(
            "supply_chain", None, False, f"binary not found: {binary}"
        )

    if not os.environ.get(api_key_env):
        return RunnerResult(
            "supply_chain", None, False,
            f"env var '{api_key_env}' is empty or unset (holds the Socket API token)",
        )

    # `socket scan create --view --json <dir>` runs the scan and prints the
    # full report on stdout. `--view` blocks until the scan completes.
    # NOTE: Socket CLI flags evolve; this is the v2.x invocation. If a future
    # version breaks the contract, the runner returns a clear stderr message.
    cmd = [
        binary, "scan", "create",
        "--view",
        "--json",
        str(root),
    ]

    try:
        rc, stdout, stderr = _run(cmd, cwd=root, timeout=timeout)
    except FileNotFoundError:
        return RunnerResult("supply_chain", None, False, f"binary not found: {binary}")
    except Exception as e:
        return RunnerResult("supply_chain", None, False, f"{type(e).__name__}: {e}")

    if rc != 0:
        return RunnerResult(
            "supply_chain", None, False,
            f"socket scan exit {rc}: {(stderr or stdout).strip()[:300]}",
        )

    try:
        payload = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as e:
        return RunnerResult(
            "supply_chain", None, False, f"parse error: {e}",
        )

    return RunnerResult("supply_chain", _to_sarif(payload, issue_types), True, None)


def _any_lockfile(root: Path) -> bool:
    """Cheap probe: does the tree contain at least one supported manifest?

    Walks the tree, but stops as soon as one match is found. Avoids invoking
    Socket (which would do a network round-trip + count against your free-tier
    scan quota) on repos that simply don't have deps to analyse.
    """
    skip_dirs = {".git", "node_modules", "vendor", "__pycache__", ".venv"}
    needle = set(_LOCKFILE_GLOBS)
    for p in root.rglob("*"):
        # Skip anything inside an excluded directory anywhere in the path.
        if any(part in skip_dirs for part in p.parts):
            continue
        if p.is_file() and p.name in needle:
            return True
    return False


def _empty_sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "socket"}}, "results": []}],
    }


def _to_sarif(payload: dict, issue_types: list[str] | None) -> dict:
    """Map a Socket scan response into a synthetic SARIF doc the normalizer eats.

    Socket's scan response shape (abbreviated, from v2.x of the CLI):
      {
        "id": "<scan-id>",
        "issues": [
          {
            "type":        "typosquatRisk" | "installScripts" | ... ,
            "severity":    "critical" | "high" | "middle" | "low" | "info",
            "pkg_name":    "lodahs",
            "pkg_version": "1.0.0",
            "purl":        "pkg:npm/lodahs@1.0.0",
            "manifestFiles": ["package-lock.json"],
            "description": "Package name resembles 'lodash' ...",
            "url":         "https://socket.dev/npm/package/lodahs",
            "ecosystem":   "npm"
          },
          ...
        ],
        "scanVersion": "v0.X.Y"
      }

    Field names have varied across CLI versions — we accept both
    camelCase and snake_case shapes (Socket switched in v1.x).
    """
    results = []
    issues = payload.get("issues") or []

    for issue in issues:
        itype = issue.get("type") or "unknown"
        if issue_types and itype not in issue_types:
            continue

        # CLI versions disagree on field naming; tolerate both.
        pkg_name = issue.get("pkg_name") or issue.get("pkgName") or issue.get("name") or ""
        pkg_ver  = (
            issue.get("pkg_version") or issue.get("pkgVersion")
            or issue.get("version") or ""
        )
        purl     = issue.get("purl") or _build_purl(pkg_name, pkg_ver, issue.get("ecosystem"))
        manifest_files = (
            issue.get("manifestFiles") or issue.get("manifest_files") or []
        )
        manifest_file = manifest_files[0] if manifest_files else "<repo>"

        sev_raw = (issue.get("severity") or "info").lower()
        # Map to a numeric so the existing SARIF severity normalizer
        # (security-severity / CVSS-style) reads it correctly.
        sev = _TIER_TO_SEVERITY.get(sev_raw, "info")

        rule_id = f"socket.{itype}"
        title   = _short_title(itype, pkg_name, pkg_ver)
        message = issue.get("description") or title

        results.append({
            "ruleId": rule_id,
            "level":  _sev_to_sarif_level(sev),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": manifest_file},
                },
            }],
            "properties": {
                "security-severity": _sev_to_numeric(sev),
                "package":           pkg_name,
                "installed_version": pkg_ver,
                "ecosystem":         issue.get("ecosystem") or _eco_from_purl(purl),
                "purl":              purl,
                "socket_issue_type": itype,
                "socket_url":        issue.get("url") or "",
                "title":             title,
            },
        })

    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name":    "socket",
                "version": payload.get("scanVersion") or payload.get("version") or "",
            }},
            "results": results,
        }],
    }


def _build_purl(name: str, version: str, eco: str | None) -> str:
    if not name:
        return ""
    eco = (eco or "").lower() or "unknown"
    return f"pkg:{eco}/{name}@{version}" if version else f"pkg:{eco}/{name}"


def _eco_from_purl(purl: str) -> str:
    # pkg:<eco>/<rest>
    if not purl.startswith("pkg:"):
        return ""
    rest = purl[len("pkg:"):]
    return rest.split("/", 1)[0] if "/" in rest else ""


def _short_title(issue_type: str, pkg: str, ver: str) -> str:
    """Compact human title; details live in the issue body."""
    pkg_at = f"{pkg}@{ver}" if (pkg and ver) else (pkg or "unknown")
    pretty = {
        "typosquatRisk":    "Typosquat risk",
        "installScripts":   "Install scripts present",
        "networkAccess":    "Network access in package",
        "filesystemAccess": "Filesystem access in package",
        "shellAccess":      "Shell access in package",
        "usesEval":         "Uses eval()",
        "majorRefactor":    "Major refactor between versions",
        "newAuthor":        "New maintainer",
        "unmaintained":     "Unmaintained package",
        "malware":          "Known malware",
    }.get(issue_type, issue_type)
    return f"{pretty}: {pkg_at}"


_SEV_NUMERIC = {
    "critical": "9.5",
    "high":     "7.5",
    "medium":   "5.5",
    "low":      "3.5",
    "info":     "1.5",
}

_SEV_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "info":     "note",
}


def _sev_to_numeric(sev: str) -> str:
    return _SEV_NUMERIC.get(sev, "1.5")


def _sev_to_sarif_level(sev: str) -> str:
    return _SEV_LEVEL.get(sev, "note")
