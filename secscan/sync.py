"""Create-decision logic. Dedup against existing sub-issues, file new ones.

The deterministic marker is always injected by code, regardless of whether the
issue prose came from a template or from Gemma. The model never owns identity.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from typing import Protocol

from secscan.fingerprint import inject_marker, parse_marker, resolve_fingerprint
from secscan.github import GitHub
from secscan.models import Finding


class Triage(Protocol):
    """Optional Gemma-backed triage. Both methods return safe defaults if the
    underlying model is unreachable; the deterministic path stays correct."""

    enabled: bool

    def is_duplicate_of_existing(self, f: Finding, existing: list[dict]) -> bool: ...

    def write_issue(self, f: Finding) -> tuple[str, str]: ...


@dataclass
class SyncResult:
    created: list[dict] = field(default_factory=list)         # the new issue dicts
    skipped_dup: int = 0                                       # fingerprint already filed
    skipped_fuzzy_dup: int = 0                                 # Gemma matched to an existing
    skipped_floor: int = 0                                     # below severity_floor
    total_findings: int = 0


def default_issue(f: Finding) -> tuple[str, str]:
    """Deterministic issue title + body. Used when triage is disabled or fails."""
    title = f.title or f.rule_id or "security finding"
    if len(title) > 200:
        title = title[:197] + "..."

    lines = [
        f"**Scanner:** `{f.scanner}`",
        f"**Category:** `{f.category}`",
        f"**Severity:** `{f.severity}`",
        f"**Rule:** `{f.rule_id}`",
        f"**File:** `{f.file_path}`" + (f" (line {f.line})" if f.line else ""),
        "",
        "### Message",
        f.message or "_(no message)_",
    ]
    if f.masked_preview:
        lines += ["", "### Masked preview", f"`{f.masked_preview}`"]
    if f.extra:
        lines += ["", "### Details"]
        for k, v in sorted(f.extra.items()):
            if k == "snippet":  # already implied by file/line; long; skip
                continue
            lines.append(f"- **{k}:** `{v}`")
    return title, "\n".join(lines)


def sync(
    findings: list[Finding],
    gh: GitHub,
    parent_issue: int,
    severity_floor: str = "low",
    triage: Triage | None = None,
) -> SyncResult:
    """Dedup -> create-only. Never edits/closes/reopens.

    - Dedup against ALL existing sub-issues (open + closed).
    - Marker is always injected by code.
    - Within a single run, the in-memory set prevents intra-run dupes too.
    """
    result = SyncResult(total_findings=len(findings))

    existing_issues = gh.list_subissues(parent_issue)
    existing_fps: set[str] = set()
    for issue in existing_issues:
        marker = parse_marker(issue.get("body"))
        if marker:
            existing_fps.add(marker["fp"])

    for f in findings:
        if not f.meets_floor(severity_floor):
            result.skipped_floor += 1
            continue

        fp = resolve_fingerprint(f)

        if fp in existing_fps:
            result.skipped_dup += 1
            continue

        # Optional fuzzy tie-break: catch renamed/moved code (different path -> different fp).
        if triage is not None and getattr(triage, "enabled", False):
            try:
                if triage.is_duplicate_of_existing(f, existing_issues):
                    result.skipped_fuzzy_dup += 1
                    continue
            except Exception as e:
                # Triage failures must never block the deterministic path.
                print(f"sync: triage fuzzy-dup check failed, continuing: {e}", file=sys.stderr)

        if triage is not None and getattr(triage, "enabled", False):
            try:
                title, body = triage.write_issue(f)
            except Exception as e:
                print(f"sync: triage prose failed, using default: {e}", file=sys.stderr)
                title, body = default_issue(f)
        else:
            title, body = default_issue(f)

        body = inject_marker(body, fp, f)
        issue = gh.create_issue(title, body)
        gh.link_subissue(parent_issue, issue)
        result.created.append(issue)
        existing_fps.add(fp)

    return result
