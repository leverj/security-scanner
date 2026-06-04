"""Create-decision logic. Dedup against existing project items, file new ones."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from security_scan.fingerprint import inject_marker, parse_marker, resolve_fingerprint
from security_scan.github import GitHub, ProjectContext
from security_scan.models import Finding


@dataclass
class SyncResult:
    created: list[dict] = field(default_factory=list)             # the new issue dicts
    created_findings: list[Finding] = field(default_factory=list)  # the Finding behind each created issue
    skipped_dup: int = 0                                           # fingerprint already filed
    skipped_fuzzy_dup: int = 0                                     # reserved (host-side LLM lane may bump)
    skipped_floor: int = 0                                         # below severity_floor
    total_findings: int = 0
    # Board-state tallies, computed from the existing items snapshot taken
    # at the START of the run (so they reflect the board BEFORE we filed
    # the new findings — the "before" picture the Slack digest reports).
    board_open_count: int = 0
    board_closed_24h_count: int = 0


def default_issue(f: Finding) -> tuple[str, str]:
    """Deterministic issue title + body."""
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
    project: ProjectContext,
    severity_floor: str = "low",
) -> SyncResult:
    """Dedup -> create-only. Never edits/closes/reopens.

    - Dedup against ALL existing project items (open + closed) — the project is
      the flat source of truth.
    - Marker is always injected by code.
    - Within a single run, the in-memory set prevents intra-run dupes too.
    """
    result = SyncResult(total_findings=len(findings))

    existing_items = gh.list_project_items(project.id)
    existing_fps: set[str] = set()
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
    for it in existing_items:
        marker = parse_marker(it.get("body"))
        if marker:
            existing_fps.add(marker["fp"])
        state = (it.get("state") or "").upper()
        if state == "OPEN":
            result.board_open_count += 1
        elif state == "CLOSED" and _closed_within(it.get("closed_at"), cutoff):
            result.board_closed_24h_count += 1

    for f in findings:
        if not f.meets_floor(severity_floor):
            result.skipped_floor += 1
            continue

        fp = resolve_fingerprint(f)

        if fp in existing_fps:
            result.skipped_dup += 1
            continue

        title, body = default_issue(f)
        body = inject_marker(body, fp, f)
        issue = gh.create_issue(title, body, labels=_labels_for(f))
        item_id = gh.add_to_project(project.id, issue["node_id"])
        gh.set_project_field(project.id, item_id, project.severity, f.severity)
        gh.set_project_field(project.id, item_id, project.category, f.category)
        result.created.append(issue)
        result.created_findings.append(f)
        existing_fps.add(fp)

    return result


def _labels_for(f: Finding) -> list[str]:
    """The label set applied to each issue filed."""
    return [
        "security",
        f"security-scan:{f.category}",
        f"security-scan:{f.severity}",
    ]


def _closed_within(iso_ts: str | None, cutoff: datetime) -> bool:
    """True iff `iso_ts` parses to a UTC datetime >= cutoff. GitHub returns
    closedAt as ISO 8601 with a `Z` suffix."""
    if not iso_ts:
        return False
    try:
        # Python 3.11 fromisoformat accepts 'Z' since 3.11; be defensive anyway.
        ts = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts >= cutoff
