"""Optional Slack digest. Either webhook URL or chat.postMessage with bot token.

Strictly additive: a Slack failure must never block the run. The deterministic
summary is computed by code; triage may override the prose if available.
"""

from __future__ import annotations

import os
import sys

import requests

from secscan.config import SlackConfig
from secscan.models import Finding
from secscan.sync import SyncResult


def post_digest(
    slack: SlackConfig,
    findings: list[Finding],
    result: SyncResult,
    repo: str,
    ref: str,
    parent_issue: int,
    digest_text: str | None = None,
    intro: str | None = None,
) -> bool:
    """Post a Slack message summarizing the run. Returns True on success.

    Two ways callers can influence the message:
      - `intro` (preferred): a one-line LLM-generated summary that we prepend to
        the deterministic per-category digest. Structure stays consistent across
        runs; the LLM only adds color.
      - `digest_text` (legacy): fully replaces the digest body. Kept for callers
        that want to entirely override the format.
    """
    if not slack.enabled:
        return False

    if digest_text:
        text = digest_text
    else:
        text = _default_digest(findings, result, repo, ref, parent_issue)
        if intro:
            text = f":speech_balloon: _{intro}_\n\n{text}"

    try:
        if slack.webhook_url_env:
            url = os.environ.get(slack.webhook_url_env, "")
            if not url:
                print(f"notify: env var {slack.webhook_url_env} unset", file=sys.stderr)
                return False
            return _post_webhook(url, text)
        if slack.channel_id_env:
            channel = os.environ.get(slack.channel_id_env, "")
            token = os.environ.get(slack.bot_token_env or "SLACK_BOT_TOKEN", "")
            if not (channel and token):
                print("notify: SLACK_CHANNEL_ID or SLACK_BOT_TOKEN unset", file=sys.stderr)
                return False
            return _post_chat(token, channel, text)
        print("notify: slack.enabled but no webhook_url_env or channel_id_env set", file=sys.stderr)
        return False
    except requests.RequestException as e:
        print(f"notify: slack post failed (non-blocking): {e}", file=sys.stderr)
        return False


def _post_webhook(url: str, text: str) -> bool:
    r = requests.post(url, json={"text": text}, timeout=15)
    return r.status_code < 300


def _post_chat(token: str, channel: str, text: str) -> bool:
    r = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {token}"},
        json={"channel": channel, "text": text},
        timeout=15,
    )
    return r.status_code < 300 and (r.json() or {}).get("ok") is True


_SEV_EMOJI = {
    "critical": ":red_circle:",
    "high":     ":large_orange_circle:",
    "medium":   ":large_yellow_circle:",
    "low":      ":large_blue_circle:",
    "info":     ":white_circle:",
}

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_CATEGORY_SECTIONS = [
    # (category, emoji, label) — ordered by triage priority
    ("secret-verified", ":key:",                "Secrets (verified live)"),
    ("secret",          ":key:",                "Secrets"),
    ("dependency",      ":shield:",             "Dependencies"),
    ("iac",             ":building_construction:", "IaC misconfigurations"),
    ("sast",            ":test_tube:",          "Code (SAST)"),
    ("license",         ":page_with_curl:",     "License"),
]

_PER_SECTION_LIMIT = 5  # show top N findings per category to keep messages skimmable


def _default_digest(
    findings: list[Finding], result: SyncResult, repo: str, ref: str, parent_issue: int
) -> str:
    """Slack mrkdwn-formatted digest. Per-category sections, top findings each,
    overall severity breakdown footer.

    Falls back to the old one-liner only when there are no findings AND nothing
    was created (so a "you're clean" message isn't a wall of empty sections).
    """
    by_cat: dict[str, list[Finding]] = {}
    by_sev: dict[str, int] = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    lines: list[str] = [f":lock: *secscan* — `{repo}@{ref}` — parent #{parent_issue}"]

    if not findings:
        lines.append("_no findings above severity floor_")
    else:
        for cat_key, emoji, label in _CATEGORY_SECTIONS:
            cat_findings = by_cat.get(cat_key) or []
            if not cat_findings:
                continue
            cat_findings.sort(key=lambda f: (_SEV_RANK.get(f.severity, 99), f.title))
            lines.append("")
            lines.append(f"{emoji} *{label}* ({len(cat_findings)})")
            for f in cat_findings[:_PER_SECTION_LIMIT]:
                lines.append(f"  {_SEV_EMOJI.get(f.severity, '•')} *{f.severity}* — {_one_liner(f)}")
            if len(cat_findings) > _PER_SECTION_LIMIT:
                lines.append(f"  _…and {len(cat_findings) - _PER_SECTION_LIMIT} more_")

    # Severity overall + create/dedup footer
    sev_parts = [f"{s}: {by_sev[s]}" for s in ("critical", "high", "medium", "low", "info") if by_sev.get(s)]
    if sev_parts:
        lines.append("")
        lines.append(":bar_chart: " + " · ".join(sev_parts))
    lines.append(
        f":card_index_dividers: filed {len(result.created)} · "
        f"dup-skipped {result.skipped_dup} · below-floor {result.skipped_floor}"
    )
    return "\n".join(lines)


def _one_liner(f: Finding) -> str:
    """Compact per-finding line. Packs the most relevant fields per category."""
    if f.category in ("dependency", "supply-chain"):
        pkg = f.extra.get("package") or ""
        ver = f.extra.get("installed_version") or ""
        eco = f.extra.get("ecosystem") or ""
        fixed = f.extra.get("fixed_versions") or []
        head = f"{pkg}@{ver}" if pkg else f.rule_id
        if eco:
            head = f"{head} ({eco})"
        fix_note = f"fixed in {fixed[0]}" if fixed else "no fix"
        return f"{head} · `{f.rule_id}` · {fix_note}"
    if f.category in ("secret", "secret-verified"):
        detector = f.extra.get("detector") or f.rule_id
        at = f"{f.file_path}:{f.line}" if f.line else f.file_path
        suffix = " *(VERIFIED LIVE)*" if f.extra.get("verified") else ""
        return f"{detector} · {at}{suffix}"
    if f.category == "iac":
        at = f"{f.file_path}:{f.line}" if f.line else f.file_path
        return f"{f.rule_id} · {at}"
    if f.category == "license":
        return f"{f.rule_id} · {f.file_path}"
    # sast / fallback
    at = f"{f.file_path}:{f.line}" if f.line else f.file_path
    return f"{f.rule_id} · {at}"
