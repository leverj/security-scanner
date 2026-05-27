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
) -> bool:
    """Post a Slack message summarizing the run. Returns True on success.

    `digest_text` may be supplied by triage; otherwise a deterministic summary is built.
    """
    if not slack.enabled:
        return False

    text = digest_text or _default_digest(findings, result, repo, ref, parent_issue)

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


def _default_digest(
    findings: list[Finding], result: SyncResult, repo: str, ref: str, parent_issue: int
) -> str:
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    parts = []
    for s in ("critical", "high", "medium", "low", "info"):
        if by_sev.get(s):
            parts.append(f"{s}: {by_sev[s]}")
    breakdown = " · ".join(parts) if parts else "no findings"
    return (
        f"*secscan* `{repo}@{ref}` parent #{parent_issue}\n"
        f"{breakdown}\n"
        f"created: {len(result.created)} · dup-skipped: {result.skipped_dup} "
        f"· below-floor: {result.skipped_floor}"
    )
