"""Optional Gemma 4 triage via Ollama. Strictly additive.

Three jobs (all optional, all guard-railed in code):
  1. Fuzzy dedup tie-break — has this finding moved/renamed since an existing issue?
  2. Issue prose — title + body draft (factual fields only; no invented fix versions).
  3. Slack digest text.

Guardrails not entrusted to the prompt:
  - The deterministic marker and masked previews are always injected by code.
  - Any malformed or unreachable response falls back to the deterministic path.
  - Raw secrets are NEVER sent to the model (only `masked_preview` from the Finding).
  - We feed only factual fields from the scanner; no invention.
"""

from __future__ import annotations

import json
import sys

import requests

from secscan.config import TriageConfig
from secscan.fingerprint import parse_marker
from secscan.models import Finding
from secscan.sync import SyncResult, default_issue


class Triage:
    """Thin client over Ollama /api/chat. If anything goes wrong, the public methods
    silently return safe defaults (False, deterministic prose) so the run completes."""

    def __init__(self, cfg: TriageConfig):
        self.cfg = cfg
        self.enabled = cfg.enabled
        self._timeout = 120
        self._session = requests.Session()
        self._reachable: bool | None = None  # lazy probe

    # ---- public API used by sync.py -----------------------------------------

    def is_duplicate_of_existing(self, f: Finding, existing: list[dict]) -> bool:
        """Ask the model whether `f` is a renamed/moved version of any existing issue.
        Returns False on any error so the deterministic path always proceeds.
        """
        if not self.enabled or not existing:
            return False
        if not self._ensure_reachable():
            return False

        candidates = self._candidates(existing)
        if not candidates:
            return False

        prompt = (
            "Decide if a new security finding is a duplicate of one of the existing issues, "
            "i.e. the same underlying problem that has been renamed or moved. "
            "Only answer 'yes' when very confident. Reply with strict JSON: "
            '{"duplicate_of": <issue_number or null>, "confidence": "high"|"low"}.\n\n'
            f"NEW FINDING:\n{_finding_brief(f)}\n\n"
            f"EXISTING ISSUES:\n{json.dumps(candidates, indent=2)}"
        )
        try:
            obj = self._chat_json(prompt)
        except Exception as e:
            print(f"triage: fuzzy-dup chat failed: {e}", file=sys.stderr)
            return False
        if not isinstance(obj, dict):
            return False
        dup = obj.get("duplicate_of")
        conf = (obj.get("confidence") or "").lower()
        return bool(dup) and conf == "high"

    def write_issue(self, f: Finding) -> tuple[str, str]:
        """Draft an issue title + body. Falls back to deterministic templating on error."""
        if not self.enabled or not self._ensure_reachable():
            return default_issue(f)

        prompt = (
            "Draft a GitHub issue for the following security finding. "
            "Be factual and short. Do NOT invent fix versions, CVSS scores, or remediation. "
            "Use the scanner-supplied fields only. Reply with strict JSON: "
            '{"title": "...", "body": "markdown body"}.\n\n'
            f"FINDING:\n{_finding_brief(f)}"
        )
        try:
            obj = self._chat_json(prompt)
        except Exception as e:
            print(f"triage: write_issue chat failed: {e}", file=sys.stderr)
            return default_issue(f)
        if not isinstance(obj, dict) or "title" not in obj or "body" not in obj:
            return default_issue(f)
        title = str(obj["title"])[:200].strip() or (f.title or "security finding")
        body = str(obj["body"]).strip()
        if not body:
            return default_issue(f)
        return title, body

    def write_slack_digest(
        self, findings: list[Finding], result: SyncResult, repo: str, ref: str, parent_issue: int
    ) -> str | None:
        """Optional: draft a Slack digest. Caller falls back to deterministic if None."""
        if not self.enabled or not self._ensure_reachable():
            return None
        summary = {
            "repo": repo,
            "ref": ref,
            "parent_issue": parent_issue,
            "created": len(result.created),
            "skipped_dup": result.skipped_dup,
            "skipped_floor": result.skipped_floor,
            "by_severity": _by_severity(findings),
            "top_rules": _top_rules(findings, n=5),
        }
        prompt = (
            "Write a concise Slack message (<= 4 short lines) summarizing this security scan run. "
            "Use only the numbers below. No emojis. Reply as plain text, no JSON.\n\n"
            f"{json.dumps(summary, indent=2)}"
        )
        try:
            text = self._chat_text(prompt)
        except Exception as e:
            print(f"triage: slack digest chat failed: {e}", file=sys.stderr)
            return None
        return text.strip() or None

    # ---- internals ----------------------------------------------------------

    def _ensure_reachable(self) -> bool:
        if self._reachable is not None:
            return self._reachable
        try:
            r = self._session.get(f"{self.cfg.base_url.rstrip('/')}/api/tags", timeout=5)
            self._reachable = r.status_code < 500
        except requests.RequestException:
            self._reachable = False
            print(f"triage: Ollama unreachable at {self.cfg.base_url}", file=sys.stderr)
        return self._reachable

    def _chat_json(self, user_prompt: str) -> object:
        """POST /api/chat with format=json so Ollama returns parseable JSON."""
        r = self._session.post(
            f"{self.cfg.base_url.rstrip('/')}/api/chat",
            json={
                "model": self.cfg.model,
                "messages": [{"role": "user", "content": user_prompt}],
                "format": "json",
                "stream": False,
                "keep_alive": self.cfg.keep_alive,
            },
            timeout=self._timeout,
        )
        r.raise_for_status()
        msg = (r.json() or {}).get("message") or {}
        content = msg.get("content") or ""
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return None

    def _chat_text(self, user_prompt: str) -> str:
        r = self._session.post(
            f"{self.cfg.base_url.rstrip('/')}/api/chat",
            json={
                "model": self.cfg.model,
                "messages": [{"role": "user", "content": user_prompt}],
                "stream": False,
                "keep_alive": self.cfg.keep_alive,
            },
            timeout=self._timeout,
        )
        r.raise_for_status()
        return ((r.json() or {}).get("message") or {}).get("content") or ""

    @staticmethod
    def _candidates(existing: list[dict]) -> list[dict]:
        """Pick issues with parseable markers; pass only fields that won't leak secrets."""
        out: list[dict] = []
        for issue in existing:
            marker = parse_marker(issue.get("body"))
            if not marker:
                continue
            out.append({
                "number": issue.get("number"),
                "state": issue.get("state"),
                "rule": marker.get("rule"),
                "cat": marker.get("cat"),
                "title": (issue.get("title") or "")[:140],
            })
            if len(out) >= 50:
                break
        return out


def _finding_brief(f: Finding) -> str:
    """Sanitized snapshot of a Finding for the model. NEVER includes raw secret values."""
    safe = {
        "scanner": f.scanner,
        "category": f.category,
        "rule_id": f.rule_id,
        "severity": f.severity,
        "file_path": f.file_path,
        "line": f.line,
        "title": f.title,
        "message": f.message[:600] if f.message else "",
        "masked_preview": f.masked_preview,  # already masked; raw value never reaches here
        "extra": {k: v for k, v in f.extra.items() if k != "snippet"} | (
            {"snippet": f.extra["snippet"][:200]} if "snippet" in f.extra else {}
        ),
    }
    return json.dumps(safe, indent=2, default=str, ensure_ascii=False)


def _by_severity(findings: list[Finding]) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _top_rules(findings: list[Finding], n: int = 5) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]
