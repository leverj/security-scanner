from unittest.mock import MagicMock, patch

from secscan.config import SlackConfig
from secscan.models import Finding
from secscan.notify import _default_digest, post_digest
from secscan.sync import SyncResult


def _f(sev):
    return Finding("semgrep", "sast", "R", sev, "a.js", 1, "t", "m")


def test_disabled_slack_is_noop(monkeypatch):
    slack = SlackConfig(enabled=False)
    monkeypatch.setattr("secscan.notify.requests.post", lambda *a, **kw: (_ for _ in ()).throw(AssertionError("called")))
    assert post_digest(slack, [], SyncResult(), "o/n", "main", 1) is False


def test_webhook_called_with_text(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    slack = SlackConfig(enabled=True, webhook_url_env="SLACK_WEBHOOK_URL")
    resp = MagicMock(status_code=200)
    with patch("secscan.notify.requests.post", return_value=resp) as mp:
        ok = post_digest(slack, [_f("high")], SyncResult(created=[{"number": 1}]), "o/n", "main", 42)
    assert ok is True
    args, kwargs = mp.call_args
    assert args[0] == "https://hooks.slack.test/x"
    assert "secscan" in kwargs["json"]["text"]


def test_webhook_missing_env_returns_false(monkeypatch, capsys):
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    slack = SlackConfig(enabled=True, webhook_url_env="SLACK_WEBHOOK_URL")
    assert post_digest(slack, [], SyncResult(), "o/n", "main", 1) is False


def test_chat_postmessage_used_when_channel_set(monkeypatch):
    monkeypatch.setenv("SLACK_CHANNEL_ID", "C123")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-fake")
    slack = SlackConfig(enabled=True, channel_id_env="SLACK_CHANNEL_ID", bot_token_env="SLACK_BOT_TOKEN")
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"ok": True}
    with patch("secscan.notify.requests.post", return_value=resp) as mp:
        ok = post_digest(slack, [], SyncResult(), "o/n", "main", 1)
    assert ok is True
    assert mp.call_args.args[0] == "https://slack.com/api/chat.postMessage"
    assert mp.call_args.kwargs["headers"]["Authorization"] == "Bearer xoxb-fake"


def test_default_digest_includes_severity_breakdown():
    findings = [_f("high"), _f("high"), _f("low")]
    text = _default_digest(findings, SyncResult(created=[{}, {}], skipped_dup=1), "o/n", "main", 9)
    assert "high: 2" in text
    assert "low: 1" in text
    assert "filed 2" in text
    assert "dup-skipped 1" in text
    # New format: must have category section + severity emoji.
    assert ":test_tube:" in text          # SAST category emoji
    assert ":large_orange_circle:" in text  # high-severity emoji


def test_default_digest_no_findings():
    text = _default_digest([], SyncResult(), "o/n", "main", 9)
    assert "no findings" in text
    assert "filed 0" in text


def test_default_digest_groups_by_category():
    from secscan.models import Finding
    findings = [
        Finding("trivy", "dependency", "CVE-2024-1", "critical", "package-lock.json", 1, "t", "m",
                extra={"package": "left-pad", "installed_version": "1.0.0",
                       "ecosystem": "npm", "fixed_versions": ["1.3.0"]}),
        Finding("trufflehog", "secret-verified", "trufflehog/GitHub/verified", "critical",
                "src/config.js", 42, "t", "m",
                extra={"detector": "GitHub", "verified": True}),
        Finding("trivy", "iac", "AVD-DS-0002", "medium", "Dockerfile", 1, "t", "m"),
    ]
    text = _default_digest(findings, SyncResult(created=findings), "o/n", "main", 9)
    # Each category gets its own section.
    assert "Dependencies" in text
    assert "Secrets (verified live)" in text
    assert "IaC misconfigurations" in text
    # Dependency one-liner shows package + fix info.
    assert "left-pad@1.0.0" in text
    assert "fixed in 1.3.0" in text
    # Verified-live secret is annotated.
    assert "VERIFIED LIVE" in text


def test_default_digest_caps_per_section():
    from secscan.models import Finding
    findings = [
        Finding("semgrep", "sast", f"rule-{i}", "medium", "f.js", i, f"t{i}", "m")
        for i in range(10)
    ]
    text = _default_digest(findings, SyncResult(), "o/n", "main", 9)
    assert "and 5 more" in text  # cap = 5 per section


def test_intro_is_prepended_to_structured_digest(monkeypatch):
    """LLM intro should ride on top of the deterministic per-category digest,
    not replace it."""
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    slack = SlackConfig(enabled=True, webhook_url_env="SLACK_WEBHOOK_URL")
    resp = MagicMock(status_code=200)
    with patch("secscan.notify.requests.post", return_value=resp) as mp:
        post_digest(
            slack, [_f("high"), _f("medium")], SyncResult(created=[{"n": 1}]),
            "o/n", "main", 9,
            intro="High-risk run: jwt@2.10.2 has an unpatched RCE",
        )
    sent = mp.call_args.kwargs["json"]["text"]
    # The LLM intro is bold-italicized at top.
    assert "High-risk run: jwt@2.10.2" in sent
    # The deterministic structure is still present.
    assert ":test_tube:" in sent  # SAST section emoji
    assert ":bar_chart:" in sent  # severity totals
    # Intro is on the FIRST line, structure follows.
    assert sent.splitlines()[0].startswith(":speech_balloon:")


def test_digest_text_legacy_param_still_overrides(monkeypatch):
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    slack = SlackConfig(enabled=True, webhook_url_env="SLACK_WEBHOOK_URL")
    resp = MagicMock(status_code=200)
    with patch("secscan.notify.requests.post", return_value=resp) as mp:
        post_digest(slack, [_f("high")], SyncResult(), "o/n", "main", 9, digest_text="exact replacement")
    assert mp.call_args.kwargs["json"]["text"] == "exact replacement"


def test_failure_is_non_blocking(monkeypatch):
    import requests
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    slack = SlackConfig(enabled=True, webhook_url_env="SLACK_WEBHOOK_URL")
    with patch("secscan.notify.requests.post", side_effect=requests.ConnectionError("down")):
        ok = post_digest(slack, [], SyncResult(), "o/n", "main", 1)
    assert ok is False  # didn't raise
