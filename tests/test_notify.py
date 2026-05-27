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
    assert "created: 2" in text
    assert "dup-skipped: 1" in text


def test_failure_is_non_blocking(monkeypatch):
    import requests
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.slack.test/x")
    slack = SlackConfig(enabled=True, webhook_url_env="SLACK_WEBHOOK_URL")
    with patch("secscan.notify.requests.post", side_effect=requests.ConnectionError("down")):
        ok = post_digest(slack, [], SyncResult(), "o/n", "main", 1)
    assert ok is False  # didn't raise
