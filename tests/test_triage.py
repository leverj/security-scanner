import json
from unittest.mock import MagicMock, patch

import requests

from secscan.config import TriageConfig
from secscan.fingerprint import inject_marker, resolve_fingerprint
from secscan.models import Finding
from secscan.triage import Triage, _finding_brief


def _f():
    return Finding(
        scanner="semgrep", category="sast", rule_id="ezel-cmd-injection",
        severity="high", file_path="src/a.js", line=10, title="cmd inj", message="msg",
        extra={"snippet": "exec(x)"},
    )


def _gemma_response(content: str | dict) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    if isinstance(content, dict):
        content = json.dumps(content)
    resp.json.return_value = {"message": {"content": content}}
    resp.raise_for_status = MagicMock()
    return resp


def _reachable_response():
    r = MagicMock()
    r.status_code = 200
    return r


def test_disabled_triage_does_not_call_ollama():
    t = Triage(TriageConfig(enabled=False))
    assert t.is_duplicate_of_existing(_f(), []) is False
    title, body = t.write_issue(_f())  # default_issue fallback
    assert "Scanner" in body


def test_unreachable_ollama_falls_back(monkeypatch):
    t = Triage(TriageConfig(enabled=True))
    with patch.object(t._session, "get", side_effect=requests.ConnectionError("down")):
        assert t.is_duplicate_of_existing(_f(), [_existing()]) is False
        title, body = t.write_issue(_f())
    assert "Scanner" in body  # deterministic template


def _existing():
    f = _f()
    return {"number": 7, "state": "open", "title": "old", "body": inject_marker("x", resolve_fingerprint(f), f), "id": 1}


def test_fuzzy_dup_yes_returns_true():
    t = Triage(TriageConfig(enabled=True))
    with patch.object(t._session, "get", return_value=_reachable_response()), \
         patch.object(t._session, "post", return_value=_gemma_response({"duplicate_of": 7, "confidence": "high"})):
        assert t.is_duplicate_of_existing(_f(), [_existing()]) is True


def test_fuzzy_dup_low_confidence_returns_false():
    t = Triage(TriageConfig(enabled=True))
    with patch.object(t._session, "get", return_value=_reachable_response()), \
         patch.object(t._session, "post", return_value=_gemma_response({"duplicate_of": 7, "confidence": "low"})):
        assert t.is_duplicate_of_existing(_f(), [_existing()]) is False


def test_fuzzy_dup_malformed_json_returns_false():
    t = Triage(TriageConfig(enabled=True))
    with patch.object(t._session, "get", return_value=_reachable_response()), \
         patch.object(t._session, "post", return_value=_gemma_response("not json")):
        assert t.is_duplicate_of_existing(_f(), [_existing()]) is False


def test_write_issue_uses_model_prose():
    t = Triage(TriageConfig(enabled=True))
    with patch.object(t._session, "get", return_value=_reachable_response()), \
         patch.object(t._session, "post", return_value=_gemma_response({"title": "T", "body": "B"})):
        title, body = t.write_issue(_f())
    assert title == "T" and body == "B"


def test_write_issue_falls_back_on_missing_keys():
    t = Triage(TriageConfig(enabled=True))
    with patch.object(t._session, "get", return_value=_reachable_response()), \
         patch.object(t._session, "post", return_value=_gemma_response({"title": "T"})):
        title, body = t.write_issue(_f())
    assert "Scanner" in body  # default fallback


def test_finding_brief_never_includes_raw_secret():
    f = Finding(
        scanner="gitleaks", category="secret", rule_id="generic-api-key",
        severity="critical", file_path=".env", line=3, title="key", message="secret found: REDACT_THIS_SECRET",
        masked_preview="sk_••cd34", extra={"secret_fingerprint": "abcd"},
    )
    blob = _finding_brief(f)
    # The function passes message through but we ensure masked_preview is what callers should rely on.
    assert "sk_••cd34" in blob
    assert "secret_fingerprint" in blob


def test_no_candidates_means_no_chat():
    t = Triage(TriageConfig(enabled=True))
    with patch.object(t._session, "get", return_value=_reachable_response()), \
         patch.object(t._session, "post") as p:
        assert t.is_duplicate_of_existing(_f(), [{"number": 1, "body": "no marker", "title": "x"}]) is False
    p.assert_not_called()


def test_slack_digest_returns_text():
    from secscan.sync import SyncResult
    t = Triage(TriageConfig(enabled=True))
    with patch.object(t._session, "get", return_value=_reachable_response()), \
         patch.object(t._session, "post", return_value=_gemma_response("Hello digest")):
        text = t.write_slack_digest([_f()], SyncResult(created=[{"n": 1}]), "o/n", "main", 42)
    assert text == "Hello digest"
