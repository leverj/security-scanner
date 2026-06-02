"""Tests for the Gemma SAST runner. Ollama HTTP is mocked."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from security_scan.runners import gemma as gemma_runner


def _ollama_resp(payload: dict, status=200):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = {"message": {"content": json.dumps(payload)}}
    r.text = json.dumps(payload)
    return r


def _drop_source(repo: Path):
    """Drop a tiny set of source files for the runner to find."""
    (repo / "src").mkdir(parents=True, exist_ok=True)
    (repo / "src" / "auth.py").write_text("def login(req):\n    eval(req.body)\n")
    (repo / "src" / "db.js").write_text("db.query('SELECT * FROM t WHERE n = ' + n);\n")


def test_runner_empty_repo_returns_completed_with_no_findings(tmp_path):
    # No source files -> short-circuit success.
    result = gemma_runner.run(tmp_path)
    assert result.completed is True
    assert result.sarif["runs"][0]["results"] == []


def test_runner_happy_path(tmp_path):
    _drop_source(tmp_path)
    payload = {
        "findings": [
            {"file": "src/auth.py", "line": 2, "rule_id": "py.eval-user-input",
             "severity": "critical", "title": "eval on user input",
             "message": "eval() on request body enables RCE.",
             "snippet": "eval(req.body)"},
            {"file": "src/db.js", "line": 1, "rule_id": "js.sql-concat",
             "severity": "high", "title": "SQL injection via concatenation",
             "message": "Concatenating user input into SQL.", "snippet": "db.query('... ' + n)"},
        ]
    }
    with patch("security_scan.runners.gemma.requests.post", return_value=_ollama_resp(payload)) as p:
        result = gemma_runner.run(tmp_path)
    assert result.completed is True
    results = result.sarif["runs"][0]["results"]
    assert {r["ruleId"] for r in results} == {"gemma.py.eval-user-input", "gemma.js.sql-concat"}

    # Defensive: chat payload uses format=json and a model name.
    body = p.call_args.kwargs["json"]
    assert body["format"] == "json"
    assert body["stream"] is False
    assert "model" in body


def test_runner_unreachable_ollama(tmp_path):
    _drop_source(tmp_path)
    import requests
    with patch("security_scan.runners.gemma.requests.post",
               side_effect=requests.ConnectionError("ollama down")):
        result = gemma_runner.run(tmp_path)
    assert result.completed is False
    assert "ollama" in result.error.lower()


def test_runner_http_error(tmp_path):
    _drop_source(tmp_path)
    r = MagicMock()
    r.status_code = 500
    r.text = "server error"
    with patch("security_scan.runners.gemma.requests.post", return_value=r):
        result = gemma_runner.run(tmp_path)
    assert result.completed is False
    assert "500" in result.error


def test_runner_parse_error_on_malformed_content(tmp_path):
    _drop_source(tmp_path)
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"message": {"content": "not json at all"}}
    with patch("security_scan.runners.gemma.requests.post", return_value=r):
        result = gemma_runner.run(tmp_path)
    assert result.completed is False
    assert "parse" in result.error.lower()


def test_runner_namespaces_rule_id(tmp_path):
    _drop_source(tmp_path)
    payload = {"findings": [
        {"file": "x.py", "rule_id": "already.prefixed.gemma.x", "severity": "low",
         "title": "t", "message": "m"},
        {"file": "y.py", "rule_id": "raw-rule", "severity": "low", "title": "t", "message": "m"},
    ]}
    with patch("security_scan.runners.gemma.requests.post", return_value=_ollama_resp(payload)):
        result = gemma_runner.run(tmp_path)
    rule_ids = {r["ruleId"] for r in result.sarif["runs"][0]["results"]}
    assert "gemma.raw-rule" in rule_ids
    # `already.prefixed.gemma.x` doesn't START with "gemma." — it gets prefixed.
    assert "gemma.already.prefixed.gemma.x" in rule_ids


def test_runner_caps_file_count_and_total_bytes(tmp_path):
    """A repo with many large files must respect the caps — the prompt body
    must not balloon past max_total_bytes."""
    (tmp_path / "src").mkdir()
    for i in range(20):
        (tmp_path / "src" / f"f{i}.py").write_text("X" * 5000)

    captured = {}

    def _capture(*args, **kwargs):
        captured["body"] = kwargs["json"]
        return _ollama_resp({"findings": []})

    with patch("security_scan.runners.gemma.requests.post", side_effect=_capture):
        gemma_runner.run(tmp_path, max_files=3, max_file_bytes=1000, max_total_bytes=5000)

    user_msg = next(m["content"] for m in captured["body"]["messages"] if m["role"] == "user")
    # max 3 files batched. The explanatory header also says `===== FILE: <path> =====`
    # in backticks; count the file-delimiter lines at start-of-line only.
    import re
    file_headers = re.findall(r"^===== FILE: ", user_msg, flags=re.MULTILINE)
    assert len(file_headers) <= 3


def test_runner_skips_node_modules_and_friends(tmp_path):
    """Standard ALWAYS_SKIP dirs must not appear in the prompt regardless of
    user excludes — they're noise that destroys the prompt budget."""
    (tmp_path / "node_modules" / "left-pad").mkdir(parents=True)
    (tmp_path / "node_modules" / "left-pad" / "index.js").write_text("module.exports = (x) => x;")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "real.py").write_text("eval(x)")

    captured = {}

    def _capture(*args, **kwargs):
        captured["body"] = kwargs["json"]
        return _ollama_resp({"findings": []})

    with patch("security_scan.runners.gemma.requests.post", side_effect=_capture):
        gemma_runner.run(tmp_path)

    user_msg = next(m["content"] for m in captured["body"]["messages"] if m["role"] == "user")
    # Look for the FILE marker, not the bare string — pytest's tmpdir path
    # happens to contain "node_modules" in some test names.
    assert "FILE: node_modules" not in user_msg
    assert "left-pad/index.js" not in user_msg
    assert "src/real.py" in user_msg


def test_runner_drops_findings_without_file(tmp_path):
    _drop_source(tmp_path)
    payload = {"findings": [
        {"file": "", "rule_id": "no-path", "severity": "low", "title": "t", "message": "m"},
        {"file": "src/auth.py", "rule_id": "ok", "severity": "low", "title": "t", "message": "m"},
    ]}
    with patch("security_scan.runners.gemma.requests.post", return_value=_ollama_resp(payload)):
        result = gemma_runner.run(tmp_path)
    paths = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
             for r in result.sarif["runs"][0]["results"]]
    assert paths == ["src/auth.py"]


def test_runner_redacts_secrets_in_source_before_sending(tmp_path):
    """Source files containing AWS/GitHub tokens or high-entropy blobs must not
    leave the box verbatim — they're rewritten to <REDACTED:...> in the prompt
    body before it hits Ollama."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "creds.py").write_text(
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        "GH = 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n"
        "BLOB = 'f4Z7q2pHk8wT3sNcRy9LbVxJgQmDeAo5'\n"
    )
    captured = {}

    def _capture(*args, **kwargs):
        captured["body"] = kwargs["json"]
        return _ollama_resp({"findings": []})

    with patch("security_scan.runners.gemma.requests.post", side_effect=_capture):
        gemma_runner.run(tmp_path)

    user_msg = next(m["content"] for m in captured["body"]["messages"] if m["role"] == "user")
    assert "AKIAIOSFODNN7EXAMPLE" not in user_msg
    assert "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in user_msg
    assert "f4Z7q2pHk8wT3sNcRy9LbVxJgQmDeAo5" not in user_msg
    assert "<REDACTED:" in user_msg


def test_runner_refuses_non_local_base_url(tmp_path):
    """If base_url isn't loopback/private, the runner refuses to send source
    over the wire at all — no plaintext, no redacted-text, nothing."""
    (tmp_path / "x.py").write_text("eval(x)")
    with patch("security_scan.runners.gemma.requests.post") as p:
        result = gemma_runner.run(tmp_path, base_url="https://api.openai.com")
    assert result.completed is False
    assert "non-local" in result.error.lower() or "loopback" in result.error.lower()
    p.assert_not_called()


def test_runner_findings_not_a_list_is_failure(tmp_path):
    _drop_source(tmp_path)
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"message": {"content": json.dumps({"findings": "not a list"})}}
    with patch("security_scan.runners.gemma.requests.post", return_value=r):
        result = gemma_runner.run(tmp_path)
    assert result.completed is False
    assert "schema" in result.error.lower()
