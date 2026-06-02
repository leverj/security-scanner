"""Tests for the Codex SAST runner. All subprocess + filesystem effects mocked."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from security_scan.runners import codex as codex_runner


def _fake_completed(rc=0, stdout="", stderr=""):
    import subprocess
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


def _findings_payload(items):
    return json.dumps({"findings": items})


def test_runner_happy_path(tmp_path):
    """codex writes a JSON file with findings; runner returns parsed SARIF."""
    captured_cmd = {}

    def _fake_run(cmd, **kw):
        captured_cmd["cmd"] = cmd
        # Find -o <path> and write the result file.
        idx = cmd.index("-o")
        out_path = Path(cmd[idx + 1])
        out_path.write_text(_findings_payload([
            {
                "file": "src/auth.py", "line": 42,
                "rule_id": "auth.missing-csrf-check",
                "severity": "high",
                "title": "POST handler missing CSRF check",
                "message": "The /login endpoint accepts POST without verifying CSRF.",
                "snippet": "@app.post('/login')\ndef login(req): ...",
            },
        ]))
        return _fake_completed(0)

    with patch("security_scan.runners.codex.shutil.which", return_value="/usr/bin/codex"), \
         patch("security_scan.runners.codex.subprocess.run", side_effect=_fake_run):
        result = codex_runner.run(tmp_path)

    assert result.completed is True
    assert result.scanner == "codex"
    sarif = result.sarif
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "codex"
    results = run["results"]
    assert len(results) == 1
    r = results[0]
    assert r["ruleId"] == "codex.auth.missing-csrf-check"  # auto-namespaced
    assert r["level"] == "error"  # high -> error
    loc = r["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/auth.py"
    assert loc["region"]["startLine"] == 42

    # Defensive: invocation must include read-only sandbox and ephemeral.
    cmd = captured_cmd["cmd"]
    assert "-s" in cmd and "read-only" in cmd
    assert "--ephemeral" in cmd
    assert "--color" in cmd and "never" in cmd
    assert "--output-schema" in cmd
    assert "-o" in cmd


def test_runner_namespaces_rule_id_only_if_missing(tmp_path):
    def _fake_run(cmd, **kw):
        idx = cmd.index("-o")
        Path(cmd[idx + 1]).write_text(_findings_payload([
            {"file": "a.py", "rule_id": "codex.already-prefixed", "severity": "low",
             "title": "x", "message": "m"},
            {"file": "b.py", "rule_id": "needs-prefix", "severity": "medium",
             "title": "y", "message": "m"},
        ]))
        return _fake_completed(0)

    with patch("security_scan.runners.codex.shutil.which", return_value="/x/codex"), \
         patch("security_scan.runners.codex.subprocess.run", side_effect=_fake_run):
        result = codex_runner.run(tmp_path)
    rule_ids = [r["ruleId"] for r in result.sarif["runs"][0]["results"]]
    assert "codex.already-prefixed" in rule_ids
    assert "codex.needs-prefix" in rule_ids


def test_runner_handles_missing_binary(tmp_path):
    with patch("security_scan.runners.codex.shutil.which", return_value=None):
        result = codex_runner.run(tmp_path)
    assert result.completed is False
    assert "binary not found" in result.error


def test_runner_detects_auth_failure(tmp_path):
    """When codex isn't logged in it exits non-zero with an auth message — surface clearly."""
    with patch("security_scan.runners.codex.shutil.which", return_value="/x/codex"), \
         patch("security_scan.runners.codex.subprocess.run",
               return_value=_fake_completed(1, "", "Error: not logged in. Run `codex login`.")):
        result = codex_runner.run(tmp_path)
    assert result.completed is False
    assert "auth" in result.error.lower()
    assert "codex login" in result.error


def test_runner_returns_failure_on_non_zero_exit(tmp_path):
    with patch("security_scan.runners.codex.shutil.which", return_value="/x/codex"), \
         patch("security_scan.runners.codex.subprocess.run",
               return_value=_fake_completed(2, "", "internal model error")):
        result = codex_runner.run(tmp_path)
    assert result.completed is False
    assert "exit 2" in result.error


def test_runner_failure_when_no_output_file_written(tmp_path):
    """codex exited cleanly but produced no output — likely refused the task."""
    with patch("security_scan.runners.codex.shutil.which", return_value="/x/codex"), \
         patch("security_scan.runners.codex.subprocess.run", return_value=_fake_completed(0)):
        result = codex_runner.run(tmp_path)
    assert result.completed is False
    assert "no output" in result.error.lower()


def test_runner_failure_on_unparseable_output(tmp_path):
    def _fake_run(cmd, **kw):
        idx = cmd.index("-o")
        Path(cmd[idx + 1]).write_text("this is not json {{{ <-- broken")
        return _fake_completed(0)

    with patch("security_scan.runners.codex.shutil.which", return_value="/x/codex"), \
         patch("security_scan.runners.codex.subprocess.run", side_effect=_fake_run):
        result = codex_runner.run(tmp_path)
    assert result.completed is False
    assert "parse" in result.error.lower()


def test_runner_timeout(tmp_path):
    import subprocess
    with patch("security_scan.runners.codex.shutil.which", return_value="/x/codex"), \
         patch("security_scan.runners.codex.subprocess.run",
               side_effect=subprocess.TimeoutExpired(cmd="codex", timeout=10)):
        result = codex_runner.run(tmp_path, timeout=10)
    assert result.completed is False
    assert "timeout" in result.error.lower()


def test_runner_skips_findings_without_file(tmp_path):
    """A finding with no file path can't be fingerprinted — drop it cleanly."""
    def _fake_run(cmd, **kw):
        idx = cmd.index("-o")
        Path(cmd[idx + 1]).write_text(_findings_payload([
            {"file": "", "rule_id": "no-path", "severity": "low", "title": "t", "message": "m"},
            {"file": "real.py", "rule_id": "ok", "severity": "low", "title": "t", "message": "m"},
        ]))
        return _fake_completed(0)

    with patch("security_scan.runners.codex.shutil.which", return_value="/x/codex"), \
         patch("security_scan.runners.codex.subprocess.run", side_effect=_fake_run):
        result = codex_runner.run(tmp_path)
    paths = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
             for r in result.sarif["runs"][0]["results"]]
    assert paths == ["real.py"]


def test_runner_unknown_severity_defaults_to_medium(tmp_path):
    def _fake_run(cmd, **kw):
        idx = cmd.index("-o")
        Path(cmd[idx + 1]).write_text(_findings_payload([
            {"file": "a.py", "rule_id": "x", "severity": "catastrophic",  # not a valid level
             "title": "t", "message": "m"},
        ]))
        return _fake_completed(0)

    with patch("security_scan.runners.codex.shutil.which", return_value="/x/codex"), \
         patch("security_scan.runners.codex.subprocess.run", side_effect=_fake_run):
        result = codex_runner.run(tmp_path)
    r = result.sarif["runs"][0]["results"][0]
    assert r["properties"]["security-severity"] == "5.5"  # medium
    assert r["level"] == "warning"
