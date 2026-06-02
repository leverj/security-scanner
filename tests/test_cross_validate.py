"""Tests for the cross-validation step.

Both `_gemma_verdict` (HTTP via Ollama) and `_codex_verdict` (subprocess) are
mocked. We verify the verdict→severity mapping, the never-suppress invariant,
and what happens when a validator is unreachable.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from security_scan.cross_validate import cross_validate
from security_scan.models import Finding


def _f(scanner, rule_id, severity="high"):
    return Finding(
        scanner=scanner,
        category="sast",
        rule_id=rule_id,
        severity=severity,
        file_path="src/a.py",
        line=10,
        title=f"{rule_id}",
        message="msg",
        extra={"snippet": "code"},
    )


def _ollama_ok(payload):
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"message": {"content": json.dumps(payload)}}
    r.raise_for_status.return_value = None
    return r


def _codex_completed(rc=0, schema_response=None):
    """Build a subprocess.run side_effect that writes `schema_response` to -o."""
    import subprocess

    def _side(cmd, **kw):
        idx = cmd.index("-o")
        out = Path(cmd[idx + 1])
        out.write_text(json.dumps(schema_response or {}))
        return subprocess.CompletedProcess(args=cmd, returncode=rc, stdout="", stderr="")
    return _side


def _ping_ok():
    r = MagicMock()
    r.status_code = 200
    return r


def test_disabled_when_only_one_scanner_enabled(tmp_path):
    findings = [_f("codex", "x"), _f("gemma", "y")]
    out = cross_validate(findings, repo_dir=tmp_path,
                         codex_enabled=True, gemma_enabled=False)
    assert out is findings
    # No cross-validation extras attached.
    assert all("cross_validation" not in (f.extra or {}) for f in findings)


def test_gemma_marks_codex_finding_real_keeps_severity(tmp_path):
    f = _f("codex", "auth.foo", severity="high")
    with patch("security_scan.cross_validate.shutil.which", return_value="/x/codex"), \
         patch("security_scan.cross_validate.requests.get", return_value=_ping_ok()), \
         patch("security_scan.cross_validate.requests.post",
               return_value=_ollama_ok({"verdict": "real", "reason": "definitely real"})):
        cross_validate([f], repo_dir=tmp_path, codex_enabled=True, gemma_enabled=True)
    cv = f.extra["cross_validation"]
    assert cv["validator"] == "gemma"
    assert cv["verdict"] == "real"
    assert "definitely real" in cv["reason"]
    assert f.severity == "high"  # unchanged
    assert cv["original_severity"] == "high"


def test_gemma_marks_codex_finding_false_positive_downgrades(tmp_path):
    f = _f("codex", "auth.foo", severity="high")
    with patch("security_scan.cross_validate.shutil.which", return_value="/x/codex"), \
         patch("security_scan.cross_validate.requests.get", return_value=_ping_ok()), \
         patch("security_scan.cross_validate.requests.post",
               return_value=_ollama_ok({"verdict": "false_positive", "reason": "not exploitable"})):
        cross_validate([f], repo_dir=tmp_path, codex_enabled=True, gemma_enabled=True)
    cv = f.extra["cross_validation"]
    assert cv["verdict"] == "false_positive"
    assert cv["original_severity"] == "high"
    assert f.severity == "medium"  # high -> medium


def test_critical_never_auto_downgrades_on_fp(tmp_path):
    """Asymmetric guardrail: critical findings stay critical even if the
    validator disagrees. The cost of missing a real critical is too high."""
    f = _f("codex", "rce.eval", severity="critical")
    with patch("security_scan.cross_validate.shutil.which", return_value="/x/codex"), \
         patch("security_scan.cross_validate.requests.get", return_value=_ping_ok()), \
         patch("security_scan.cross_validate.requests.post",
               return_value=_ollama_ok({"verdict": "false_positive", "reason": "looks fine"})):
        cross_validate([f], repo_dir=tmp_path, codex_enabled=True, gemma_enabled=True)
    assert f.severity == "critical"  # protected
    assert f.extra["cross_validation"]["verdict"] == "false_positive"
    assert f.extra["cross_validation"]["original_severity"] == "critical"


def test_uncertain_does_not_downgrade(tmp_path):
    f = _f("codex", "auth.foo", severity="high")
    with patch("security_scan.cross_validate.shutil.which", return_value="/x/codex"), \
         patch("security_scan.cross_validate.requests.get", return_value=_ping_ok()), \
         patch("security_scan.cross_validate.requests.post",
               return_value=_ollama_ok({"verdict": "uncertain", "reason": "can't tell"})):
        cross_validate([f], repo_dir=tmp_path, codex_enabled=True, gemma_enabled=True)
    assert f.severity == "high"
    assert f.extra["cross_validation"]["verdict"] == "uncertain"


def test_unrecognized_verdict_treated_as_uncertain(tmp_path):
    f = _f("codex", "x", severity="medium")
    with patch("security_scan.cross_validate.shutil.which", return_value="/x/codex"), \
         patch("security_scan.cross_validate.requests.get", return_value=_ping_ok()), \
         patch("security_scan.cross_validate.requests.post",
               return_value=_ollama_ok({"verdict": "OBVIOUSLY_FAKE", "reason": "what"})):
        cross_validate([f], repo_dir=tmp_path, codex_enabled=True, gemma_enabled=True)
    assert f.severity == "medium"
    assert f.extra["cross_validation"]["verdict"] == "uncertain"


def test_codex_marks_gemma_finding_false_positive_downgrades(tmp_path):
    f = _f("gemma", "py.eval", severity="high")
    with patch("security_scan.cross_validate.shutil.which", return_value="/x/codex"), \
         patch("security_scan.cross_validate.requests.get", return_value=_ping_ok()), \
         patch("security_scan.cross_validate.subprocess.run",
               side_effect=_codex_completed(0, {"verdict": "false_positive",
                                                "reason": "test code, not prod"})):
        cross_validate([f], repo_dir=tmp_path, codex_enabled=True, gemma_enabled=True)
    cv = f.extra["cross_validation"]
    assert cv["validator"] == "codex"
    assert cv["verdict"] == "false_positive"
    assert f.severity == "medium"


def test_ollama_unreachable_skips_gemma_review(tmp_path):
    """If Ollama can't be reached, codex findings simply get no review — not failure."""
    import requests
    f = _f("codex", "x", severity="high")
    with patch("security_scan.cross_validate.shutil.which", return_value="/x/codex"), \
         patch("security_scan.cross_validate.requests.get",
               side_effect=requests.ConnectionError("down")):
        cross_validate([f], repo_dir=tmp_path, codex_enabled=True, gemma_enabled=True)
    assert "cross_validation" not in (f.extra or {})
    assert f.severity == "high"


def test_codex_missing_skips_codex_review_of_gemma_findings(tmp_path):
    f = _f("gemma", "x", severity="high")
    with patch("security_scan.cross_validate.shutil.which", return_value=None), \
         patch("security_scan.cross_validate.requests.get", return_value=_ping_ok()):
        cross_validate([f], repo_dir=tmp_path, codex_enabled=True, gemma_enabled=True)
    # Gemma finding not reviewed because codex CLI is missing.
    assert "cross_validation" not in (f.extra or {})


def test_validator_failure_yields_uncertain(tmp_path):
    """Network/subprocess failures during validation produce an 'uncertain'
    verdict — never block the finding or crash the run."""
    f = _f("codex", "x", severity="high")
    import requests
    with patch("security_scan.cross_validate.shutil.which", return_value="/x/codex"), \
         patch("security_scan.cross_validate.requests.get", return_value=_ping_ok()), \
         patch("security_scan.cross_validate.requests.post",
               side_effect=requests.ConnectionError("post failed")):
        cross_validate([f], repo_dir=tmp_path, codex_enabled=True, gemma_enabled=True)
    cv = f.extra["cross_validation"]
    assert cv["verdict"] == "uncertain"
    assert f.severity == "high"
