"""Tests for the Trivy / Trufflehog / Syft additions."""

import json
from pathlib import Path
from unittest.mock import patch

from secscan.normalize import normalize_sarif
from secscan.runners import syft as syft_runner
from secscan.runners import trivy as trivy_runner
from secscan.runners import trufflehog as trufflehog_runner

FIXTURES = Path(__file__).parent / "fixtures"


def _completed(rc=0, stdout="", stderr=""):
    from unittest.mock import MagicMock
    p = MagicMock()
    p.returncode = rc
    p.stdout = stdout
    p.stderr = stderr
    return p


# ---- Trivy ----------------------------------------------------------------


def test_trivy_runner_happy_path(tmp_path):
    sarif = (FIXTURES / "sarif" / "trivy.json").read_text()
    with patch("secscan.runners.subprocess.run", return_value=_completed(0, sarif, "")):
        result = trivy_runner.run(tmp_path)
    assert result.completed and result.sarif is not None
    assert result.scanner == "trivy"


def test_trivy_cmd_includes_all_scanners(tmp_path):
    with patch("secscan.runners.subprocess.run", return_value=_completed(0, "{}", "")) as m:
        trivy_runner.run(tmp_path, exclude=["vendor/"])
    cmd = m.call_args.args[0]
    # Joined --scanners value
    joined = " ".join(cmd)
    assert "fs" in cmd
    assert "--format" in cmd and "sarif" in cmd
    assert "vuln" in joined and "secret" in joined and "misconfig" in joined and "license" in joined
    assert "--skip-dirs" in cmd
    assert "vendor" in cmd  # trailing slash stripped


def test_trivy_findings_get_correct_categories(tmp_path):
    sarif = json.loads((FIXTURES / "sarif" / "trivy.json").read_text())
    findings = normalize_sarif(sarif, "trivy")
    by_rule = {f.rule_id: f for f in findings}
    assert by_rule["CVE-2024-99991"].category == "dependency"
    assert by_rule["AVD-DS-0002"].category == "iac"
    assert by_rule["trivy.secret.aws-access-key"].category == "secret"
    assert by_rule["trivy.license.gpl"].category == "license"


def test_trivy_severity_normalization(tmp_path):
    sarif = json.loads((FIXTURES / "sarif" / "trivy.json").read_text())
    findings = normalize_sarif(sarif, "trivy")
    by_rule = {f.rule_id: f for f in findings}
    # CVE-2024-99991 has security-severity 9.8 -> critical
    assert by_rule["CVE-2024-99991"].severity == "critical"
    # AVD-DS-0002 = 6.5 -> medium
    assert by_rule["AVD-DS-0002"].severity == "medium"


def test_trivy_exclude_filter(tmp_path):
    sarif = json.loads((FIXTURES / "sarif" / "trivy.json").read_text())
    findings = normalize_sarif(sarif, "trivy", exclude=["vendor/"])
    rule_ids = {f.rule_id for f in findings}
    assert "trivy.license.gpl" not in rule_ids  # was in vendor/


def test_trivy_binary_not_found(tmp_path):
    with patch("secscan.runners.subprocess.run", side_effect=FileNotFoundError("trivy")):
        result = trivy_runner.run(tmp_path)
    assert not result.completed
    assert "binary not found" in (result.error or "")


# ---- Trufflehog -----------------------------------------------------------


def test_trufflehog_runner_wraps_jsonl(tmp_path):
    jsonl = (FIXTURES / "trufflehog.jsonl").read_text()
    with patch("secscan.runners.subprocess.run", return_value=_completed(0, jsonl, "")):
        result = trufflehog_runner.run(tmp_path)
    assert result.completed
    assert isinstance(result.sarif, dict)
    assert result.sarif.get("_trufflehog_jsonl") == jsonl


def test_trufflehog_normalize_categories_and_verification(tmp_path):
    jsonl = (FIXTURES / "trufflehog.jsonl").read_text()
    findings = normalize_sarif({"_trufflehog_jsonl": jsonl}, "trufflehog")
    # 3 findings: 1 verified (GitHub PAT), 2 unverified (AWS + Slack)
    assert len(findings) == 3
    by_detector = {f.extra["detector"]: f for f in findings}
    assert by_detector["GitHub"].category == "secret-verified"
    assert by_detector["GitHub"].severity == "critical"
    assert by_detector["AWS"].category == "secret"
    assert by_detector["AWS"].severity == "high"


def test_trufflehog_never_exposes_raw_value(tmp_path):
    jsonl = (FIXTURES / "trufflehog.jsonl").read_text()
    findings = normalize_sarif({"_trufflehog_jsonl": jsonl}, "trufflehog")
    raw_strings = [
        "ghp_FAKE_PLACEHOLDER_FOR_TEST_FIXTURE_VALUE",
        "AKIA_TEST_PLACEHOLDER_VALUE",
        "xoxb-fake-test-value",
    ]
    for f in findings:
        for raw in raw_strings:
            assert raw not in (f.masked_preview or "")
            assert raw not in (f.title or "")
            assert raw not in (f.message or "")


def test_trufflehog_exclude_filter(tmp_path):
    jsonl = (FIXTURES / "trufflehog.jsonl").read_text()
    findings = normalize_sarif({"_trufflehog_jsonl": jsonl}, "trufflehog", exclude=["archive/"])
    # Slack one was in archive/legacy.js -> dropped
    detectors = {f.extra["detector"] for f in findings}
    assert "Slack" not in detectors


def test_trufflehog_skips_unparseable_lines(tmp_path, capsys):
    jsonl = '{"valid": "json but no detector"}\nnot-json-at-all\n'
    findings = normalize_sarif({"_trufflehog_jsonl": jsonl}, "trufflehog")
    # The valid-shape line has no path -> dropped; the broken line is also dropped
    assert findings == []


def test_trufflehog_exit_code_nonzero_is_failure(tmp_path):
    with patch("secscan.runners.subprocess.run", return_value=_completed(2, "", "config error")):
        result = trufflehog_runner.run(tmp_path)
    assert not result.completed
    assert "exit 2" in (result.error or "")


# ---- Syft -----------------------------------------------------------------


def test_syft_runner_writes_sbom(tmp_path):
    sbom_path = tmp_path / "out" / "sbom.cyclonedx.json"

    def fake_run(cmd, **kw):
        # The runner instructs syft -o cyclonedx-json=<path>; emulate it writing the file.
        from unittest.mock import MagicMock
        sbom_path.parent.mkdir(parents=True, exist_ok=True)
        sbom_path.write_text(json.dumps({"components": [{"name": "a"}, {"name": "b"}]}))
        p = MagicMock()
        p.returncode = 0
        p.stdout = ""
        p.stderr = ""
        return p

    with patch("secscan.runners.subprocess.run", side_effect=fake_run):
        result = syft_runner.run(tmp_path, output_path=sbom_path)
    assert result.completed
    meta = result.sarif["_syft_sbom"]
    assert meta["path"] == str(sbom_path)
    assert meta["format"] == "cyclonedx-json"
    assert meta["components"] == 2


def test_syft_runner_failure_missing_output(tmp_path):
    sbom_path = tmp_path / "should-not-exist.json"
    with patch("secscan.runners.subprocess.run", return_value=_completed(0, "", "")):
        result = syft_runner.run(tmp_path, output_path=sbom_path)
    assert not result.completed


def test_syft_binary_not_found(tmp_path):
    with patch("secscan.runners.subprocess.run", side_effect=FileNotFoundError("syft")):
        result = syft_runner.run(tmp_path, output_path=tmp_path / "x.json")
    assert not result.completed
    assert "binary not found" in (result.error or "")
