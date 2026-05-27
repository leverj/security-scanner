import json
from pathlib import Path

import pytest

from secscan.fingerprint import resolve_fingerprint
from secscan.normalize import normalize_sarif

FIXTURES = Path(__file__).parent / "fixtures" / "sarif"

# Raw secret strings present in the gitleaks fixture; masked_preview must never contain these.
GITLEAKS_RAW_SECRETS = [
    "sk_live_FAKE_9f8e7d6c5b4a3210ZZZZ",
    "TEST_FAKE_AWS_KEY_PLACEHOLDER",
]


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text())


# --- osv ---------------------------------------------------------------------

def test_osv_basic_shape():
    findings = normalize_sarif(_load("osv.json"), "osv")
    assert len(findings) == 2
    assert {f.category for f in findings} == {"dependency"}
    assert {f.scanner for f in findings} == {"osv"}
    paths = {f.file_path for f in findings}
    assert paths == {"package-lock.json", "frontend/package-lock.json"}


def test_osv_severity_from_rule_cvss():
    findings = normalize_sarif(_load("osv.json"), "osv")
    by_rule = {f.rule_id: f for f in findings}
    # 9.8 -> critical (per normalize_severity)
    assert by_rule["GHSA-aaaa-aaaa-aaaa"].severity == "critical"
    # 5.3 -> medium
    assert by_rule["GHSA-bbbb-bbbb-bbbb"].severity == "medium"


def test_osv_extras_carry_ecosystem_package_version():
    findings = normalize_sarif(_load("osv.json"), "osv")
    by_rule = {f.rule_id: f for f in findings}
    lodash = by_rule["GHSA-aaaa-aaaa-aaaa"].extra
    assert lodash["ecosystem"] == "npm"
    assert lodash["package"] == "lodash"
    assert lodash["installed_version"] == "4.17.15"
    assert lodash["fixed_versions"] == ["4.17.21"]
    assert "CVE-2021-23337" in lodash["aliases"]


def test_osv_fingerprint_roundtrips():
    findings = normalize_sarif(_load("osv.json"), "osv")
    fps = {resolve_fingerprint(f) for f in findings}
    assert len(fps) == 2
    for fp in fps:
        assert fp.startswith("fp_") and len(fp) == 19


# --- gitleaks ----------------------------------------------------------------

def test_gitleaks_basic_shape():
    findings = normalize_sarif(_load("gitleaks.json"), "gitleaks")
    assert len(findings) == 2
    assert {f.category for f in findings} == {"secret"}
    assert {f.rule_id for f in findings} == {"generic-api-key", "aws-access-token"}


def test_gitleaks_masked_preview_never_contains_raw_secret():
    findings = normalize_sarif(_load("gitleaks.json"), "gitleaks")
    for f in findings:
        for raw in GITLEAKS_RAW_SECRETS:
            assert raw not in f.masked_preview, f"raw secret leaked in {f.rule_id}"
        # And the message/title/extras shouldn't carry it either.
        for raw in GITLEAKS_RAW_SECRETS:
            assert raw not in (f.extra.get("secret_fingerprint") or "")


def test_gitleaks_masked_preview_format():
    findings = normalize_sarif(_load("gitleaks.json"), "gitleaks")
    by_rule = {f.rule_id: f for f in findings}
    aws = by_rule["aws-access-token"].masked_preview
    # "TEST_FAKE_AWS_KEY_PLACEHOLDER" (29 chars) -> "TE" + 23 bullets + "LDER"
    assert aws.startswith("TE")
    assert aws.endswith("LDER")
    assert "•" in aws
    # No raw middle leaked
    assert "FAKE_AWS" not in aws


def test_gitleaks_secret_fingerprint_in_extra():
    findings = normalize_sarif(_load("gitleaks.json"), "gitleaks")
    for f in findings:
        assert f.extra.get("secret_fingerprint"), f"missing secret_fingerprint for {f.rule_id}"


def test_gitleaks_fingerprint_roundtrips():
    findings = normalize_sarif(_load("gitleaks.json"), "gitleaks")
    fps = {resolve_fingerprint(f) for f in findings}
    assert len(fps) == 2
    for fp in fps:
        assert fp.startswith("fp_") and len(fp) == 19


# --- semgrep -----------------------------------------------------------------

def test_semgrep_basic_shape():
    findings = normalize_sarif(_load("semgrep.json"), "semgrep")
    # 3 results in fixture (one of which is the legacy.js result for the exclude test)
    assert len(findings) == 3
    assert {f.category for f in findings} == {"sast"}


def test_semgrep_snippet_in_extra():
    findings = normalize_sarif(_load("semgrep.json"), "semgrep")
    for f in findings:
        assert f.extra.get("snippet"), f"missing snippet for {f.rule_id}"


def test_semgrep_severity_from_security_severity():
    findings = normalize_sarif(_load("semgrep.json"), "semgrep")
    by_path = {f.file_path: f for f in findings}
    # 8.5 -> high
    assert by_path["src/api/handler.js"].severity == "high"
    # 4.5 -> medium
    assert by_path["src/utils/cmd.js"].severity == "medium"


def test_semgrep_fingerprint_roundtrips():
    findings = normalize_sarif(_load("semgrep.json"), "semgrep")
    fps = {resolve_fingerprint(f) for f in findings}
    assert len(fps) == 3
    for fp in fps:
        assert fp.startswith("fp_") and len(fp) == 19


# --- exclude filtering -------------------------------------------------------

def test_exclude_prefix_drops_archive():
    findings = normalize_sarif(_load("semgrep.json"), "semgrep", exclude=["archive/"])
    paths = {f.file_path for f in findings}
    assert "archive/legacy.js" not in paths
    assert len(findings) == 2


def test_exclude_glob_drops_specific_file():
    findings = normalize_sarif(_load("semgrep.json"), "semgrep", exclude=["**/handler.js"])
    paths = {f.file_path for f in findings}
    assert "src/api/handler.js" not in paths
    # the other two survive
    assert {"src/utils/cmd.js", "archive/legacy.js"} <= paths


def test_exclude_none_keeps_all():
    findings = normalize_sarif(_load("semgrep.json"), "semgrep", exclude=None)
    assert len(findings) == 3


# --- missing-location handling ----------------------------------------------

def test_result_without_location_is_skipped(capsys):
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "rules": []}},
                "results": [
                    {
                        "ruleId": "no-loc-rule",
                        "level": "warning",
                        "message": {"text": "result without any location"},
                    }
                ],
            }
        ],
    }
    findings = normalize_sarif(sarif, "semgrep")
    assert findings == []
    err = capsys.readouterr().err
    assert "no location" in err
    assert "no-loc-rule" in err


# --- unknown scanner ---------------------------------------------------------

def test_unknown_scanner_raises():
    with pytest.raises(ValueError):
        normalize_sarif({"runs": []}, "totally-made-up-scanner")
