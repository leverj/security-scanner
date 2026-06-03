"""Mock-driven tests for the supply-chain (Socket.dev) runner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from security_scan.runners import supply_chain as runner


def _fake_completed(rc: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


SOCKET_SCAN_RESPONSE = {
    "id": "scan-abc",
    "scanVersion": "v1.0.55",
    "issues": [
        {
            "type": "typosquatRisk",
            "severity": "high",
            "pkg_name": "lodahs",
            "pkg_version": "1.0.0",
            "purl": "pkg:npm/lodahs@1.0.0",
            "manifestFiles": ["package-lock.json"],
            "description": "Package name 'lodahs' resembles popular 'lodash'.",
            "url": "https://socket.dev/npm/package/lodahs",
            "ecosystem": "npm",
        },
        {
            "type": "installScripts",
            "severity": "middle",
            "pkg_name": "shady-package",
            "pkg_version": "2.1.0",
            "purl": "pkg:npm/shady-package@2.1.0",
            "manifestFiles": ["package-lock.json"],
            "description": "Package runs install scripts (preinstall, postinstall).",
            "url": "https://socket.dev/npm/package/shady-package",
            "ecosystem": "npm",
        },
    ],
}


def _make_repo_with_lockfile(tmp_path: Path) -> Path:
    (tmp_path / "package-lock.json").write_text('{"name":"x","lockfileVersion":3}')
    return tmp_path


def test_no_lockfile_returns_completed_empty(tmp_path: Path):
    """Empty repo (no lockfile anywhere) must NOT invoke socket — Socket scans
    count against a SaaS quota, so we save the round-trip."""
    with patch("security_scan.runners.subprocess.run") as m:
        result = runner.run(tmp_path)
    assert result.completed is True
    assert result.scanner == "supply_chain"
    assert result.sarif is not None
    assert result.sarif["runs"][0]["results"] == []
    m.assert_not_called()


def test_missing_binary_returns_failure(tmp_path: Path, monkeypatch):
    _make_repo_with_lockfile(tmp_path)
    monkeypatch.setenv("SOCKET_API_KEY", "fake-token")
    with patch("security_scan.runners.supply_chain.shutil.which", return_value=None):
        result = runner.run(tmp_path)
    assert result.completed is False
    assert "binary not found" in result.error


def test_missing_api_key_returns_failure(tmp_path: Path, monkeypatch):
    _make_repo_with_lockfile(tmp_path)
    monkeypatch.delenv("SOCKET_API_KEY", raising=False)
    with patch("security_scan.runners.supply_chain.shutil.which", return_value="/usr/local/bin/socket"):
        result = runner.run(tmp_path)
    assert result.completed is False
    assert "SOCKET_API_KEY" in result.error


def test_happy_path_maps_issues_to_sarif(tmp_path: Path, monkeypatch):
    _make_repo_with_lockfile(tmp_path)
    monkeypatch.setenv("SOCKET_API_KEY", "fake-token")
    with patch("security_scan.runners.supply_chain.shutil.which", return_value="/usr/local/bin/socket"), \
         patch("security_scan.runners.subprocess.run",
               return_value=_fake_completed(0, json.dumps(SOCKET_SCAN_RESPONSE), "")):
        result = runner.run(tmp_path)

    assert result.completed is True
    assert result.scanner == "supply_chain"
    assert result.error is None

    results = result.sarif["runs"][0]["results"]
    assert len(results) == 2

    rule_ids = {r["ruleId"] for r in results}
    assert rule_ids == {"socket.typosquatRisk", "socket.installScripts"}

    by_rule = {r["ruleId"]: r for r in results}
    typo = by_rule["socket.typosquatRisk"]
    assert typo["properties"]["package"] == "lodahs"
    assert typo["properties"]["installed_version"] == "1.0.0"
    assert typo["properties"]["security-severity"] == "7.5"   # high
    assert typo["properties"]["ecosystem"] == "npm"
    assert typo["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "package-lock.json"

    install = by_rule["socket.installScripts"]
    # Socket emits "middle" — we map to "medium" (5.5).
    assert install["properties"]["security-severity"] == "5.5"


def test_issue_type_allowlist_filters(tmp_path: Path, monkeypatch):
    _make_repo_with_lockfile(tmp_path)
    monkeypatch.setenv("SOCKET_API_KEY", "fake-token")
    with patch("security_scan.runners.supply_chain.shutil.which", return_value="/usr/local/bin/socket"), \
         patch("security_scan.runners.subprocess.run",
               return_value=_fake_completed(0, json.dumps(SOCKET_SCAN_RESPONSE), "")):
        result = runner.run(tmp_path, issue_types=["typosquatRisk"])

    results = result.sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "socket.typosquatRisk"


def test_socket_nonzero_exit_returns_failure(tmp_path: Path, monkeypatch):
    _make_repo_with_lockfile(tmp_path)
    monkeypatch.setenv("SOCKET_API_KEY", "fake-token")
    with patch("security_scan.runners.supply_chain.shutil.which", return_value="/usr/local/bin/socket"), \
         patch("security_scan.runners.subprocess.run",
               return_value=_fake_completed(1, "", "auth error: token invalid")):
        result = runner.run(tmp_path)
    assert result.completed is False
    assert "exit 1" in result.error
    assert "auth error" in result.error


def test_unparseable_json_returns_failure(tmp_path: Path, monkeypatch):
    _make_repo_with_lockfile(tmp_path)
    monkeypatch.setenv("SOCKET_API_KEY", "fake-token")
    with patch("security_scan.runners.supply_chain.shutil.which", return_value="/usr/local/bin/socket"), \
         patch("security_scan.runners.subprocess.run",
               return_value=_fake_completed(0, "not json {", "")):
        result = runner.run(tmp_path)
    assert result.completed is False
    assert "parse error" in result.error


def test_camelcase_field_shape_is_tolerated(tmp_path: Path, monkeypatch):
    """Earlier socket CLI versions used camelCase (pkgName/pkgVersion).
    Newer versions use snake_case. The runner accepts both."""
    _make_repo_with_lockfile(tmp_path)
    monkeypatch.setenv("SOCKET_API_KEY", "fake-token")
    legacy = {
        "issues": [
            {
                "type": "malware",
                "severity": "critical",
                "pkgName": "evil-pkg",
                "pkgVersion": "0.0.1",
                "manifest_files": ["package-lock.json"],
                "description": "Known malicious package.",
                "ecosystem": "npm",
            },
        ],
    }
    with patch("security_scan.runners.supply_chain.shutil.which", return_value="/usr/local/bin/socket"), \
         patch("security_scan.runners.subprocess.run",
               return_value=_fake_completed(0, json.dumps(legacy), "")):
        result = runner.run(tmp_path)
    assert result.completed is True
    [r] = result.sarif["runs"][0]["results"]
    assert r["ruleId"] == "socket.malware"
    assert r["properties"]["package"] == "evil-pkg"
    assert r["properties"]["security-severity"] == "9.5"  # critical
