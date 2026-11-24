"""Slack digest flags a run in which no enabled check completed (exit 3).

Slack is mocked at `_post_webhook`; nothing is sent. Each case runs the real
pipeline (`cli`) with only GitHub and the scanner runners mocked.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from security_scan.github import GitHubError
from security_scan.main import _no_scan_alert, cli
from security_scan.runners import RunnerResult

from .test_main import _fresh_gh, _scanner_results

EMPTY = {"runs": [{"tool": {"driver": {"name": "x", "rules": []}}, "results": []}]}


def _config(tmp_path, scanners: dict, image=False):
    lines = ["repo: owner/name", "ref: main", "project: {owner: owner, number: 5}",
             "slack: {enabled: true, webhook_url_env: SLACK_TEST_WEBHOOK}",
             f"image_scan: {{base_images: {str(image).lower()}}}", "scanners:"]
    for name in ("osv", "gitleaks", "semgrep", "trivy", "trufflehog", "syft", "supply_chain"):
        lines.append(f"  {name}: {str(scanners.get(name, False)).lower()}")
    p = tmp_path / "config.yaml"
    p.write_text("\n".join(lines) + "\n")
    return p


def _run(tmp_path, monkeypatch, config, files, results=None, gh=None):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake")
    monkeypatch.setenv("SLACK_TEST_WEBHOOK", "https://hooks.example.invalid/test")
    gh = gh or _fresh_gh()

    def clone(ref, dest, shallow=True):
        for rel, text in files.items():
            (Path(dest) / rel).parent.mkdir(parents=True, exist_ok=True)
            (Path(dest) / rel).write_text(text)
    gh.clone.side_effect = clone
    results = results or {}
    posted = []
    patches = [patch("security_scan.main.GitHub", return_value=gh),
               patch("security_scan.notify._post_webhook", side_effect=lambda url, text: posted.append(text) or True)]
    for name in ("osv", "gitleaks", "semgrep", "trivy", "trufflehog", "syft"):
        patches.append(patch(f"security_scan.runners.{name}.run",
                             return_value=results.get(name, RunnerResult(name, EMPTY, True))))
    for p in patches:
        p.start()
    try:
        rc = cli(["--config", str(config), "--work-dir", str(tmp_path / "work")])
    finally:
        for p in reversed(patches):
            p.stop()
    return rc, posted


SRC = {"README.md": "x\n", "app.py": "print(1)\n", "package.json": "{}", "package-lock.json": "{}"}


def test_all_enabled_checks_skipped_is_critical_no_scans_ran(tmp_path, monkeypatch):
    # osv + semgrep enabled, but the tree has no lockfile and no source file.
    rc, posted = _run(tmp_path, monkeypatch, _config(tmp_path, {"osv": True, "semgrep": True}),
                      {"README.md": "docs only\n"})
    assert rc == 3
    [text] = posted
    assert ":rotating_light: *CRITICAL — no scans ran*: every enabled check was skipped: " \
           "no eligible input found for osv, semgrep" in text
    assert "_no findings reported — no check completed_" in text
    assert "_no findings_" not in text.splitlines()
    assert ":card_index_dividers: filed 0 · dup-skipped 0 · below-floor 0" in text


def test_attempted_but_none_completed_is_critical_with_reasons(tmp_path, monkeypatch):
    results = {
        "gitleaks": RunnerResult("gitleaks", None, False, "exit 2: boom"),
        "trivy": RunnerResult("trivy", None, False,
                              "fetch https://user:s3cret@mirror.example.invalid/db failed; token ghp_ABCDEF1234567890"),
    }
    rc, posted = _run(tmp_path, monkeypatch,
                      _config(tmp_path, {"gitleaks": True, "trivy": True, "osv": True}), {"README.md": "x\n"},
                      results)
    assert rc == 3
    [text] = posted
    assert ":rotating_light: *CRITICAL — no scans completed*: 2 check(s) attempted, none completed — " in text
    assert "gitleaks: exit 2: boom" in text
    assert "https://***@mirror.example.invalid/db" in text and "s3cret" not in text
    assert "ghp_ABCDEF" not in text and "token ***" in text
    assert "skipped (no eligible input): osv" in text


def test_successful_scan_with_zero_findings_is_an_ordinary_report(tmp_path, monkeypatch):
    rc, posted = _run(tmp_path, monkeypatch, _config(tmp_path, {"gitleaks": True, "trivy": True}), SRC)
    assert rc == 0
    [text] = posted
    assert "CRITICAL" not in text
    assert "_no findings_" in text


def test_all_lanes_disabled_keeps_current_policy(tmp_path, monkeypatch):
    rc, posted = _run(tmp_path, monkeypatch, _config(tmp_path, {}), SRC)
    assert rc == 0
    [text] = posted
    assert "CRITICAL" not in text


def test_partial_failure_is_not_critical(tmp_path, monkeypatch):
    results = {"gitleaks": RunnerResult("gitleaks", None, False, "exit 2: boom")}
    rc, posted = _run(tmp_path, monkeypatch, _config(tmp_path, {"gitleaks": True, "trivy": True}), SRC, results)
    assert rc == 0
    [text] = posted
    assert "CRITICAL" not in text


def test_findings_report_counts_unchanged(tmp_path, monkeypatch):
    rc, posted = _run(tmp_path, monkeypatch, _config(tmp_path, {"osv": True, "gitleaks": True, "semgrep": True}),
                      SRC, _scanner_results())
    assert rc == 0
    [text] = posted
    assert "CRITICAL" not in text
    assert ":card_index_dividers: filed 3 · dup-skipped 0 · below-floor 0" in text


def test_github_failure_still_exits_4_without_a_digest(tmp_path, monkeypatch):
    gh = _fresh_gh()
    gh.resolve_project.side_effect = GitHubError(401, "Bad credentials")
    rc, posted = _run(tmp_path, monkeypatch, _config(tmp_path, {"gitleaks": True}), SRC, gh=gh)
    assert rc == 4
    assert posted == []


def test_image_lane_counts_as_enabled(tmp_path, monkeypatch):
    # Only the base-image lane is on and the tree has no Dockerfile: nothing ran.
    rc, posted = _run(tmp_path, monkeypatch, _config(tmp_path, {}, image=True), {"README.md": "x\n"})
    assert rc == 3
    assert "no eligible input found for image" in posted[0]


def test_image_failure_is_attempted_not_skipped(tmp_path, monkeypatch):
    fail = [RunnerResult("image", None, False, "pull denied")]
    with patch("security_scan.runners.image.run", return_value=fail):
        rc, posted = _run(tmp_path, monkeypatch, _config(tmp_path, {}, image=True),
                          {"Dockerfile": "FROM python:3.12\n"})
    assert rc == 3
    assert "*CRITICAL — no scans completed*: 1 check(s) attempted" in posted[0]
    assert "image:unknown: pull denied" in posted[0]
    assert "skipped (no eligible input)" not in posted[0]


# ---- reason formatting ---------------------------------------------------------


@pytest.mark.parametrize("err,leaked,kept", [
    ("https://:s3cret@redis.example.invalid/0", "s3cret", "https://***@redis.example.invalid/0"),
    ("https://u:p4ss@h.example.invalid/x", "p4ss", "https://***@h.example.invalid/x"),
    ("Authorization: Bearer eyJhbGciOi.payload.sig", "eyJhbGciOi", "Bearer ***"),
    ("slack xoxe.xoxp-1-abc and xapp-1-A0-xyz", "xoxp-1-abc", "slack *** and ***"),
    ("token github_pat_11ABCDEF_xyz", "github_pat_11", "token ***"),
])
def test_reasons_redact_credentials(err, leaked, kept):
    _, reason = _no_scan_alert(["trivy"], [("trivy", err)])
    assert leaked not in reason and kept in reason


def test_reasons_escape_slack_mrkdwn():
    _, reason = _no_scan_alert(["trivy"], [("trivy", "<!channel> see <https://x.example.invalid|here> & more")])
    assert "<!channel>" not in reason and "<https" not in reason
    assert "&lt;!channel&gt;" in reason and "&amp; more" in reason


def test_reasons_cap_at_five_with_remainder():
    failed = [(f"lane{i}", "boom") for i in range(7)]
    _, reason = _no_scan_alert([f"lane{i}" for i in range(7)], failed)
    assert reason.startswith("7 check(s) attempted, none completed — ")
    assert reason.count(": boom") == 5 and "(+2 more)" in reason
