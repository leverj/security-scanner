"""End-to-end dry-run against a synthetic fixture repo.

Exercises the full pipeline (config -> detect -> run -> normalize -> sync) with
every external dep mocked: git clone is a no-op that populates the dest, scanner
binaries are replaced with canned SARIF, and the GitHub class is in dry-run mode.

This test verifies the deterministic invariants that matter most:
  * Findings flow through every layer and end up in the sync result.
  * Fingerprints are stable across line shifts in the synthetic source.
  * `--dry-run` creates zero GitHub issues (no POSTs).
  * Marker round-trip works on the bodies that *would* have been posted.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from security_scan.config import (
    Config,
    PathsConfig,
    ProjectConfig,
    ScannersConfig,
    SlackConfig,
    TriageConfig,
)
from security_scan.fingerprint import parse_marker, resolve_fingerprint
from security_scan.github import ProjectContext, ProjectField
from security_scan.normalize import normalize_sarif
from security_scan.runners import RunnerResult


def _synthetic_repo(root: Path) -> None:
    """Build a tiny repo with planted issues for each scanner."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"name": "demo", "version": "0.0.0", "dependencies": {"left-pad": "1.0.0"}}')
    (root / "package-lock.json").write_text(json.dumps({"name": "demo", "lockfileVersion": 3, "packages": {}}))
    (root / "frontend").mkdir(exist_ok=True)
    (root / "frontend" / "package.json").write_text('{"name": "fe", "version": "0.0.0"}')
    (root / "frontend" / "yarn.lock").write_text("# yarn lockfile v1\n")
    (root / ".env").write_text("AWS_ACCESS_KEY_ID=TEST_FAKE_SECRET_VALUE\n")
    src = root / "src"
    src.mkdir(exist_ok=True)
    (src / "handler.js").write_text(
        "// planted SAST issue\n"
        "function handle(req) {\n"
        "  eval(req.body.cmd);\n"
        "}\n"
    )


def _osv_sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "osv-scanner", "rules": [
                {"id": "GHSA-dddd-2222", "properties": {
                    "security-severity": "9.8",
                    "ecosystem": "npm", "package": "left-pad",
                    "installed_version": "1.0.0",
                    "fixed_versions": ["1.3.0"],
                    "aliases": ["CVE-2024-99999"],
                }}
            ]}},
            "results": [{
                "ruleId": "GHSA-dddd-2222",
                "level": "error",
                "message": {"text": "Critical RCE in left-pad 1.0.0"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "package-lock.json"},
                        "region": {"startLine": 1},
                    }
                }],
            }],
        }],
    }


def _gitleaks_sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks"}},
            "results": [{
                "ruleId": "aws-access-token",
                "level": "error",
                "message": {"text": "AWS Access Key ID detected"},
                "partialFingerprints": {"commitSha": "0000000000000000000000000000000000000000:abc-secret"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": ".env"},
                        "region": {
                            "startLine": 1,
                            "snippet": {"text": "TEST_FAKE_SECRET_VALUE"},
                        },
                    }
                }],
            }],
        }],
    }


def _semgrep_sarif() -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "rules": [
                {"id": "js.eval-on-user-input", "properties": {"security-severity": "9.0"}}
            ]}},
            "results": [{
                "ruleId": "js.eval-on-user-input",
                "level": "error",
                "message": {"text": "eval on user-controlled input enables RCE"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/handler.js"},
                        "region": {"startLine": 3, "snippet": {"text": "eval(req.body.cmd)"}},
                    }
                }],
            }],
        }],
    }


@pytest.fixture
def cfg(tmp_path):
    return Config(
        repo="owner/demo",
        ref="main",
        project=ProjectConfig(owner="owner", number=7),
        github_token="ghp_fake_e2e",
        scanners=ScannersConfig(osv=True, gitleaks=True, semgrep=True),
        paths=PathsConfig(exclude=[]),
        severity_floor="low",
        triage=TriageConfig(enabled=False),
        slack=SlackConfig(enabled=False),
        semgrep_rules_dir="auto",
    )


def _project_ctx():
    return ProjectContext(
        id="PVT_x",
        owner="owner",
        number=7,
        severity=ProjectField(id="SEV", options={
            "critical": "o-c", "high": "o-h", "medium": "o-m", "low": "o-l", "info": "o-i",
        }),
        category=ProjectField(id="CAT", options={
            "dependency": "o-d", "secret": "o-s", "sast": "o-a", "iac": "o-ia", "license": "o-li",
        }),
    )


def _make_fake_gh(state="OPEN", existing_with_fp: list[str] | None = None) -> MagicMock:
    """Return a MagicMock GitHub that captures every create_issue call for inspection."""
    captured: list[dict] = []
    existing = []
    if existing_with_fp:
        # Synthesize existing project items whose bodies already contain those fingerprints.
        for i, fp in enumerate(existing_with_fp):
            existing.append({
                "item_id": f"OLD_ITEM_{i}",
                "content_id": f"I_{1000 + i}",
                "number": i + 1,
                "state": state,
                "title": "old",
                "body": f"prose\n<!-- security-scan: fp={fp} rule=R cat=sast -->",
            })

    fake_gh = MagicMock()
    fake_gh.dry_run = True
    fake_gh.resolve_project.return_value = _project_ctx()
    fake_gh.list_project_items.return_value = existing
    fake_gh.add_to_project.side_effect = lambda pid, nid: f"ITEM_{nid}"
    fake_gh.set_project_field.return_value = None

    def create(title, body, labels=None):
        issue = {"number": len(captured) + 100, "id": 1001 + len(captured),
                 "node_id": f"I_NEW_{len(captured)}",
                 "title": title, "body": body, "html_url": "<dry-run>"}
        captured.append(issue)
        return issue

    fake_gh.create_issue.side_effect = create
    fake_gh.captured = captured  # type: ignore[attr-defined]
    fake_gh.clone.side_effect = lambda ref, dest, shallow=True: _synthetic_repo(Path(dest))
    return fake_gh


def test_full_dryrun_pipeline_files_three_findings(cfg, tmp_path):
    from security_scan.main import run
    fake_gh = _make_fake_gh()

    with patch("security_scan.main.GitHub", return_value=fake_gh), \
         patch("security_scan.runners.osv.run", return_value=RunnerResult("osv", _osv_sarif(), True)), \
         patch("security_scan.runners.gitleaks.run", return_value=RunnerResult("gitleaks", _gitleaks_sarif(), True)), \
         patch("security_scan.runners.semgrep.run", return_value=RunnerResult("semgrep", _semgrep_sarif(), True)):
        rc = run(cfg, dry_run=True, work_dir=str(tmp_path), keep_work=True)

    assert rc == 0
    assert len(fake_gh.captured) == 3  # 1 osv + 1 gitleaks + 1 semgrep
    titles = [c["title"] for c in fake_gh.captured]
    assert any("GHSA-dddd-2222" in t for t in titles)
    assert any("aws-access-token" in t for t in titles)
    assert any("js.eval-on-user-input" in t for t in titles)


def test_dryrun_does_not_post_to_real_github(cfg, tmp_path):
    """The actual GitHub class in dry_run mode must make zero HTTP requests across
    issue creation AND every Projects v2 mutation."""
    from security_scan.github import GitHub

    captured_requests = []

    real_gh = GitHub("ghp_fake", "owner", "demo", dry_run=True)

    def fake_request(*a, **kw):
        captured_requests.append((a, kw))
        raise AssertionError("dry-run made an HTTP request")

    with patch.object(real_gh.session, "request", side_effect=fake_request):
        ctx = real_gh.resolve_project("owner", 7)
        items = real_gh.list_project_items(ctx.id)
        issue = real_gh.create_issue("t", "b")
        item_id = real_gh.add_to_project(ctx.id, issue["node_id"])
        real_gh.set_project_field(ctx.id, item_id, ctx.severity, "critical")

    assert captured_requests == []  # zero HTTP calls in dry-run
    assert items == []
    assert issue["html_url"] == "<dry-run>"
    assert item_id.startswith("DRY_RUN_ITEM_")


def test_marker_roundtrip_on_dryrun_bodies(cfg, tmp_path):
    """Every body that the pipeline would have posted must contain a parseable marker."""
    from security_scan.main import run
    fake_gh = _make_fake_gh()

    with patch("security_scan.main.GitHub", return_value=fake_gh), \
         patch("security_scan.runners.osv.run", return_value=RunnerResult("osv", _osv_sarif(), True)), \
         patch("security_scan.runners.gitleaks.run", return_value=RunnerResult("gitleaks", _gitleaks_sarif(), True)), \
         patch("security_scan.runners.semgrep.run", return_value=RunnerResult("semgrep", _semgrep_sarif(), True)):
        run(cfg, dry_run=True, work_dir=str(tmp_path), keep_work=True)

    for issue in fake_gh.captured:
        parsed = parse_marker(issue["body"])
        assert parsed is not None, f"missing marker on: {issue['title']}"
        assert parsed["fp"].startswith("fp_")


def test_closed_existing_fingerprint_suppresses_refile(cfg, tmp_path):
    """The spec invariant: a closed project item with our fingerprint never refiles."""
    from security_scan.main import run

    findings = normalize_sarif(_semgrep_sarif(), "semgrep")
    semgrep_fp = resolve_fingerprint(findings[0])

    fake_gh = _make_fake_gh(state="CLOSED", existing_with_fp=[semgrep_fp])

    with patch("security_scan.main.GitHub", return_value=fake_gh), \
         patch("security_scan.runners.osv.run", return_value=RunnerResult("osv", _osv_sarif(), True)), \
         patch("security_scan.runners.gitleaks.run", return_value=RunnerResult("gitleaks", _gitleaks_sarif(), True)), \
         patch("security_scan.runners.semgrep.run", return_value=RunnerResult("semgrep", _semgrep_sarif(), True)):
        run(cfg, dry_run=True, work_dir=str(tmp_path), keep_work=True)

    # 3 findings total; the semgrep one matches a closed-existing fp -> skip.
    assert len(fake_gh.captured) == 2
    captured_rules = [c["title"].split(":", 1)[0] for c in fake_gh.captured]
    assert "js.eval-on-user-input" not in captured_rules


def test_fingerprint_survives_line_shift_in_source(cfg):
    """The whole point of line-number-free fingerprints: refactor doesn't refile."""
    s1 = _semgrep_sarif()
    s2 = _semgrep_sarif()
    # Shift the planted issue to a much later line, same snippet.
    s2["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"] = 999

    f1 = normalize_sarif(s1, "semgrep")[0]
    f2 = normalize_sarif(s2, "semgrep")[0]
    assert resolve_fingerprint(f1) == resolve_fingerprint(f2)


def test_raw_secret_never_in_issue_body(cfg, tmp_path):
    """End-to-end check that the raw AWS key never reaches a posted body."""
    from security_scan.main import run
    raw_secret = "TEST_FAKE_SECRET_VALUE"
    fake_gh = _make_fake_gh()

    with patch("security_scan.main.GitHub", return_value=fake_gh), \
         patch("security_scan.runners.osv.run", return_value=RunnerResult("osv", _osv_sarif(), True)), \
         patch("security_scan.runners.gitleaks.run", return_value=RunnerResult("gitleaks", _gitleaks_sarif(), True)), \
         patch("security_scan.runners.semgrep.run", return_value=RunnerResult("semgrep", _semgrep_sarif(), True)):
        run(cfg, dry_run=True, work_dir=str(tmp_path), keep_work=True)

    for issue in fake_gh.captured:
        assert raw_secret not in issue["body"], f"raw secret leaked into: {issue['title']}"
        assert raw_secret not in issue["title"]
