"""End-to-end tests for main.run() with mocks for everything that touches the outside world."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from secscan.config import (
    Config,
    PathsConfig,
    ProjectConfig,
    ScannersConfig,
    SlackConfig,
    TriageConfig,
)
from secscan.github import ProjectContext, ProjectField
from secscan.runners import RunnerResult


def _cfg(tmp_path, **kw):
    return Config(
        repo=kw.get("repo", "owner/name"),
        ref=kw.get("ref", "main"),
        project=kw.get("project", ProjectConfig(owner="owner", number=5)),
        github_token=kw.get("github_token", "ghp_fake"),
        scanners=kw.get("scanners", ScannersConfig(osv=True, gitleaks=True, semgrep=True)),
        paths=kw.get("paths", PathsConfig(exclude=[])),
        severity_floor=kw.get("severity_floor", "low"),
        triage=kw.get("triage", TriageConfig(enabled=False)),
        slack=kw.get("slack", SlackConfig(enabled=False)),
        semgrep_rules_dir=kw.get("semgrep_rules_dir", "auto"),
    )


def _project_ctx():
    return ProjectContext(
        id="PVT_x",
        owner="owner",
        number=5,
        severity=ProjectField(id="SEV", options={
            "critical": "o-c", "high": "o-h", "medium": "o-m", "low": "o-l", "info": "o-i",
        }),
        category=ProjectField(id="CAT", options={
            "dependency": "o-d", "secret": "o-s", "sast": "o-a", "iac": "o-ia", "license": "o-li",
        }),
    )


def _populate_synthetic_repo(repo_dir: Path):
    """Drop a tiny repo with all three signal types."""
    repo_dir.mkdir(parents=True, exist_ok=True)
    (repo_dir / "package.json").write_text('{"name": "x", "version": "0.0.0"}')
    (repo_dir / "package-lock.json").write_text(
        json.dumps({"name": "x", "lockfileVersion": 3, "packages": {}})
    )
    (repo_dir / ".env").write_text("API_KEY=sk_test_fake_value_for_unit_test\n")
    (repo_dir / "src").mkdir(exist_ok=True)
    (repo_dir / "src" / "a.js").write_text("eval(req.body.cmd);\n")


def _clone_populates(dest_dir_factory):
    """Build a clone side_effect that populates the destination as a synthetic repo."""

    def _side_effect(ref, dest, shallow=True):
        _populate_synthetic_repo(Path(dest))

    return _side_effect


def _osv_sarif():
    return {"runs": [{"tool": {"driver": {"name": "osv-scanner", "rules": [{"id": "GHSA-aaaa", "properties": {"security-severity": "9.8", "ecosystem": "npm", "package": "leftpad"}}]}}, "results": [
        {"ruleId": "GHSA-aaaa", "level": "error", "message": {"text": "leftpad vuln"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "package-lock.json"}, "region": {"startLine": 1}}}]}
    ]}]}


def _gitleaks_sarif():
    return {"runs": [{"tool": {"driver": {"name": "gitleaks"}}, "results": [
        {"ruleId": "generic-api-key", "level": "error", "message": {"text": "secret detected"},
         "partialFingerprints": {"commitSha": "abcd1234"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".env"}, "region": {"startLine": 1, "snippet": {"text": "sk_test_fake_value_for_unit_test"}}}}]}
    ]}]}


def _semgrep_sarif():
    return {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": [{"id": "js.eval", "properties": {"security-severity": "8.5"}}]}}, "results": [
        {"ruleId": "js.eval", "level": "error", "message": {"text": "eval on user input"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a.js"}, "region": {"startLine": 1, "snippet": {"text": "eval(req.body.cmd)"}}}}]}
    ]}]}


def _scanner_results():
    return {
        "osv": RunnerResult("osv", _osv_sarif(), True),
        "gitleaks": RunnerResult("gitleaks", _gitleaks_sarif(), True),
        "semgrep": RunnerResult("semgrep", _semgrep_sarif(), True),
    }


def _fresh_gh(dry_run=False):
    fake = MagicMock()
    fake.dry_run = dry_run
    fake.resolve_project.return_value = _project_ctx()
    fake.list_project_items.return_value = []
    fake.add_to_project.side_effect = lambda pid, nid: f"ITEM_{nid}"
    fake.set_project_field.return_value = None
    counter = {"n": 100}

    def create(title, body, labels=None):
        counter["n"] += 1
        return {"number": counter["n"], "id": counter["n"] + 1000,
                "node_id": f"I_{counter['n']}", "title": title, "body": body, "html_url": "x"}

    fake.create_issue.side_effect = create
    return fake


def test_e2e_dry_run_creates_no_issues(tmp_path):
    from secscan.main import run
    repo_dir = tmp_path / "name"
    _populate_synthetic_repo(repo_dir)

    cfg = _cfg(tmp_path)
    fake_gh = _fresh_gh(dry_run=True)

    results = _scanner_results()
    with patch("secscan.main.GitHub", return_value=fake_gh), \
         patch("secscan.runners.osv.run", return_value=results["osv"]) as o, \
         patch("secscan.runners.gitleaks.run", return_value=results["gitleaks"]) as gl, \
         patch("secscan.runners.semgrep.run", return_value=results["semgrep"]) as sg:
        fake_gh.clone.side_effect = _clone_populates(None)
        rc = run(cfg, dry_run=True, work_dir=str(tmp_path), keep_work=True)

    assert rc == 0
    o.assert_called()
    gl.assert_called()
    sg.assert_called()
    fake_gh.resolve_project.assert_called_once_with("owner", 5)
    fake_gh.list_project_items.assert_called_once()


def test_e2e_creates_issues_when_not_dry_run(tmp_path):
    from secscan.main import run
    repo_dir = tmp_path / "name"
    _populate_synthetic_repo(repo_dir)

    cfg = _cfg(tmp_path)
    fake_gh = _fresh_gh(dry_run=False)

    results = _scanner_results()
    with patch("secscan.main.GitHub", return_value=fake_gh), \
         patch("secscan.runners.osv.run", return_value=results["osv"]), \
         patch("secscan.runners.gitleaks.run", return_value=results["gitleaks"]), \
         patch("secscan.runners.semgrep.run", return_value=results["semgrep"]):
        fake_gh.clone.side_effect = _clone_populates(None)
        rc = run(cfg, dry_run=False, work_dir=str(tmp_path), keep_work=True)

    assert rc == 0
    # 1 OSV + 1 gitleaks + 1 semgrep finding -> 3 issues
    assert fake_gh.create_issue.call_count == 3
    assert fake_gh.add_to_project.call_count == 3
    # Severity + Category for each = 6
    assert fake_gh.set_project_field.call_count == 6


def test_failed_scanner_does_not_block_others(tmp_path):
    from secscan.main import run
    repo_dir = tmp_path / "name"
    _populate_synthetic_repo(repo_dir)

    cfg = _cfg(tmp_path)
    fake_gh = _fresh_gh(dry_run=False)

    with patch("secscan.main.GitHub", return_value=fake_gh), \
         patch("secscan.runners.osv.run", return_value=RunnerResult("osv", None, False, "binary not found")), \
         patch("secscan.runners.gitleaks.run", return_value=RunnerResult("gitleaks", _gitleaks_sarif(), True)), \
         patch("secscan.runners.semgrep.run", return_value=RunnerResult("semgrep", _semgrep_sarif(), True)):
        fake_gh.clone.side_effect = _clone_populates(None)
        rc = run(cfg, dry_run=False, work_dir=str(tmp_path), keep_work=True)

    assert rc == 0  # partial success is still success
    assert fake_gh.create_issue.call_count == 2  # gitleaks + semgrep


def test_all_scanners_fail_returns_error(tmp_path):
    from secscan.main import run
    repo_dir = tmp_path / "name"
    _populate_synthetic_repo(repo_dir)

    cfg = _cfg(tmp_path)
    fake_gh = _fresh_gh(dry_run=False)

    with patch("secscan.main.GitHub", return_value=fake_gh), \
         patch("secscan.runners.osv.run", return_value=RunnerResult("osv", None, False, "x")), \
         patch("secscan.runners.gitleaks.run", return_value=RunnerResult("gitleaks", None, False, "x")), \
         patch("secscan.runners.semgrep.run", return_value=RunnerResult("semgrep", None, False, "x")):
        fake_gh.clone.side_effect = _clone_populates(None)
        rc = run(cfg, dry_run=False, work_dir=str(tmp_path), keep_work=True)

    assert rc == 3
    fake_gh.create_issue.assert_not_called()


def test_repo_dir_is_wiped_even_when_work_dir_provided(tmp_path):
    """Security: the clone must be removed even when the caller supplied --work-dir."""
    from secscan.main import run

    cfg = _cfg(tmp_path)
    fake_gh = _fresh_gh(dry_run=False)

    with patch("secscan.main.GitHub", return_value=fake_gh), \
         patch("secscan.runners.osv.run", return_value=RunnerResult("osv", _osv_sarif(), True)), \
         patch("secscan.runners.gitleaks.run", return_value=RunnerResult("gitleaks", _gitleaks_sarif(), True)), \
         patch("secscan.runners.semgrep.run", return_value=RunnerResult("semgrep", _semgrep_sarif(), True)):
        fake_gh.clone.side_effect = _clone_populates(None)
        rc = run(cfg, dry_run=False, work_dir=str(tmp_path), keep_work=False)

    assert rc == 0
    assert not (tmp_path / "name").exists(), "clone dir must be wiped after the run"
    assert tmp_path.exists()


def test_keep_work_preserves_clone(tmp_path):
    from secscan.main import run

    cfg = _cfg(tmp_path)
    fake_gh = _fresh_gh(dry_run=True)

    with patch("secscan.main.GitHub", return_value=fake_gh), \
         patch("secscan.runners.osv.run", return_value=RunnerResult("osv", _osv_sarif(), True)), \
         patch("secscan.runners.gitleaks.run", return_value=RunnerResult("gitleaks", _gitleaks_sarif(), True)), \
         patch("secscan.runners.semgrep.run", return_value=RunnerResult("semgrep", _semgrep_sarif(), True)):
        fake_gh.clone.side_effect = _clone_populates(None)
        run(cfg, dry_run=True, work_dir=str(tmp_path), keep_work=True)

    assert (tmp_path / "name").exists()  # --keep-work honored


def test_severity_floor_skips_low_findings(tmp_path):
    from secscan.main import run
    repo_dir = tmp_path / "name"
    _populate_synthetic_repo(repo_dir)

    cfg = _cfg(tmp_path, severity_floor="critical")  # only critical
    fake_gh = _fresh_gh(dry_run=False)

    with patch("secscan.main.GitHub", return_value=fake_gh), \
         patch("secscan.runners.osv.run", return_value=RunnerResult("osv", _osv_sarif(), True)), \
         patch("secscan.runners.gitleaks.run", return_value=RunnerResult("gitleaks", _gitleaks_sarif(), True)), \
         patch("secscan.runners.semgrep.run", return_value=RunnerResult("semgrep", _semgrep_sarif(), True)):
        fake_gh.clone.side_effect = _clone_populates(None)
        rc = run(cfg, dry_run=False, work_dir=str(tmp_path), keep_work=True)

    assert rc == 0
    # only OSV's GHSA-aaaa has CVSS 9.8 = critical; gitleaks and semgrep are high
    assert fake_gh.create_issue.call_count == 1
