"""Opt-in `semgrep_extra_rules`: repo-local rule files run alongside the bundled
rules. Absent (the default) must leave the semgrep invocation exactly as before."""

import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from security_scan.config import (
    Config,
    ConfigError,
    PathsConfig,
    ProjectConfig,
    ScannersConfig,
    SlackConfig,
    load_config,
)
from security_scan.detect import ScannerTarget
from security_scan.main import _invoke_runner
from security_scan.runners import RunnerResult
from security_scan.runners import semgrep as semgrep_runner

RULES = """\
rules:
  - id: demo-one
    languages: [python]
    severity: INFO
    message: m
    pattern: eval(...)
  - id: demo-two
    languages: [python]
    severity: INFO
    message: m
    pattern: exec(...)
"""


def _cfg(extra=None):
    return Config(
        repo="o/r", ref="main",
        project=ProjectConfig(owner="o", number=1),
        github_token="t",
        scanners=ScannersConfig(),
        paths=PathsConfig(),
        severity_floor="low",
        slack=SlackConfig(),
        semgrep_extra_rules=list(extra or []),
    )


def _sarif(rule_ids):
    return {"runs": [{"tool": {"driver": {"name": "Semgrep", "rules": [{"id": i} for i in rule_ids]}},
                      "results": []}]}


SEMGREP = ScannerTarget(scanner="semgrep", ecosystem=None, targets=[])


# ---- config -----------------------------------------------------------------

BASE = "repo: o/n\nref: main\nproject: {owner: o, number: 1}\n"


@pytest.fixture
def cfg_file(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake")
    p = tmp_path / "c.yaml"

    def write(extra=""):
        p.write_text(BASE + extra)
        return p
    return write


def test_absent_by_default(cfg_file):
    assert load_config(cfg_file()).semgrep_extra_rules == []


def test_list_of_repo_relative_paths(cfg_file):
    cfg = load_config(cfg_file("semgrep_extra_rules: [.security-scan/semgrep/a.yaml, ./b.yml]\n"))
    assert cfg.semgrep_extra_rules == [".security-scan/semgrep/a.yaml", "b.yml"]


@pytest.mark.parametrize("value", ["/etc/rules.yaml", "../other/rules.yaml", "a/../../x.yaml"])
def test_paths_outside_repo_rejected(cfg_file, value):
    with pytest.raises(ConfigError, match="repo-relative"):
        load_config(cfg_file(f"semgrep_extra_rules: [{json.dumps(value)}]\n"))


@pytest.mark.parametrize("value", ['"a.yaml"', "[1]", '[""]', "{a: b}"])
def test_non_list_rejected(cfg_file, value):
    with pytest.raises(ConfigError, match="semgrep_extra_rules"):
        load_config(cfg_file(f"semgrep_extra_rules: {value}\n"))


# ---- runner -----------------------------------------------------------------

def test_runner_adds_one_config_per_extra_file(tmp_path):
    with patch("security_scan.runners.semgrep._run", return_value=(0, json.dumps(_sarif([])), "")) as m:
        semgrep_runner.run(tmp_path, rules_dir="/bundled", extra_rules=[Path("/w/a.yaml"), Path("/w/b.yaml")])
    cmd = m.call_args.args[0]
    assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "--config"] == ["/bundled", "/w/a.yaml", "/w/b.yaml"]


def test_runner_without_extra_is_unchanged(tmp_path):
    with patch("security_scan.runners.semgrep._run", return_value=(0, json.dumps(_sarif([])), "")) as m:
        semgrep_runner.run(tmp_path, rules_dir="/bundled")
    assert m.call_args.args[0] == ["semgrep", "scan", "--config", "/bundled", "--sarif", "--metrics=off",
                                   "--quiet", str(tmp_path)]


# ---- pipeline wiring ----------------------------------------------------------

def test_default_config_calls_semgrep_exactly_as_before(tmp_path):
    """Projects that don't opt in (e.g. every config without the key) get the
    same runner call as before this feature: no extra_rules argument at all."""
    with patch("security_scan.runners.semgrep.run", return_value=RunnerResult("semgrep", _sarif([]), True)) as m:
        _invoke_runner(SEMGREP, _cfg(), tmp_path, "/bundled")
    assert m.call_args.args == (tmp_path,)
    assert m.call_args.kwargs == {"rules_dir": "/bundled", "exclude": []}


def test_extra_rules_resolved_logged_and_counted(tmp_path, capsys):
    rel = ".security-scan/semgrep/demo.yaml"
    (tmp_path / rel).parent.mkdir(parents=True)
    (tmp_path / rel).write_text(RULES)
    loaded = ["bundled.some-rule", "work..security-scan.semgrep.demo-one", "work..security-scan.semgrep.demo-two"]
    with patch("security_scan.runners.semgrep.run", return_value=RunnerResult("semgrep", _sarif(loaded), True)) as m:
        r = _invoke_runner(SEMGREP, _cfg([rel]), tmp_path, "/bundled")
    assert r.completed
    assert m.call_args.kwargs["extra_rules"] == [(tmp_path / rel).resolve()]
    err = capsys.readouterr().err
    digest = hashlib.sha256(RULES.encode()).hexdigest()
    assert f"semgrep: extra rules {rel} sha256={digest} rules=2" in err
    assert "semgrep: extra rules demo.yaml: 2/2 rules active" in err


def test_partially_loaded_rules_are_reported_not_hidden(tmp_path, capsys):
    (tmp_path / "r.yaml").write_text(RULES)
    with patch("security_scan.runners.semgrep.run",
               return_value=RunnerResult("semgrep", _sarif(["x.demo-one"]), True)):
        _invoke_runner(SEMGREP, _cfg(["r.yaml"]), tmp_path, "/bundled")
    assert "r.yaml: 1/2 rules active" in capsys.readouterr().err


@pytest.mark.parametrize("setup,needle", [
    (lambda root: None, "file not found"),
    (lambda root: (root / "r.yaml").write_text("rules: [{no_id: 1}]"), "unreadable rule file"),
    (lambda root: (root / "r.yaml").write_text(":\n  - ["), "unreadable rule file"),
    (lambda root: (root / "r.yaml").symlink_to(root.parent / "outside.yaml"), "resolves outside the repo"),
])
def test_bad_extra_rules_fail_the_lane_visibly(tmp_path, setup, needle):
    root = tmp_path / "repo"
    root.mkdir()
    (tmp_path / "outside.yaml").write_text(RULES)
    setup(root)
    with patch("security_scan.runners.semgrep.run") as m:
        r = _invoke_runner(SEMGREP, _cfg(["r.yaml"]), root, "/bundled")
    m.assert_not_called()
    assert not r.completed and needle in r.error


def test_failed_semgrep_run_does_not_claim_rules_active(tmp_path, capsys):
    (tmp_path / "r.yaml").write_text(RULES)
    with patch("security_scan.runners.semgrep.run", return_value=RunnerResult("semgrep", None, False, "exit 7")):
        r = _invoke_runner(SEMGREP, _cfg(["r.yaml"]), tmp_path, "/bundled")
    assert not r.completed
    assert "rules active" not in capsys.readouterr().err
