"""Exit-code contract for both entrypoints: `cli()` and `python -m security_scan`.

The Docker ENTRYPOINT is `python -m security_scan`, so a return code that
`cli()` computes but `__main__` drops turns every failure into a green CI run.
Each scenario runs through both entrypoints with the outside world mocked:

  0  scan completed (findings present — the tool files, it does not gate)
  2  config error
  3  every enabled scanner failed
  4  GitHub API failure (e.g. 401 Bad credentials)
"""

import os
import runpy
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from security_scan.github import GitHubError
from security_scan.runners import RunnerResult

from .test_main import _clone_populates, _fresh_gh, _scanner_results

REPO_ROOT = Path(__file__).resolve().parent.parent

CONFIG_YAML = """\
repo: owner/name
ref: main
project:
  owner: owner
  number: 5
scanners:
  osv: true
  gitleaks: true
  semgrep: true
  trivy: false
  trufflehog: false
  syft: false
  supply_chain: false
"""


@pytest.fixture
def config_path(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake")
    p = tmp_path / "config.yaml"
    p.write_text(CONFIG_YAML)
    return p


def _invoke(entry, argv):
    """Run an entrypoint and return its exit code."""
    if entry == "cli":
        from security_scan.main import cli
        return cli(argv)
    with patch.object(sys, "argv", ["security_scan", *argv]):
        with pytest.raises(SystemExit) as exc:
            runpy.run_module("security_scan", run_name="__main__", alter_sys=True)
    return exc.value.code


def _scan(entry, config_path, tmp_path, fake_gh, results):
    argv = ["--config", str(config_path), "--work-dir", str(tmp_path / "work"), "--keep-work"]
    fake_gh.clone.side_effect = _clone_populates(None)
    with patch("security_scan.main.GitHub", return_value=fake_gh), \
         patch("security_scan.runners.osv.run", return_value=results["osv"]), \
         patch("security_scan.runners.gitleaks.run", return_value=results["gitleaks"]), \
         patch("security_scan.runners.semgrep.run", return_value=results["semgrep"]):
        return _invoke(entry, argv)


ENTRIES = ["cli", "module"]


@pytest.mark.parametrize("entry", ENTRIES)
def test_success_with_findings_exits_0(entry, config_path, tmp_path):
    fake_gh = _fresh_gh()
    rc = _scan(entry, config_path, tmp_path, fake_gh, _scanner_results())
    assert rc == 0
    assert fake_gh.create_issue.call_count == 3  # findings were filed, not gated


@pytest.mark.parametrize("entry", ENTRIES)
def test_missing_config_exits_2(entry, tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake")
    assert _invoke(entry, ["--config", str(tmp_path / "nope.yaml")]) == 2


@pytest.mark.parametrize("entry", ENTRIES)
def test_missing_token_exits_2(entry, config_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN")
    assert _invoke(entry, ["--config", str(config_path)]) == 2


@pytest.mark.parametrize("entry", ENTRIES)
def test_all_scanners_fail_exits_3(entry, config_path, tmp_path):
    fake_gh = _fresh_gh()
    failed = {s: RunnerResult(s, None, False, "x") for s in ("osv", "gitleaks", "semgrep")}
    assert _scan(entry, config_path, tmp_path, fake_gh, failed) == 3
    fake_gh.create_issue.assert_not_called()


@pytest.mark.parametrize("entry", ENTRIES)
def test_github_401_exits_4_and_is_reported(entry, config_path, tmp_path, capsys):
    fake_gh = _fresh_gh()
    fake_gh.resolve_project.side_effect = GitHubError(401, "Bad credentials")
    assert _scan(entry, config_path, tmp_path, fake_gh, _scanner_results()) == 4
    assert "GitHub API 401" in capsys.readouterr().err


def test_real_module_subprocess_propagates_exit_code(tmp_path):
    """Same invocation shape as the Docker ENTRYPOINT, in a real interpreter."""
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_TOKEN"}
    env["PYTHONPATH"] = str(REPO_ROOT)
    proc = subprocess.run(
        [sys.executable, "-m", "security_scan", "--config", str(tmp_path / "nope.yaml")],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 2, proc.stderr
    assert "file not found" in proc.stderr
