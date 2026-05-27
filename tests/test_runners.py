"""Mock-driven tests for runner modules. No real scanner binaries required."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from secscan.runners import RunnerResult, _run
from secscan.runners import gitleaks as gitleaks_runner
from secscan.runners import osv as osv_runner
from secscan.runners import semgrep as semgrep_runner

TINY_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "fake"}}, "results": []}],
}
TINY_SARIF_JSON = json.dumps(TINY_SARIF)

EXECUTE_LIKE_VERBS = {"install", "build", "run"}


def _fake_completed(rc: int, stdout: str = "", stderr: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=rc, stdout=stdout, stderr=stderr)


def _assert_no_execute_verbs(cmd: list[str]) -> None:
    # `semgrep scan` is the subcommand; allow it explicitly. Anything else execute-like is banned.
    for arg in cmd[1:]:  # skip the binary name itself
        low = arg.lower()
        # "scan" is fine; only flag literal execute-like verbs as standalone args.
        assert low not in EXECUTE_LIKE_VERBS, f"forbidden verb in cmd: {arg!r} ({cmd!r})"


# --- _run --------------------------------------------------------------------

def test_run_invokes_subprocess_with_cwd(tmp_path: Path):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(0, "hello", "")
        rc, out, err = _run(["echo", "hi"], cwd=tmp_path)
    assert (rc, out, err) == (0, "hello", "")
    kwargs = m.call_args.kwargs
    assert kwargs["cwd"] == str(tmp_path)
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["check"] is False


# --- happy-path: exit 0 with valid SARIF ------------------------------------

@pytest.mark.parametrize(
    "module,kwargs,scanner",
    [
        (osv_runner, {}, "osv"),
        (gitleaks_runner, {}, "gitleaks"),
        (semgrep_runner, {"rules_dir": "/rules"}, "semgrep"),
    ],
)
def test_runner_exit_zero_returns_parsed_sarif(module, kwargs, scanner, tmp_path: Path):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(0, TINY_SARIF_JSON, "")
        result: RunnerResult = module.run(tmp_path, **kwargs)
    assert result.completed is True
    assert result.scanner == scanner
    assert result.sarif == TINY_SARIF
    assert result.error is None

    # cwd MUST be set explicitly (not None) so subprocess doesn't leak into caller's cwd.
    cwd_arg = m.call_args.kwargs.get("cwd")
    assert cwd_arg is not None and cwd_arg == str(tmp_path)

    # Defensive: no execute-like verb leaked into the command.
    cmd = m.call_args.args[0]
    _assert_no_execute_verbs(cmd)


# --- "found vulnerabilities" exit codes still count as success --------------

@pytest.mark.parametrize(
    "module,kwargs,scanner,vuln_rc",
    [
        (osv_runner, {}, "osv", 1),
        (gitleaks_runner, {}, "gitleaks", 77),
        (semgrep_runner, {"rules_dir": "/rules"}, "semgrep", 1),
    ],
)
def test_runner_vulns_found_exit_code_is_success(
    module, kwargs, scanner, vuln_rc, tmp_path: Path
):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(vuln_rc, TINY_SARIF_JSON, "")
        result = module.run(tmp_path, **kwargs)
    assert result.completed is True
    assert result.scanner == scanner
    assert result.sarif == TINY_SARIF
    assert result.error is None


# --- binary not installed ---------------------------------------------------

@pytest.mark.parametrize(
    "module,kwargs,binary_name",
    [
        (osv_runner, {"binary": "osv-scanner"}, "osv-scanner"),
        (gitleaks_runner, {"binary": "gitleaks"}, "gitleaks"),
        (semgrep_runner, {"rules_dir": "/rules", "binary": "semgrep"}, "semgrep"),
    ],
)
def test_runner_binary_not_found(module, kwargs, binary_name, tmp_path: Path):
    with patch("secscan.runners.subprocess.run", side_effect=FileNotFoundError(binary_name)):
        result = module.run(tmp_path, **kwargs)
    assert result.completed is False
    assert result.sarif is None
    assert result.error is not None
    assert binary_name in result.error


# --- failure exit codes -----------------------------------------------------

@pytest.mark.parametrize(
    "module,kwargs",
    [
        (osv_runner, {}),
        (gitleaks_runner, {}),
        (semgrep_runner, {"rules_dir": "/rules"}),
    ],
)
def test_runner_unexpected_exit_code_is_failure(module, kwargs, tmp_path: Path):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(99, "", "boom")
        result = module.run(tmp_path, **kwargs)
    assert result.completed is False
    assert result.sarif is None
    assert result.error is not None


# --- unparseable JSON despite valid exit code -------------------------------

@pytest.mark.parametrize(
    "module,kwargs",
    [
        (osv_runner, {}),
        (gitleaks_runner, {}),
        (semgrep_runner, {"rules_dir": "/rules"}),
    ],
)
def test_runner_unparseable_json_is_failure(module, kwargs, tmp_path: Path):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(0, "not json at all <<<", "")
        result = module.run(tmp_path, **kwargs)
    assert result.completed is False
    assert result.sarif is None
    assert result.error is not None
    assert "parse" in result.error.lower()


# --- defensive: command never contains install/build/run verbs --------------

@pytest.mark.parametrize(
    "module,kwargs",
    [
        (osv_runner, {"exclude": ["vendor/", "archive/"]}),
        (gitleaks_runner, {}),
        (semgrep_runner, {"rules_dir": "/rules", "exclude": ["vendor/"]}),
    ],
)
def test_runner_cmd_has_no_execute_verbs(module, kwargs, tmp_path: Path):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(0, TINY_SARIF_JSON, "")
        module.run(tmp_path, **kwargs)
    cmd = m.call_args.args[0]
    _assert_no_execute_verbs(cmd)


# --- defensive: cwd is explicitly set on every successful invocation --------

@pytest.mark.parametrize(
    "module,kwargs",
    [
        (osv_runner, {}),
        (gitleaks_runner, {}),
        (semgrep_runner, {"rules_dir": "/rules"}),
    ],
)
def test_runner_subprocess_cwd_is_set(module, kwargs, tmp_path: Path):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(0, TINY_SARIF_JSON, "")
        module.run(tmp_path, **kwargs)
    cwd = m.call_args.kwargs.get("cwd")
    assert cwd is not None
    assert cwd == str(tmp_path)


# --- osv-specific: excludes wired in ----------------------------------------

def test_osv_passes_paths_to_ignore(tmp_path: Path):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(0, TINY_SARIF_JSON, "")
        osv_runner.run(tmp_path, exclude=["vendor/", "archive/"])
    cmd = m.call_args.args[0]
    # one --paths-to-ignore per exclude
    assert cmd.count("--paths-to-ignore") == 2
    assert "vendor/" in cmd
    assert "archive/" in cmd
    assert "--skip-git" in cmd
    assert "--recursive" in cmd


# --- semgrep-specific: excludes + config wired in ---------------------------

def test_semgrep_passes_config_and_excludes(tmp_path: Path):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(0, TINY_SARIF_JSON, "")
        semgrep_runner.run(tmp_path, rules_dir="/rules", exclude=["archive/", "vendor/"])
    cmd = m.call_args.args[0]
    assert "--config" in cmd
    assert "/rules" in cmd
    assert cmd.count("--exclude") == 2
    assert "--metrics=off" in cmd
    assert "--sarif" in cmd


# --- gitleaks-specific: stdout report wiring --------------------------------

def test_gitleaks_reports_to_stdout(tmp_path: Path):
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(0, TINY_SARIF_JSON, "")
        gitleaks_runner.run(tmp_path)
    cmd = m.call_args.args[0]
    assert "--report-format" in cmd
    assert "sarif" in cmd
    assert "--report-path" in cmd
    # stdout sentinel
    assert "-" in cmd
