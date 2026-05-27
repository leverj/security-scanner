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


def _fake_side_effect(rc: int, stdout: str = "", stderr: str = ""):
    """Like _fake_completed, but also honors the gitleaks-style
    `--report-path <path>` flag: writes `stdout` to that path so file-based
    readers see the SARIF where they expect."""

    def _f(cmd, **kw):
        if "--report-path" in cmd:
            idx = cmd.index("--report-path")
            if idx + 1 < len(cmd) and cmd[idx + 1] not in ("", "-"):
                try:
                    Path(cmd[idx + 1]).write_text(stdout)
                except OSError:
                    pass
        return _fake_completed(rc, stdout, stderr)

    return _f


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
    with patch("secscan.runners.subprocess.run", side_effect=_fake_side_effect(0, TINY_SARIF_JSON, "")) as m:
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
    with patch("secscan.runners.subprocess.run", side_effect=_fake_side_effect(vuln_rc, TINY_SARIF_JSON, "")) as m:
        result = module.run(tmp_path, **kwargs)
    assert m.called
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
    with patch("secscan.runners.subprocess.run", side_effect=_fake_side_effect(0, "not json at all <<<", "")):
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

def test_osv_does_not_pass_paths_to_ignore(tmp_path: Path):
    """osv-scanner's exclude flag name varies by version (and is unsupported on
    1.9.2). We rely on post-hoc filtering in normalize.py instead — assert the
    flag is never passed even when excludes are configured."""
    with patch("secscan.runners.subprocess.run") as m:
        m.return_value = _fake_completed(0, TINY_SARIF_JSON, "")
        osv_runner.run(tmp_path, exclude=["vendor/", "archive/"])
    cmd = m.call_args.args[0]
    assert "--paths-to-ignore" not in cmd
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


# --- gitleaks-specific: file-based report wiring ----------------------------

def test_gitleaks_writes_report_to_tempfile_in_root(tmp_path: Path):
    """v8 ignores `--report-path -` (silently writes 0 bytes to stdout). We must
    pass a real file path inside the scan root."""
    with patch("secscan.runners.subprocess.run", side_effect=_fake_side_effect(0, TINY_SARIF_JSON, "")) as m:
        gitleaks_runner.run(tmp_path)
    cmd = m.call_args.args[0]
    assert "--report-format" in cmd
    assert "sarif" in cmd
    assert "--report-path" in cmd
    idx = cmd.index("--report-path")
    report_path = cmd[idx + 1]
    assert report_path != "-"
    # Path must live inside the scan root so it shares lifecycle.
    assert report_path.startswith(str(tmp_path))


def test_gitleaks_tempfile_is_cleaned_up_after_run(tmp_path: Path):
    """The tempfile must not survive the run regardless of outcome."""
    captured_path = {}

    def _capture(cmd, **kw):
        idx = cmd.index("--report-path")
        captured_path["p"] = cmd[idx + 1]
        Path(cmd[idx + 1]).write_text(TINY_SARIF_JSON)
        return _fake_completed(0, "", "")

    with patch("secscan.runners.subprocess.run", side_effect=_capture):
        gitleaks_runner.run(tmp_path)
    assert not Path(captured_path["p"]).exists()


@pytest.mark.parametrize("rc", [0, 1, 77])
def test_gitleaks_accepts_any_exit_code_when_report_parses(rc, tmp_path: Path):
    """v7 used rc=77 for "leaks found"; v8 uses rc=1. We trust the SARIF parse,
    not the exit code: if the report file is valid SARIF the run was successful."""
    with patch("secscan.runners.subprocess.run", side_effect=_fake_side_effect(rc, TINY_SARIF_JSON, "")):
        result = gitleaks_runner.run(tmp_path)
    assert result.completed is True
    assert result.sarif == TINY_SARIF


def test_gitleaks_no_report_file_written_is_failure(tmp_path: Path):
    """Genuine failure: scanner didn't write the report. Empty/missing file -> error."""
    with patch("secscan.runners.subprocess.run", return_value=_fake_completed(1, "", "config error")):
        result = gitleaks_runner.run(tmp_path)
    assert result.completed is False
    assert "no SARIF report written" in (result.error or "") or "exit 1" in (result.error or "")
