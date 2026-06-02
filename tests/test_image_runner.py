"""Tests for the image-scan runner. `trivy image` / `docker build` are mocked."""

from __future__ import annotations

import json
from unittest.mock import patch

from security_scan.runners import image as image_runner
from security_scan.runners.image import ImageScanConfig

# -- Dockerfile FROM extraction ----------------------------------------------


def test_discover_base_images_basic(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "# comment\n"
        "FROM python:3.14-slim\n"
        "RUN pip install requests\n"
    )
    assert image_runner._discover_base_images(tmp_path) == ["python:3.14-slim"]


def test_discover_base_images_handles_multi_stage_and_alias(tmp_path):
    """Multi-stage builds reference stage aliases like `FROM builder AS final`;
    those aren't real images and must not be passed to trivy."""
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go build .\n"
        "FROM alpine:3.20\n"
        "COPY --from=builder /out /usr/local/bin\n"
        "FROM builder AS shipped\n"   # alias — must be skipped
    )
    refs = image_runner._discover_base_images(tmp_path)
    assert refs == ["golang:1.22", "alpine:3.20"]


def test_discover_base_images_skips_scratch_and_args(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "ARG BASE=python:3.14\n"
        "FROM $BASE\n"
        "FROM scratch\n"
        "FROM debian:bookworm-slim\n"
    )
    assert image_runner._discover_base_images(tmp_path) == ["debian:bookworm-slim"]


def test_discover_base_images_handles_platform_flag(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM --platform=linux/amd64 nginx:1.27 AS web\n")
    assert image_runner._discover_base_images(tmp_path) == ["nginx:1.27"]


def test_discover_base_images_walks_nested_and_dedups(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "Dockerfile").write_text("FROM redis:7.4\n")
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "api.Dockerfile").write_text("FROM redis:7.4\nFROM postgres:16\n")
    refs = image_runner._discover_base_images(tmp_path)
    # Dedup'd across files.
    assert sorted(refs) == ["postgres:16", "redis:7.4"]


def test_discover_base_images_skips_well_known_noise_dirs(tmp_path):
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "Dockerfile").write_text("FROM should-not-see:1.0\n")
    (tmp_path / "Dockerfile").write_text("FROM real:1.0\n")
    assert image_runner._discover_base_images(tmp_path) == ["real:1.0"]


def test_is_dockerfile_name_variants():
    assert image_runner._is_dockerfile_name("Dockerfile")
    assert image_runner._is_dockerfile_name("dockerfile")
    assert image_runner._is_dockerfile_name("Dockerfile.dev")
    assert image_runner._is_dockerfile_name("api.Dockerfile")
    assert image_runner._is_dockerfile_name("Containerfile")
    assert not image_runner._is_dockerfile_name("docker-compose.yaml")
    assert not image_runner._is_dockerfile_name("README.md")


# -- mode B: base-image scan via trivy ----------------------------------------


def _trivy_sarif_with(rule_id="CVE-2025-0001", level="error", sec_sev="9.5",
                      package="openssl"):
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Trivy", "rules": [{
                "id": rule_id,
                "properties": {"security-severity": sec_sev, "type": "vulnerability"},
            }]}},
            "results": [{
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f"vuln in {package}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": package},
                    "region": {"startLine": 1},
                }}],
            }],
        }],
    }


def test_run_base_images_invokes_trivy_per_ref(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.14\nFROM redis:7.4\n")

    seen_refs: list[str] = []

    def _fake_run(cmd, cwd, timeout=600):
        # `trivy image --format sarif ... <ref>`; the last arg is the ref.
        seen_refs.append(cmd[-1])
        return 0, json.dumps(_trivy_sarif_with(rule_id=f"CVE-{cmd[-1]}")), ""

    with patch("security_scan.runners.image.shutil.which", return_value="/x/trivy"), \
         patch("security_scan.runners.image._run", side_effect=_fake_run):
        results = image_runner.run(tmp_path, ImageScanConfig())

    assert seen_refs == ["python:3.14", "redis:7.4"]
    assert all(r.completed for r in results)
    assert len(results) == 2
    # Each SARIF result must carry the source provenance.
    for r in results:
        res = r.sarif["runs"][0]["results"][0]
        assert res["properties"]["security_scan_image_source"] == "base"
        assert res["properties"]["security_scan_image_ref"] in seen_refs


def test_run_no_dockerfile_returns_empty(tmp_path):
    """A repo without a Dockerfile shouldn't error or run trivy."""
    with patch("security_scan.runners.image._run") as p:
        results = image_runner.run(tmp_path, ImageScanConfig())
    assert results == []
    p.assert_not_called()


def test_run_skips_base_when_flag_off(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.14\n")
    with patch("security_scan.runners.image._run") as p:
        results = image_runner.run(tmp_path, ImageScanConfig(base_images=False))
    p.assert_not_called()
    assert results == []


def test_run_trivy_failure_yields_failed_result(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.14\n")

    def _fake_run(cmd, cwd, timeout=600):
        return 1, "", "trivy: vulnerability DB locked"

    with patch("security_scan.runners.image.shutil.which", return_value="/x/trivy"), \
         patch("security_scan.runners.image._run", side_effect=_fake_run):
        results = image_runner.run(tmp_path, ImageScanConfig())

    assert len(results) == 1
    assert results[0].completed is False
    assert "exit 1" in results[0].error
    assert "DB locked" in results[0].error


def test_run_trivy_missing_binary(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.14\n")
    with patch("security_scan.runners.image.shutil.which", return_value=None):
        results = image_runner.run(tmp_path, ImageScanConfig())
    assert results[0].completed is False
    assert "binary not found" in results[0].error


# -- mode C: built-image -----------------------------------------------------


def test_built_image_ref_scans_without_build(tmp_path):
    """When `ref` is set, we should NOT call docker; we should call trivy image
    against the ref directly."""
    seen_cmds: list[list[str]] = []

    def _fake_run(cmd, cwd, timeout=600):
        seen_cmds.append(cmd)
        return 0, json.dumps(_trivy_sarif_with(rule_id="CVE-built")), ""

    cfg = ImageScanConfig(
        base_images=False,
        built_image_enabled=True,
        built_image_ref="leverj/security-scan:latest",
    )
    with patch("security_scan.runners.image.shutil.which", return_value="/x/trivy"), \
         patch("security_scan.runners.image._run", side_effect=_fake_run), \
         patch("security_scan.runners.image.subprocess.run") as docker:
        results = image_runner.run(tmp_path, cfg)

    docker.assert_not_called()  # no `docker build`
    assert len(seen_cmds) == 1
    assert "leverj/security-scan:latest" == seen_cmds[0][-1]
    res = results[0].sarif["runs"][0]["results"][0]
    assert res["properties"]["security_scan_image_source"] == "built"


def test_built_image_build_locally_blocked_without_env(tmp_path, monkeypatch):
    """build_locally requires SECURITY_SCAN_ALLOW_BUILD=1 — otherwise we refuse
    to docker build the untrusted repo."""
    monkeypatch.delenv("SECURITY_SCAN_ALLOW_BUILD", raising=False)
    cfg = ImageScanConfig(
        base_images=False,
        built_image_enabled=True,
        build_locally=True,
    )
    with patch("security_scan.runners.image.subprocess.run") as docker:
        results = image_runner.run(tmp_path, cfg)
    docker.assert_not_called()
    assert results[0].completed is False
    assert "SECURITY_SCAN_ALLOW_BUILD" in results[0].error


def test_built_image_enabled_without_ref_or_build(tmp_path):
    cfg = ImageScanConfig(
        base_images=False,
        built_image_enabled=True,
        build_locally=False,
        built_image_ref=None,
    )
    results = image_runner.run(tmp_path, cfg)
    assert results[0].completed is False
    assert "neither `ref` nor `build_locally`" in results[0].error


def test_built_image_build_locally_happy_path(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_SCAN_ALLOW_BUILD", "1")
    (tmp_path / "Dockerfile").write_text("FROM python:3.14\n")

    import subprocess

    def _fake_subprocess_run(cmd, **kw):
        # First call: docker build, then docker rmi cleanup.
        if "build" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0,
                                               stdout="sha256:abc", stderr="")
        if "rmi" in cmd:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        raise AssertionError(f"unexpected docker invocation: {cmd}")

    def _fake_run(cmd, cwd, timeout=600):
        return 0, json.dumps(_trivy_sarif_with(rule_id="CVE-built-local")), ""

    cfg = ImageScanConfig(
        base_images=False,
        built_image_enabled=True,
        build_locally=True,
    )
    with patch("security_scan.runners.image.shutil.which", return_value="/x/bin"), \
         patch("security_scan.runners.image.subprocess.run", side_effect=_fake_subprocess_run), \
         patch("security_scan.runners.image._run", side_effect=_fake_run):
        results = image_runner.run(tmp_path, cfg)
    assert results[0].completed is True


def test_built_image_build_failure_surfaced(tmp_path, monkeypatch):
    monkeypatch.setenv("SECURITY_SCAN_ALLOW_BUILD", "1")
    (tmp_path / "Dockerfile").write_text("FROM python:3.14\nRUN exit 1\n")

    import subprocess

    def _fake_subprocess_run(cmd, **kw):
        return subprocess.CompletedProcess(args=cmd, returncode=2, stdout="",
                                           stderr="build failed: step 2")

    cfg = ImageScanConfig(
        base_images=False,
        built_image_enabled=True,
        build_locally=True,
    )
    with patch("security_scan.runners.image.shutil.which", return_value="/x/docker"), \
         patch("security_scan.runners.image.subprocess.run", side_effect=_fake_subprocess_run):
        results = image_runner.run(tmp_path, cfg)
    assert results[0].completed is False
    assert "docker build failed" in results[0].error


# -- normalize round-trip ----------------------------------------------------


def test_normalize_image_sarif_assigns_image_category(tmp_path):
    from security_scan.normalize import normalize_sarif

    sarif = _trivy_sarif_with()
    image_runner._tag_sarif(sarif, image_ref="python:3.14", source="base")
    findings = normalize_sarif(sarif, "image")
    assert len(findings) == 1
    assert findings[0].category == "image"
    assert findings[0].extra["image_ref"] == "python:3.14"
    assert findings[0].extra["image_source"] == "base"
