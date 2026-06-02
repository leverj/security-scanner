
import pytest

from security_scan.config import ConfigError, load_config


def write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    return p


def test_load_minimal_config(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake")
    p = write(tmp_path, "c.yaml", """
repo: "leverj/ezel"
ref: "dev"
project:
  owner: "leverj"
  number: 5
""")
    cfg = load_config(p)
    assert cfg.repo == "leverj/ezel"
    assert cfg.repo_owner == "leverj"
    assert cfg.repo_name == "ezel"
    assert cfg.project.owner == "leverj"
    assert cfg.project.number == 5
    assert cfg.severity_floor == "low"
    assert cfg.scanners.osv and cfg.scanners.gitleaks and cfg.scanners.semgrep
    assert cfg.github_token == "ghp_fake"


def test_load_full_config(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_fake")
    p = write(tmp_path, "c.yaml", """
repo: "owner/name"
ref: "main"
project:
  owner: "owner"
  number: 1
scanners: {osv: false, gitleaks: true, semgrep: false}
paths: {exclude: ["a/", "b/"]}
severity_floor: "high"
triage: {enabled: true, model: "gemma4:9b"}
slack: {enabled: true, webhook_url_env: "SLACK_WEBHOOK_URL"}
""")
    cfg = load_config(p)
    assert cfg.scanners.osv is False
    assert cfg.scanners.semgrep is False
    assert cfg.paths.exclude == ["a/", "b/"]
    assert cfg.severity_floor == "high"
    assert cfg.triage.enabled is True
    assert cfg.triage.model == "gemma4:9b"
    assert cfg.slack.enabled is True
    assert cfg.project.owner == "owner"
    assert cfg.project.number == 1


def test_missing_token_env_fails_fast(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    p = write(tmp_path, "c.yaml", """
repo: "leverj/ezel"
ref: "dev"
project: {owner: "leverj", number: 5}
""")
    with pytest.raises(ConfigError, match="GITHUB_TOKEN"):
        load_config(p)


def test_bad_repo_format_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    p = write(tmp_path, "c.yaml", """
repo: "not-a-slash"
ref: "dev"
project: {owner: "x", number: 1}
""")
    with pytest.raises(ConfigError, match="owner/name"):
        load_config(p)


def test_bad_severity_floor_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    p = write(tmp_path, "c.yaml", """
repo: "o/n"
ref: "dev"
project: {owner: "o", number: 1}
severity_floor: "bogus"
""")
    with pytest.raises(ConfigError, match="severity_floor"):
        load_config(p)


def test_missing_project_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    p = write(tmp_path, "c.yaml", """
repo: "o/n"
ref: "dev"
""")
    with pytest.raises(ConfigError, match="project"):
        load_config(p)


def test_missing_project_number_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    p = write(tmp_path, "c.yaml", """
repo: "o/n"
ref: "dev"
project: {owner: "o"}
""")
    with pytest.raises(ConfigError, match="project.number"):
        load_config(p)


def test_missing_project_owner_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    p = write(tmp_path, "c.yaml", """
repo: "o/n"
ref: "dev"
project: {number: 1}
""")
    with pytest.raises(ConfigError, match="project.owner"):
        load_config(p)


def test_non_integer_project_number_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "x")
    p = write(tmp_path, "c.yaml", """
repo: "o/n"
ref: "dev"
project: {owner: "o", number: "not-a-number"}
""")
    with pytest.raises(ConfigError, match="project.number"):
        load_config(p)


def test_missing_file_fails(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")
