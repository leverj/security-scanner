"""Config loader. YAML on disk; secrets via env (never on disk).

Fail-fast: missing required fields, missing env vars, or invalid severity_floor
raise ConfigError before any scanner runs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from secscan.models import SEVERITY_ORDER


class ConfigError(ValueError):
    """Bad config — surfaced to the user with a clear message."""


@dataclass
class ScannersConfig:
    osv: bool = True
    gitleaks: bool = True
    semgrep: bool = True
    trivy: bool = True          # comprehensive: vuln + secret + misconfig + license
    trufflehog: bool = True     # verified secrets (validates live tokens)
    syft: bool = True           # SBOM artifact (no sub-issues filed)


@dataclass
class PathsConfig:
    exclude: list[str] = field(default_factory=list)


@dataclass
class TriageConfig:
    enabled: bool = False
    provider: str = "ollama"
    model: str = "gemma4:26b"
    base_url: str = "http://host.docker.internal:11434"
    keep_alive: str = "5m"


@dataclass
class SlackConfig:
    enabled: bool = False
    channel_id_env: str | None = None
    webhook_url_env: str | None = None
    bot_token_env: str | None = None


@dataclass
class Config:
    repo: str
    ref: str
    parent_issue: int
    github_token: str  # resolved from env; never logged
    scanners: ScannersConfig
    paths: PathsConfig
    severity_floor: str
    triage: TriageConfig
    slack: SlackConfig
    # bundled defaults
    semgrep_rules_dir: str | None = None

    @property
    def repo_owner(self) -> str:
        return self.repo.split("/", 1)[0]

    @property
    def repo_name(self) -> str:
        return self.repo.split("/", 1)[1]


def _require(d: dict, key: str, path: str) -> object:
    if key not in d or d[key] in (None, ""):
        raise ConfigError(f"config: missing required field '{path}.{key}'" if path else f"config: missing required field '{key}'")
    return d[key]


def load_config(path: str | Path) -> Config:
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config: file not found: {p}")
    raw = yaml.safe_load(p.read_text()) or {}
    return _from_dict(raw)


def _from_dict(raw: dict) -> Config:
    repo = str(_require(raw, "repo", ""))
    if "/" not in repo:
        raise ConfigError(f"config: 'repo' must be 'owner/name', got: {repo!r}")
    ref = str(_require(raw, "ref", ""))
    try:
        parent_issue = int(_require(raw, "parent_issue", ""))
    except (TypeError, ValueError) as e:
        raise ConfigError(f"config: 'parent_issue' must be an integer: {e}") from e

    token_env = str(raw.get("github_token_env") or "GITHUB_TOKEN")
    token = os.environ.get(token_env, "")
    if not token:
        raise ConfigError(f"config: env var '{token_env}' is empty or unset (holds the GitHub PAT)")

    floor = str(raw.get("severity_floor") or "low").lower()
    if floor not in SEVERITY_ORDER:
        raise ConfigError(f"config: severity_floor must be one of {list(SEVERITY_ORDER)}, got {floor!r}")

    scanners_raw = raw.get("scanners") or {}
    scanners = ScannersConfig(
        osv=bool(scanners_raw.get("osv", True)),
        gitleaks=bool(scanners_raw.get("gitleaks", True)),
        semgrep=bool(scanners_raw.get("semgrep", True)),
        trivy=bool(scanners_raw.get("trivy", True)),
        trufflehog=bool(scanners_raw.get("trufflehog", True)),
        syft=bool(scanners_raw.get("syft", True)),
    )

    paths_raw = raw.get("paths") or {}
    paths = PathsConfig(exclude=list(paths_raw.get("exclude") or []))

    triage_raw = raw.get("triage") or {}
    triage = TriageConfig(
        enabled=bool(triage_raw.get("enabled", False)),
        provider=str(triage_raw.get("provider") or "ollama"),
        model=str(triage_raw.get("model") or "gemma4:26b"),
        base_url=str(triage_raw.get("base_url") or "http://host.docker.internal:11434"),
        keep_alive=str(triage_raw.get("keep_alive") or "5m"),
    )

    slack_raw = raw.get("slack") or {}
    slack = SlackConfig(
        enabled=bool(slack_raw.get("enabled", False)),
        channel_id_env=slack_raw.get("channel_id_env"),
        webhook_url_env=slack_raw.get("webhook_url_env"),
        bot_token_env=slack_raw.get("bot_token_env") or "SLACK_BOT_TOKEN",
    )

    return Config(
        repo=repo,
        ref=ref,
        parent_issue=parent_issue,
        github_token=token,
        scanners=scanners,
        paths=paths,
        severity_floor=floor,
        triage=triage,
        slack=slack,
        semgrep_rules_dir=raw.get("semgrep_rules_dir"),
    )
