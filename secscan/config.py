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
    # Cold-start of a ~17 GB Gemma model can take several minutes the first time
    # of the day. Subsequent calls are fast thanks to keep_alive. 600s tolerates
    # the cold case for fuzzy-dedup + prose generation.
    timeout: int = 600
    # If True, kick off a model-warming request in a BACKGROUND thread when
    # Triage is constructed. Scans run while the model loads; by the time we
    # need the Slack intro the model is hot. Strongly recommended for large models.
    prewarm: bool = True
    # Intro generation runs at the end of the pipeline. Cap it separately and
    # shorter than `timeout`: if Gemma can't produce a one-liner in this window
    # we skip the intro and post the structured digest without it. Default 120s.
    intro_timeout: int = 120
    # Granular feature flags. Each defaults to a sensible value so flipping
    # `enabled: true` doesn't accidentally explode runtime.
    #
    #   intro      — one short Gemma-written sentence prepended to the Slack
    #                digest. Cheap: 1 chat call at the end of the run.
    #   prose      — Gemma rewrites issue title/body for each NEW finding.
    #                Expensive: 1 chat call per new finding. Off by default.
    #   fuzzy_dup  — Gemma decides whether a new finding is a fuzzy match for
    #                an existing issue at a different path/name. Expensive:
    #                1 chat call per new (post-fp-dedup) finding. Off by default.
    intro_enabled: bool = True
    prose_enabled: bool = False
    fuzzy_dup_enabled: bool = False


@dataclass
class SlackConfig:
    enabled: bool = False
    channel_id_env: str | None = None
    webhook_url_env: str | None = None
    bot_token_env: str | None = None


@dataclass
class ProjectConfig:
    """Target GitHub Projects v2 board. Findings file as flat items here — no
    parent/child epic relationship. The owner is the org or user that owns the
    project; `number` is the project number from the URL (`/projects/<number>`).
    """
    owner: str
    number: int


@dataclass
class Config:
    repo: str
    ref: str
    project: ProjectConfig
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

    project_raw = raw.get("project") or {}
    if not isinstance(project_raw, dict):
        raise ConfigError("config: 'project' must be a mapping with 'owner' and 'number'")
    project_owner = str(_require(project_raw, "owner", "project"))
    try:
        project_number = int(_require(project_raw, "number", "project"))
    except (TypeError, ValueError) as e:
        raise ConfigError(f"config: 'project.number' must be an integer: {e}") from e
    project = ProjectConfig(owner=project_owner, number=project_number)

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
    try:
        triage_timeout = int(triage_raw.get("timeout") or 600)
    except (TypeError, ValueError):
        triage_timeout = 600
    try:
        intro_timeout = int(triage_raw.get("intro_timeout") or 120)
    except (TypeError, ValueError):
        intro_timeout = 120
    triage = TriageConfig(
        enabled=bool(triage_raw.get("enabled", False)),
        provider=str(triage_raw.get("provider") or "ollama"),
        model=str(triage_raw.get("model") or "gemma4:26b"),
        base_url=str(triage_raw.get("base_url") or "http://host.docker.internal:11434"),
        keep_alive=str(triage_raw.get("keep_alive") or "5m"),
        timeout=triage_timeout,
        prewarm=bool(triage_raw.get("prewarm", True)),
        intro_timeout=intro_timeout,
        intro_enabled=bool(triage_raw.get("intro_enabled", True)),
        prose_enabled=bool(triage_raw.get("prose_enabled", False)),
        fuzzy_dup_enabled=bool(triage_raw.get("fuzzy_dup_enabled", False)),
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
        project=project,
        github_token=token,
        scanners=scanners,
        paths=paths,
        severity_floor=floor,
        triage=triage,
        slack=slack,
        semgrep_rules_dir=raw.get("semgrep_rules_dir"),
    )
