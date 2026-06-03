"""Config loader. YAML on disk; secrets via env (never on disk).

Fail-fast: missing required fields, missing env vars, or invalid severity_floor
raise ConfigError before any scanner runs.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from security_scan.models import SEVERITY_ORDER


class ConfigError(ValueError):
    """Bad config — surfaced to the user with a clear message."""


@dataclass
class ScannersConfig:
    osv: bool = True
    gitleaks: bool = True
    semgrep: bool = True
    trivy: bool = True          # comprehensive: vuln + secret + misconfig + license
    trufflehog: bool = True     # verified secrets (validates live tokens)
    syft: bool = True           # SBOM artifact (no project items filed)
    # Supply-chain risk via Socket.dev. Off by default — when enabled,
    # the repo's LOCKFILES are uploaded to socket.dev SaaS for analysis
    # (typosquat / install-script / capability / known-malware detection).
    # Source files never leave the box.
    supply_chain: bool = False


@dataclass
class BuiltImageConfig:
    """Mode C of the image-scan lane. Off by default.

    Two sub-modes (mutually exclusive):
      - `ref` — pull `<ref>` and scan it. Same trust boundary as `docker pull`.
      - `build_locally` — `docker build .` the cloned repo, then scan. Requires
        the docker socket mounted AND SECURITY_SCAN_ALLOW_BUILD=1 in env (since
        docker build executes the repo's RUN lines, breaking the
        "never execute repo code" invariant for this opt-in mode only).
    """
    enabled: bool = False
    ref: str | None = None
    build_locally: bool = False


@dataclass
class ImageScanConfig:
    """Container image scanning lane. Three modes (epic #9):
      A. Dockerfile audit  — handled by the existing trivy fs misconfig scanner.
      B. base_images       — `trivy image` over every FROM ref in the repo's
                             Dockerfiles. Default ON; cacheable.
      C. built_image       — opt-in pull-or-build + scan; see BuiltImageConfig.
    """
    base_images: bool = True
    built_image: BuiltImageConfig = field(default_factory=BuiltImageConfig)
    timeout: int = 600           # per `trivy image` call
    trivy_binary: str = "trivy"
    docker_binary: str = "docker"


@dataclass
class SupabaseConfig:
    """Live Supabase Security Advisor lane (epic #4).

    Off by default. When enabled, the scanner opens a read-only connection
    to the project's Postgres and runs Supabase Studio's lint queries
    against the live DB. Secrets resolve from env vars at runtime — never
    on disk.

    Two ways to provide credentials (use whichever your secrets pipeline
    already supports):

      1. `url_env`     — name of an env var holding a full DSN
                         (`postgres://user:pass@host:port/db`). Takes precedence.
      2. discrete envs — `host_env`, `db_env`, `user_env`, `password_env`,
                         plus optional `port` and `sslmode`.

    The recommended setup is a low-privilege read-only role:
      CREATE ROLE security_scanner LOGIN PASSWORD '...';
      GRANT pg_read_all_settings, pg_read_all_data TO security_scanner;
    """
    enabled: bool = False
    url_env: str | None = None
    host_env: str | None = None
    db_env: str | None = None
    user_env: str | None = None
    password_env: str | None = None
    port: int = 5432
    sslmode: str = "require"
    connect_timeout: int = 10
    query_timeout_ms: int = 30_000
    # Optional subset of lint check names (`supabase.<check>`) — None => all.
    checks: list[str] | None = None


@dataclass
class SupplyChainConfig:
    """Behavioral / reputation supply-chain analysis via Socket.dev.

    OSV-Scanner covers known-CVE dep findings. This lane covers what OSV
    can't see: typosquatted package names, install-script execution,
    capability escalations between versions, maintainer takeover,
    known-malicious packages.

    SaaS trust boundary: when enabled, the repo's LOCKFILES (not source
    files) are sent to socket.dev for analysis. The skill's upgrade flow
    surfaces this before flipping the flag on.
    """
    vendor: str = "socket"            # "socket" (only one supported today)
    binary: str = "socket"            # CLI on PATH inside the container
    api_key_env: str = "SOCKET_API_KEY"
    timeout: int = 600
    # Optional allow-list of Socket issue types to keep — empty means "all".
    # See https://socket.dev/docs/issue-types for the catalog.
    issue_types: list[str] = field(default_factory=list)


@dataclass
class PathsConfig:
    exclude: list[str] = field(default_factory=list)


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
    slack: SlackConfig
    image_scan: ImageScanConfig = field(default_factory=ImageScanConfig)
    supabase: SupabaseConfig = field(default_factory=SupabaseConfig)
    supply_chain: SupplyChainConfig = field(default_factory=SupplyChainConfig)
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
        supply_chain=bool(scanners_raw.get("supply_chain", False)),
    )

    img_raw = raw.get("image_scan") or {}
    built_raw = img_raw.get("built_image") or {}
    image_scan_cfg = ImageScanConfig(
        base_images=bool(img_raw.get("base_images", True)),
        built_image=BuiltImageConfig(
            enabled=bool(built_raw.get("enabled", False)),
            ref=(str(built_raw.get("ref")) if built_raw.get("ref") else None),
            build_locally=bool(built_raw.get("build_locally", False)),
        ),
        timeout=int(img_raw.get("timeout") or 600),
        trivy_binary=str(img_raw.get("trivy_binary") or "trivy"),
        docker_binary=str(img_raw.get("docker_binary") or "docker"),
    )

    sb_raw = raw.get("supabase") or {}
    sb_cfg = SupabaseConfig(
        enabled=bool(sb_raw.get("enabled", False)),
        url_env=(str(sb_raw.get("url_env")) if sb_raw.get("url_env") else None),
        host_env=(str(sb_raw.get("host_env")) if sb_raw.get("host_env") else None),
        db_env=(str(sb_raw.get("db_env")) if sb_raw.get("db_env") else None),
        user_env=(str(sb_raw.get("user_env")) if sb_raw.get("user_env") else None),
        password_env=(str(sb_raw.get("password_env")) if sb_raw.get("password_env") else None),
        port=int(sb_raw.get("port") or 5432),
        sslmode=str(sb_raw.get("sslmode") or "require"),
        connect_timeout=int(sb_raw.get("connect_timeout") or 10),
        query_timeout_ms=int(sb_raw.get("query_timeout_ms") or 30_000),
        checks=(list(sb_raw.get("checks")) if sb_raw.get("checks") else None),
    )
    if sb_cfg.enabled and not sb_cfg.url_env and not all(
        [sb_cfg.host_env, sb_cfg.db_env, sb_cfg.user_env, sb_cfg.password_env]
    ):
        raise ConfigError(
            "config: supabase.enabled=true but no credentials configured. "
            "Set either `url_env` (DSN) OR all of host_env/db_env/user_env/password_env."
        )

    sc_raw = raw.get("supply_chain") or {}
    sc_cfg = SupplyChainConfig(
        vendor=str(sc_raw.get("vendor") or "socket"),
        binary=str(sc_raw.get("binary") or "socket"),
        api_key_env=str(sc_raw.get("api_key_env") or "SOCKET_API_KEY"),
        timeout=int(sc_raw.get("timeout") or 600),
        issue_types=list(sc_raw.get("issue_types") or []),
    )
    if sc_cfg.vendor not in ("socket",):
        raise ConfigError(
            f"config: supply_chain.vendor must be 'socket' (got {sc_cfg.vendor!r}); "
            "future versions may add 'phylum'."
        )

    paths_raw = raw.get("paths") or {}
    paths = PathsConfig(exclude=list(paths_raw.get("exclude") or []))

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
        slack=slack,
        image_scan=image_scan_cfg,
        supabase=sb_cfg,
        supply_chain=sc_cfg,
        semgrep_rules_dir=raw.get("semgrep_rules_dir"),
    )
