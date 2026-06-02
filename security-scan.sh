#!/usr/bin/env bash
# Convenience wrapper for building and running the security-scan container.
#
#   ./security-scan.sh build              -> docker build the image
#   ./security-scan.sh run [args...]      -> docker run, default --dry-run, forwards extra args
#   ./security-scan.sh check              -> validate setup (config, secrets, docker, image)
#
# Two things are config-driven and read from config.yaml at runtime:
#
#   secrets.source        env | 1password   — how GITHUB_TOKEN (and Slack vars) are sourced
#   slack.enabled         bool              — whether to wire Slack at all
#   slack.webhook_url_env name              — env var holding the incoming webhook URL
#   slack.channel_id_env  name              — env var holding the channel id (chat.postMessage)
#   slack.bot_token_env   name              — env var holding the bot token (chat.postMessage)
#
# Required env (only when secrets.source=env):
#   GITHUB_TOKEN          PAT with repo scope on the target repo
# Required env (only when slack.enabled=true AND secrets.source=env):
#   the var named by slack.webhook_url_env  (or BOTH channel_id_env and bot_token_env)
#
# Config layout (bind-mounted as a single directory into the container):
#
#   config/config.yaml              # required — main settings
#   config/.env.1password.tpl       # optional — only when secrets.source=1password
#
# Default config directory: ./config/. Override with one of:
#   --config /path/to/cfg.yaml     # explicit file path (its parent dir is mounted)
#   SECURITY_SCAN_CONFIG=...             # same thing via env var
#   SECURITY_SCAN_CONFIG_DIR=...         # mount this dir instead; expects config.yaml inside
#
# When the skill packages security-scan, point SECURITY_SCAN_CONFIG_DIR at the per-project
# config the agent maintains for the user.

set -euo pipefail

IMAGE="${SECURITY_SCAN_IMAGE:-security-scan:latest}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_CONFIG_DIR="$HERE/config"

die() { echo "error: $*" >&2; exit 1; }
warn() { echo "warning: $*" >&2; }

# Resolve a python that can `import yaml` — needed to read the config's secrets block.
pick_python() {
  if [[ -x "$HERE/.venv/bin/python" ]]; then
    echo "$HERE/.venv/bin/python"
  elif command -v python3 >/dev/null; then
    echo "python3"
  else
    die "need python3 to parse config.yaml"
  fi
}

# read_config_field <config-path> <dotted.key> [default]
# Echoes the value or `default` if missing/empty. Returns 0 always.
read_config_field() {
  local cfg="$1" key="$2" default="${3:-}"
  local py; py="$(pick_python)"
  "$py" - "$cfg" "$key" "$default" <<'PYEOF' 2>/dev/null || echo "$default"
import sys
try:
    import yaml
except ImportError:
    print(sys.argv[3]); sys.exit(0)
try:
    with open(sys.argv[1]) as f:
        d = yaml.safe_load(f) or {}
    v = d
    for p in sys.argv[2].split('.'):
        if not isinstance(v, dict):
            v = None
            break
        v = v.get(p)
    print(v if v not in (None, "") else sys.argv[3])
except Exception:
    print(sys.argv[3])
PYEOF
}

# is_truthy <string> — handles yaml-ish bool spellings
is_truthy() {
  case "${1,,}" in true|yes|on|1) return 0 ;; *) return 1 ;; esac
}

# Build the docker -e flags from configured slack vars. Sets globals:
#   ENV_VARS_TO_FORWARD   array of env var names (e.g. GITHUB_TOKEN SLACK_WEBHOOK_URL)
#   SLACK_MODE            "off" | "webhook:<var>" | "chat:<chan>+<tok>"
#   SLACK_REQUIRED_VARS   array of var names that MUST be non-empty for slack.enabled
plan_env_forwarding() {
  local cfg="$1"
  ENV_VARS_TO_FORWARD=(GITHUB_TOKEN)
  SLACK_REQUIRED_VARS=()
  SLACK_MODE="off"

  local slack_enabled webhook_var channel_var bot_var
  slack_enabled="$(read_config_field "$cfg" "slack.enabled" "false")"
  if ! is_truthy "$slack_enabled"; then
    return 0
  fi

  webhook_var="$(read_config_field "$cfg" "slack.webhook_url_env" "")"
  channel_var="$(read_config_field "$cfg" "slack.channel_id_env" "")"
  bot_var="$(read_config_field "$cfg" "slack.bot_token_env" "")"

  if [[ -n "$webhook_var" ]]; then
    ENV_VARS_TO_FORWARD+=("$webhook_var")
    SLACK_REQUIRED_VARS+=("$webhook_var")
    SLACK_MODE="webhook:$webhook_var"
  elif [[ -n "$channel_var" && -n "$bot_var" ]]; then
    ENV_VARS_TO_FORWARD+=("$channel_var" "$bot_var")
    SLACK_REQUIRED_VARS+=("$channel_var" "$bot_var")
    SLACK_MODE="chat:$channel_var+$bot_var"
  else
    warn "slack.enabled=true but neither slack.webhook_url_env nor (channel_id_env + bot_token_env) is set in $cfg; Slack will be skipped"
  fi
}

cmd_build() {
  command -v docker >/dev/null || die "docker not on PATH"
  echo "building $IMAGE from $HERE ..."
  docker build -t "$IMAGE" "$HERE"
  echo "done: $IMAGE"
}

# read_version_from <file> <regex>
# Pulls the first match of <regex> from <file>, returns just the captured version.
read_version_from() {
  local file="$1" pattern="$2"
  [[ -f "$file" ]] || die "missing file: $file"
  grep -E "$pattern" "$file" | head -1 | sed -E 's/.*"([^"]+)".*/\1/'
}

cmd_publish() {
  command -v docker >/dev/null || die "docker not on PATH"

  local tag=""
  local push=1
  local multi_arch=1
  local repo="leverj/security-scan"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --no-push)      push=0; shift ;;
      --single-arch)  multi_arch=0; shift ;;
      --repo)         repo="$2"; shift 2 ;;
      --repo=*)       repo="${1#--repo=}"; shift ;;
      v[0-9]*|[0-9]*) tag="$1"; shift ;;
      -h|--help)
        cat <<EOH
usage: ./security-scan.sh publish [vX.Y.Z] [--no-push] [--single-arch] [--repo <user/image>]

Build and push the docker image to Docker Hub. Assumes you've already run
\`docker login\` in this shell (push uses the existing credentials).

  vX.Y.Z          override the tag. Default: derived from SECURITY-SCAN-MANIFEST.yaml
                  (with a 'v' prefix). When omitted, the script verifies that
                  pyproject.toml's version matches the manifest's.

  --no-push       build + tag locally; do NOT push. Useful to dry-run a release.
  --single-arch   build only for the host architecture (skip multi-arch buildx).
                  Default: linux/amd64 + linux/arm64.
  --repo          override the image repo. Default: leverj/security-scan.
EOH
        return 0 ;;
      *) die "publish: unknown argument: $1 (try --help)" ;;
    esac
  done

  # Resolve the tag.
  if [[ -z "$tag" ]]; then
    local py_version mf_version
    py_version="$(read_version_from "$HERE/pyproject.toml" '^version\s*=')"
    mf_version="$(read_version_from "$HERE/SECURITY-SCAN-MANIFEST.yaml" '^version:')"
    if [[ -z "$py_version" || -z "$mf_version" ]]; then
      die "could not read version from pyproject.toml or SECURITY-SCAN-MANIFEST.yaml"
    fi
    if [[ "$py_version" != "$mf_version" ]]; then
      die "version mismatch — pyproject.toml: $py_version  vs  manifest: $mf_version. Align them, then re-run."
    fi
    tag="v$py_version"
    echo "publish: resolved tag $tag from pyproject.toml + manifest"
  else
    echo "publish: using explicit tag $tag (skipping version-alignment check)"
  fi

  # Sanity: the version-stripped tag should match what's in the manifest if no override.
  local image_versioned="$repo:$tag"
  local image_latest="$repo:latest"

  if (( multi_arch )); then
    if ! docker buildx version >/dev/null 2>&1; then
      die "docker buildx not available — pass --single-arch, or set up buildx (https://docs.docker.com/build/architecture/)"
    fi
    # Ensure a builder that supports multi-platform exists / is current.
    local builder; builder="$(docker buildx inspect --bootstrap 2>/dev/null | grep -E '^Name:' | head -1 | awk '{print $2}')"
    echo "publish: using buildx builder: ${builder:-default}"
  fi

  local plat_msg="host-only" push_msg="no (--no-push)"
  (( multi_arch )) && plat_msg="linux/amd64,linux/arm64"
  (( push )) && push_msg="yes"
  echo
  echo "  repo:      $repo"
  echo "  tags:      $tag, latest"
  echo "  platforms: $plat_msg"
  echo "  push:      $push_msg"
  echo

  if (( push )); then
    # Confirm a real publish.
    read -r -p "publish $image_versioned + $image_latest to Docker Hub? [yes/no] " ans
    [[ "$ans" == "yes" ]] || { echo "aborted."; return 1; }
  fi

  if (( multi_arch )); then
    # `--load` doesn't support multi-arch (single-image local load only); for
    # --no-push we just build to the buildx cache without exporting, which still
    # exercises the full build and proves it would push cleanly.
    #
    # `--sbom=true` and `--provenance=mode=max` attach a CycloneDX SBOM and
    # SLSA build provenance to the manifest list — these are what Docker Scout's
    # "Missing supply chain attestation(s)" check looks for.
    local export_args=()
    (( push )) && export_args=(--push)
    docker buildx build \
      --platform linux/amd64,linux/arm64 \
      --sbom=true \
      --provenance=mode=max \
      -t "$image_versioned" \
      -t "$image_latest" \
      "${export_args[@]}" \
      "$HERE"
  else
    docker build -t "$image_versioned" -t "$image_latest" "$HERE"
    if (( push )); then
      docker push "$image_versioned"
      docker push "$image_latest"
    fi
  fi

  echo
  if (( push )); then
    echo "published: $image_versioned + $image_latest"
    # Smoke-test the manifest is readable from the just-pushed tag.
    echo "smoke test: extracting manifest from the pushed image..."
    docker run --rm --entrypoint cat "$image_versioned" /app/SECURITY-SCAN-MANIFEST.yaml | head -5
  else
    echo "built locally (not pushed): $image_versioned + $image_latest"
  fi
}

cmd_check() {
  local config_dir="${SECURITY_SCAN_CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
  local config="${SECURITY_SCAN_CONFIG:-$config_dir/config.yaml}"
  local ok=1

  echo "== config =="
  if [[ -f "$config" ]]; then
    echo "  ✓ $config"
  else
    echo "  ✗ $config (cp config/config.example.yaml config/config.yaml)"
    ok=0
  fi

  echo "== docker =="
  if command -v docker >/dev/null; then
    if docker info >/dev/null 2>&1; then
      echo "  ✓ docker is running"
    else
      echo "  ✗ docker installed but daemon not reachable (is Docker Desktop running?)"
      ok=0
    fi
  else
    echo "  ✗ docker not on PATH (install Docker Desktop or `brew install --cask docker`)"
    ok=0
  fi

  echo "== image =="
  if docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "  ✓ $IMAGE present"
  else
    echo "  ⚠ $IMAGE not built yet — run: ./security-scan.sh build"
  fi

  if [[ -f "$config" ]]; then
    local secrets_source slack_enabled
    secrets_source="$(read_config_field "$config" "secrets.source" "env")"
    slack_enabled="$(read_config_field "$config" "slack.enabled" "false")"
    plan_env_forwarding "$config"

    echo "== secrets ($secrets_source) =="
    case "$secrets_source" in
      env)
        local missing=()
        [[ -n "${GITHUB_TOKEN:-}" ]] && echo "  ✓ GITHUB_TOKEN set" || { echo "  ✗ GITHUB_TOKEN unset (export it)"; missing+=(GITHUB_TOKEN); ok=0; }
        for v in "${SLACK_REQUIRED_VARS[@]+"${SLACK_REQUIRED_VARS[@]}"}"; do
          if [[ -n "${!v:-}" ]]; then
            echo "  ✓ $v set"
          else
            echo "  ✗ $v unset (slack.enabled=true requires this)"
            missing+=("$v")
            ok=0
          fi
        done
        ;;
      1password|1Password|op)
        local ef; ef="$(read_config_field "$config" "secrets.env_file" ".env.1password.tpl")"
        # Resolve env_file relative to the config directory (so the whole config/
        # dir is the unit of bind-mount).
        [[ "$ef" = /* ]] || ef="$config_dir/$ef"
        if command -v op >/dev/null; then echo "  ✓ op (1Password CLI) installed"; else echo "  ✗ op not installed (brew install 1password-cli)"; ok=0; fi
        if op account list >/dev/null 2>&1; then echo "  ✓ op signed in"; else echo "  ⚠ op not signed in (run: op signin)"; fi
        if [[ -f "$ef" ]]; then echo "  ✓ $ef present"; else echo "  ✗ $ef missing (cp config/.env.1password.tpl.example config/.env.1password.tpl)"; ok=0; fi
        ;;
      *)
        echo "  ✗ secrets.source must be 'env' or '1password', got: $secrets_source"
        ok=0
        ;;
    esac

    echo "== slack =="
    if is_truthy "$slack_enabled"; then
      echo "  ✓ enabled — mode: $SLACK_MODE"
    else
      echo "  · disabled"
    fi
  fi

  echo
  if [[ $ok -eq 1 ]]; then
    echo "all good. try: ./security-scan.sh run"
    return 0
  else
    echo "fix the ✗ items above, then re-run ./security-scan.sh check"
    return 1
  fi
}

cmd_run() {
  command -v docker >/dev/null || die "docker not on PATH"

  local config_dir="${SECURITY_SCAN_CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
  local config="${SECURITY_SCAN_CONFIG:-$config_dir/config.yaml}"
  local extra_args=()
  local have_dry_run=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config) config="$2"; config_dir="$(dirname "$2")"; shift 2 ;;
      --config=*) config="${1#--config=}"; config_dir="$(dirname "$config")"; shift ;;
      --config-dir) config_dir="$2"; config="$2/config.yaml"; shift 2 ;;
      --config-dir=*) config_dir="${1#--config-dir=}"; config="$config_dir/config.yaml"; shift ;;
      --dry-run) have_dry_run=1; extra_args+=("$1"); shift ;;
      --) shift; extra_args+=("$@"); break ;;
      *) extra_args+=("$1"); shift ;;
    esac
  done
  # Canonicalize.
  config_dir="$(cd "$config_dir" 2>/dev/null && pwd || echo "$config_dir")"

  # Default to --dry-run unless the caller asked for the real path. Build a new
  # array so `--no-dry-run` is removed cleanly (rather than replaced with "").
  if [[ $have_dry_run -eq 0 ]]; then
    local has_no_dry=0 filtered=()
    for a in "${extra_args[@]+"${extra_args[@]}"}"; do
      if [[ "$a" == "--no-dry-run" ]]; then
        has_no_dry=1
      else
        filtered+=("$a")
      fi
    done
    if [[ $has_no_dry -eq 0 ]]; then
      filtered=(--dry-run "${filtered[@]+"${filtered[@]}"}")
      echo "note: defaulting to --dry-run (pass --no-dry-run to actually create issues)" >&2
    fi
    extra_args=("${filtered[@]+"${filtered[@]}"}")
  fi

  if [[ ! -f "$config" ]]; then
    cat >&2 <<EOF
error: config not found at $config

To set up:
  cp config/config.example.yaml config/config.yaml
  \$EDITOR config/config.yaml          # set repo, ref, project, secrets.source

See README.md ("Setup: secrets") for env-vs-1Password choice.
Or set SECURITY_SCAN_CONFIG_DIR=/path/to/your-config-dir to use a different directory.
EOF
    exit 1
  fi

  local secrets_source env_file
  secrets_source="$(read_config_field "$config" "secrets.source" "env")"
  env_file="$(read_config_field "$config" "secrets.env_file" ".env.1password.tpl")"

  # Decide which env vars to forward into the container, based on slack config.
  plan_env_forwarding "$config"

  # IMPORTANT: pass `-e VAR` (no value) so the secret is read from this shell's
  # env by docker, not interpolated into argv where `ps` would show it.
  local env_args=()
  for v in "${ENV_VARS_TO_FORWARD[@]}"; do
    env_args+=(-e "$v")
  done

  # Build the final command. With secrets.source=1password, the *outer* op run
  # populates this shell's env, then docker copies the values from env into the
  # container — so neither token nor URL appears on docker's argv.
  case "$secrets_source" in
    env)
      if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        cat >&2 <<EOF
error: GITHUB_TOKEN not set in your shell (secrets.source=env in $config)

Two ways to fix this:

  1) Export it now:
       export GITHUB_TOKEN=github_pat_xxx       # see README.md "Option A"
       ./security-scan.sh run

  2) Switch to 1Password (recommended for daily use):
       # in config.yaml
       secrets:
         source: "1password"
         env_file: ".env.1password.tpl"
       # then:
       cp .env.1password.tpl.example .env.1password.tpl
       \$EDITOR .env.1password.tpl               # set op:// vault paths
       ./security-scan.sh run

Run \`./security-scan.sh check\` to see your full setup status.
EOF
        exit 1
      fi
      local missing_slack=()
      for v in "${SLACK_REQUIRED_VARS[@]+"${SLACK_REQUIRED_VARS[@]}"}"; do
        [[ -z "${!v:-}" ]] && missing_slack+=("$v")
      done
      if [[ ${#missing_slack[@]} -gt 0 ]]; then
        cat >&2 <<EOF
error: slack.enabled=true but these vars are unset in your shell: ${missing_slack[*]}

Either export them:
  export ${missing_slack[0]}=...

…or set slack.enabled: false in $config to disable Slack for this run.

Run \`./security-scan.sh check\` to see your full setup status.
EOF
        exit 1
      fi
      echo "secrets: env (shell exports)  slack: $SLACK_MODE  config-dir: $config_dir" >&2
      exec docker run --rm \
        -v "$config_dir":/config:ro \
        "${env_args[@]}" \
        "$IMAGE" "${extra_args[@]+"${extra_args[@]}"}"
      ;;
    1password|1Password|op)
      if ! command -v op >/dev/null; then
        cat >&2 <<EOF
error: 1Password CLI (op) not on PATH but secrets.source=1password in $config

Install it:
  brew install 1password-cli
  op signin

Or switch to plain env vars by setting \`secrets.source: "env"\` in $config.
EOF
        exit 1
      fi
      local ef="$env_file"
      [[ "$ef" = /* ]] || ef="$config_dir/$ef"
      if [[ ! -f "$ef" ]]; then
        cat >&2 <<EOF
error: secrets env file not found: $ef

Create it from the committed template:
  cp config/.env.1password.tpl.example config/.env.1password.tpl
  \$EDITOR config/.env.1password.tpl        # set op://<vault>/<item>/<field> paths

The template lists every env var security-scan understands.
EOF
        exit 1
      fi
      if [[ ${#SLACK_REQUIRED_VARS[@]} -gt 0 ]]; then
        # Best-effort sanity check: warn if the Slack vars aren't referenced in the env file.
        for v in "${SLACK_REQUIRED_VARS[@]}"; do
          grep -qE "^\s*${v}\s*=" "$ef" || warn "$v not referenced in $ef but slack.enabled=true; add 'op://...' line or set slack.enabled: false"
        done
      fi
      echo "secrets: 1password ($ef)  slack: $SLACK_MODE  config-dir: $config_dir" >&2
      exec op run --env-file="$ef" -- docker run --rm \
        -v "$config_dir":/config:ro \
        "${env_args[@]}" \
        "$IMAGE" "${extra_args[@]+"${extra_args[@]}"}"
      ;;
    *)
      die "secrets.source must be 'env' or '1password' in $config, got: $secrets_source"
      ;;
  esac
}

case "${1:-}" in
  build)   shift; cmd_build "$@" ;;
  run)     shift; cmd_run "$@" ;;
  check)   shift; cmd_check "$@" ;;
  publish) shift; cmd_publish "$@" ;;
  ""|-h|--help)
    cat <<EOF
security-scan.sh — build/run/publish the security-scan container

usage:
  ./security-scan.sh build
  ./security-scan.sh run [--config path/to/config.yaml]
                         [--config-dir path/to/config_dir]
                         [--dry-run|--no-dry-run]
                         [extra security-scan args...]
  ./security-scan.sh check
  ./security-scan.sh publish [vX.Y.Z] [--no-push] [--single-arch] [--repo user/img]
                         # builds + pushes multi-arch to Docker Hub.
                         # Run \`docker login\` first; uses your existing creds.

defaults:
  --dry-run is added unless you pass --no-dry-run
  --config-dir defaults to ./config/ (override with SECURITY_SCAN_CONFIG_DIR env)
  --config defaults to <config-dir>/config.yaml (override with SECURITY_SCAN_CONFIG env)
  image tag defaults to "security-scan:latest" (override with SECURITY_SCAN_IMAGE env)

The whole --config-dir is bind-mounted read-only at /config inside the container,
so any related files (the 1Password env template, etc.) ride along.

secrets (driven by config.yaml):
  secrets.source: env        -> use already-exported shell variables
  secrets.source: 1password  -> auto-wrap with \`op run --env-file=<env_file>\`

  GITHUB_TOKEN is always required.

slack (driven by config.yaml):
  slack.enabled: false       -> Slack is off; no extra env needed
  slack.enabled: true with slack.webhook_url_env: "VAR"
                             -> the named VAR (typically SLACK_WEBHOOK_URL) must be set
  slack.enabled: true with slack.channel_id_env + slack.bot_token_env
                             -> both named vars must be set (uses chat.postMessage)

Run \`./security-scan.sh check\` for a full setup status.
EOF
    ;;
  *) die "unknown command: $1 (try 'build', 'run', 'check', or 'publish')" ;;
esac
