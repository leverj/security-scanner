#!/usr/bin/env bash
# Convenience wrapper for building and running the secscan container.
#
#   ./secscan.sh build              -> docker build the image
#   ./secscan.sh run [args...]      -> docker run, default --dry-run, forwards extra args
#
# Secret sourcing is controlled by `secrets.source` in config.yaml:
#   source: env         -> assumes GITHUB_TOKEN (etc.) are already exported in your shell
#   source: 1password   -> auto-prefixes the command with `op run --env-file=<env_file>`
#
# Optional env (forwarded into the container if set):
#   SLACK_WEBHOOK_URL, SLACK_BOT_TOKEN, SLACK_CHANNEL_ID
#
# Config: defaults to ./config.yaml; override with `--config /path/to/cfg.yaml` before
# any other args, or set SECSCAN_CONFIG=... in env.

set -euo pipefail

IMAGE="${SECSCAN_IMAGE:-secscan:latest}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }

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

cmd_build() {
  command -v docker >/dev/null || die "docker not on PATH"
  echo "building $IMAGE from $HERE ..."
  docker build -t "$IMAGE" "$HERE"
  echo "done: $IMAGE"
}

cmd_run() {
  command -v docker >/dev/null || die "docker not on PATH"

  local config="${SECSCAN_CONFIG:-$HERE/config.yaml}"
  local extra_args=()
  local have_dry_run=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config) config="$2"; shift 2 ;;
      --config=*) config="${1#--config=}"; shift ;;
      --dry-run) have_dry_run=1; extra_args+=("$1"); shift ;;
      --) shift; extra_args+=("$@"); break ;;
      *) extra_args+=("$1"); shift ;;
    esac
  done

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

  [[ -f "$config" ]] || die "config not found: $config (copy config.example.yaml to config.yaml)"

  local secrets_source env_file
  secrets_source="$(read_config_field "$config" "secrets.source" "env")"
  env_file="$(read_config_field "$config" "secrets.env_file" ".env.1password.tpl")"

  # IMPORTANT: pass `-e VAR` (no value) so the secret is read from this shell's
  # env by docker, not interpolated into argv where `ps` would show it.
  local env_args=(-e GITHUB_TOKEN)
  for var in SLACK_WEBHOOK_URL SLACK_BOT_TOKEN SLACK_CHANNEL_ID; do
    env_args+=(-e "$var")
  done

  # Build the final command. With secrets.source=1password, the *outer* op run
  # populates this shell's env, then docker copies the values from env into the
  # container — so neither token nor URL appears on docker's argv.
  case "$secrets_source" in
    env)
      [[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN env var is required (secrets.source=env in config)"
      echo "secrets: env (using already-exported shell variables)" >&2
      exec docker run --rm \
        -v "$config":/config/config.yaml:ro \
        "${env_args[@]}" \
        "$IMAGE" "${extra_args[@]+"${extra_args[@]}"}"
      ;;
    1password|1Password|op)
      command -v op >/dev/null || die "1Password CLI (op) not on PATH; install: brew install 1password-cli"
      local ef="$env_file"
      [[ "$ef" = /* ]] || ef="$HERE/$ef"
      [[ -f "$ef" ]] || die "secrets env file not found: $ef"
      echo "secrets: 1password (op run --env-file=$ef)" >&2
      exec op run --env-file="$ef" -- docker run --rm \
        -v "$config":/config/config.yaml:ro \
        "${env_args[@]}" \
        "$IMAGE" "${extra_args[@]+"${extra_args[@]}"}"
      ;;
    *)
      die "secrets.source must be 'env' or '1password', got: $secrets_source"
      ;;
  esac
}

case "${1:-}" in
  build) shift; cmd_build "$@" ;;
  run)   shift; cmd_run "$@" ;;
  ""|-h|--help)
    cat <<EOF
secscan.sh — build/run the secscan container

usage:
  ./secscan.sh build
  ./secscan.sh run [--config path/to/config.yaml] [--dry-run|--no-dry-run] [extra secscan args...]

defaults:
  --dry-run is added unless you pass --no-dry-run
  --config defaults to ./config.yaml (override with SECSCAN_CONFIG env)
  image tag defaults to "secscan:latest" (override with SECSCAN_IMAGE env)

secrets:
  Driven by config.yaml's \`secrets.source\` field:
    env        -> use GITHUB_TOKEN (and SLACK_*) already exported in your shell
    1password  -> auto-wrap with \`op run --env-file=<env_file>\`
EOF
    ;;
  *) die "unknown command: $1 (try 'build' or 'run')" ;;
esac
