#!/usr/bin/env bash
# Convenience wrapper for building and running the secscan container.
#
#   ./secscan.sh build              -> docker build the image
#   ./secscan.sh run [args...]      -> docker run, default --dry-run, forwards extra args
#
# Required env (only for `run`):
#   GITHUB_TOKEN          PAT with repo scope on the target repo
# Optional env (forwarded if set):
#   SLACK_WEBHOOK_URL, SLACK_BOT_TOKEN, SLACK_CHANNEL_ID
#
# Config: defaults to ./config.yaml; override with `--config /path/to/cfg.yaml` before
# any other args, or set SECSCAN_CONFIG=... in env.

set -euo pipefail

IMAGE="${SECSCAN_IMAGE:-secscan:latest}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

die() { echo "error: $*" >&2; exit 1; }

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
  [[ -n "${GITHUB_TOKEN:-}" ]] || die "GITHUB_TOKEN env var is required"

  # IMPORTANT: pass `-e VAR` (no value) so the secret is read from this shell's
  # env by docker, not interpolated into argv where `ps` would show it.
  local env_args=(-e GITHUB_TOKEN)
  for var in SLACK_WEBHOOK_URL SLACK_BOT_TOKEN SLACK_CHANNEL_ID; do
    if [[ -n "${!var:-}" ]]; then
      env_args+=(-e "$var")
    fi
  done

  echo "running $IMAGE with config=$config ${extra_args[*]+(${extra_args[*]})}" >&2
  docker run --rm \
    -v "$config":/config/config.yaml:ro \
    "${env_args[@]}" \
    "$IMAGE" "${extra_args[@]+"${extra_args[@]}"}"
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

env (run only):
  GITHUB_TOKEN          required
  SLACK_*               forwarded if set
EOF
    ;;
  *) die "unknown command: $1 (try 'build' or 'run')" ;;
esac
