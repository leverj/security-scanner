# secscan config — reference

The agent (you) reads this when configuring secscan for the user. The config
lives in **a directory**, not a single file — the whole directory is
bind-mounted into the container, so secrets-resolution files (1Password env
file, etc.) ride along with the main `config.yaml`.

## Layout

```
config/
  config.yaml                  # required — main settings
  config.example.yaml          # committed template
  .env.1password.tpl           # required only when secrets.source: 1password
  .env.1password.tpl.example   # committed template
```

By default secscan looks at `$SECSCAN_HOME/config/`. Override with
`--config-dir` or `SECSCAN_CONFIG_DIR=/path/to/your-config`.

## Required top-level keys

```yaml
repo: "owner/name"             # target repo to scan (must exist on GitHub)
ref:  "main"                   # branch / tag / SHA to scan

project:                       # target Projects v2 board for findings
  owner: "owner"               #   org or user that owns the project
  number: 5                    #   project number from the URL: /projects/<n>

github_token_env: "GITHUB_TOKEN"   # env var name that holds the PAT
```

**PAT scopes:** `repo` (full) + `project`. Classic PAT, not fine-grained
(fine-grained doesn't yet expose Projects v2 mutations as of late 2025).

## Scanners — flip what runs

```yaml
scanners:
  osv: true            # vulnerable language packages
  gitleaks: true       # secret patterns (with git history)
  semgrep: true        # SAST patterns
  trivy: true          # vuln + secret + IaC + license, all in one
  trufflehog: true     # verified-live secrets
  syft: true           # SBOM artifact (no project items filed)

  # LLM-driven SAST — off by default; opt-in.
  codex: false         # OpenAI Codex via local `codex` CLI (subscription)
  gemma: false         # Local Gemma 4 via Ollama
```

When **both** `codex` and `gemma` are true, cross-validation kicks in
automatically. See the `cross_validate:` block below.

## Codex (subscription)

```yaml
codex:
  binary: "codex"           # auto-detected on PATH
  # model: "gpt-5-codex"    # omit to use codex's configured default
  timeout: 1200             # seconds; LLM scans take minutes on real repos
```

**Auth:** `codex login` outside this tool. secscan never sees an API key.

**Prereq:** `codex` CLI installed (`brew install codex` or per docs) AND the
user is logged in via `codex login`. The runner refuses to start otherwise
with a clear "run `codex login`" message.

## Gemma (local Ollama)

```yaml
gemma:
  # Falls back to triage.base_url / triage.model when blank — most users only
  # configure Ollama once.
  # base_url: "http://host.docker.internal:11434"
  # model: "gemma4:26b"
  # keep_alive: "5m"
  timeout: 1800
  max_files: 60             # source files batched in one prompt
  max_file_bytes: 12000     # per-file content cap (truncated past this)
  max_total_bytes: 200000   # total prompt cap across all files
```

**Prereq:** Ollama running locally (or reachable via `host.docker.internal`)
and the named model pulled (`ollama pull gemma4:26b`).

## Cross-validation

```yaml
cross_validate:
  enabled: true
  codex_timeout: 300        # per-finding budget for codex reviewing a gemma flag
  gemma_timeout: 180        # per-finding budget for gemma reviewing a codex flag
```

Only active when **both** `scanners.codex` and `scanners.gemma` are true.
Verdicts: `real` (no change), `false_positive` (severity downgraded one
notch — `high→medium`, `medium→low`, `low→info`; **`critical` stays
critical**), or `uncertain` (annotated, no change). Findings are **never
suppressed** — humans triage on the project board.

## Triage (optional, post-scanner)

Gemma also runs as a per-finding reviewer / Slack-intro writer, distinct from
its scanner role:

```yaml
triage:
  enabled: true
  provider: "ollama"
  model: "gemma4:26b"
  base_url: "http://host.docker.internal:11434"
  keep_alive: "5m"
  timeout: 600
  prewarm: true             # load the model in a background thread at startup
  intro_timeout: 120        # tight cap on the Slack intro generation
  # Granular feature flags (default conservative):
  intro_enabled: true       # cheap: one chat call total
  prose_enabled: false      # expensive: one call per new finding
  fuzzy_dup_enabled: false  # expensive: one call per new finding
```

## Slack (optional)

```yaml
slack:
  enabled: true
  webhook_url_env: "SLACK_WEBHOOK_URL"     # OR (mutually exclusive):
  # channel_id_env: "SLACK_CHANNEL_ID"
  # bot_token_env:  "SLACK_BOT_TOKEN"
```

## Other knobs

```yaml
paths:
  exclude:                  # fnmatch globs + trailing-slash directory prefixes
    - "archive/"
    - "vendor/"
    - ".github/scripts/"

severity_floor: "low"       # info | low | medium | high | critical
```

## Secrets — two paths

### Path A: shell env (simplest)

```yaml
secrets:
  source: "env"
```

```bash
export GITHUB_TOKEN=github_pat_...
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...   # only if slack.enabled
$SECSCAN_HOME/secscan.sh run
```

Put the `export` lines in `~/.zshrc` to persist. The script fails fast if any
required var is missing.

### Path B: 1Password (recommended for daily use)

```yaml
secrets:
  source: "1password"
  env_file: ".env.1password.tpl"   # relative to the config/ dir
```

Setup:

```bash
brew install 1password-cli
op signin

cp config/.env.1password.tpl.example config/.env.1password.tpl
$EDITOR config/.env.1password.tpl
```

The file should look like:

```
GITHUB_TOKEN=op://<your-vault>/<your-item>/GITHUB_TOKEN
SLACK_WEBHOOK_URL=op://<your-vault>/<your-item>/SLACK_WEBHOOK_URL
```

Then just:

```bash
$SECSCAN_HOME/secscan.sh run
```

`secscan.sh` auto-wraps the invocation with
`op run --env-file=config/.env.1password.tpl -- docker run ...`. Tokens are
pulled JIT into the process env, never written to disk and never on argv.

### Path C: Docker secrets / CI

Set `secrets.source: env` in `config.yaml` and let your orchestrator
(GitHub Actions, K8s, Docker Swarm) populate `GITHUB_TOKEN` etc. in the
container env. The script picks them up the same way.

## Verifying

After any config change:

```bash
$SECSCAN_HOME/secscan.sh check
```

This reports the state of every prerequisite (config file, docker, image,
secrets path, Slack vars). Walk the user through any `✗` it surfaces — see
the troubleshooting table in **RUN.md**.
