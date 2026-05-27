# secscan

[![CI](https://github.com/leverj/security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/leverj/security-scanner/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Stateless single-repo security scanner. Detects a repo's stack, runs OSV-Scanner +
Gitleaks + Semgrep, and files each finding as a deduplicated GitHub sub-issue under
a user-provided parent issue.

State lives in GitHub Issues. No internal database. Closing/fixing findings is out
of scope — another system owns that.

---

## Quick start

```bash
# 1. Create the PARENT issue on your target GitHub repo and note its number.
#    secscan files findings as sub-issues of THIS issue — it does not create the
#    parent for you. Title it something like "Security findings (secscan)".

# 2. Copy the example config
cp config.example.yaml config.yaml
$EDITOR config.yaml          # set repo, ref, parent_issue (= the number from step 1)

# 3. Set up secrets — pick ONE of the two paths in the next section

# 4. Verify your setup, then run
./secscan.sh check           # green checks across the board?
./secscan.sh build
./secscan.sh run             # defaults to --dry-run; add --no-dry-run to actually file issues
```

---

## Setup: secrets

secscan needs a GitHub Personal Access Token, and optionally a Slack webhook URL.
**Secrets never go into `config.yaml`** — they come in via env vars at runtime.

`config.yaml` declares which path you're using:

```yaml
secrets:
  source: "env"        # or "1password"
  env_file: ".env.1password.tpl"   # only used when source=1password
```

### Option A — Shell environment (simplest)

For local/dev runs where you're comfortable having a token in your shell:

```yaml
# in config.yaml
secrets:
  source: "env"
```

```bash
# Create a fine-grained PAT at https://github.com/settings/tokens
#   Scope: `repo` (full) — required to create issues + sub-issues on the target repo
export GITHUB_TOKEN=github_pat_...

# Optional Slack — get a webhook from https://api.slack.com/apps
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

./secscan.sh run
```

To persist, put the `export` lines in `~/.zshrc` or `~/.bashrc`. The script verifies
the token is present and fails fast if not.

### Option B — 1Password (recommended for daily use)

Secrets live in your 1Password vault and are pulled in just-in-time by `op run`,
so they're never stored on disk and only exist in process env for the duration of
one command.

```bash
# Prereq: 1Password CLI
brew install 1password-cli
op signin

# Copy the template and edit the vault/item paths to point at your own entries
cp .env.1password.tpl.example .env.1password.tpl
$EDITOR .env.1password.tpl
```

`.env.1password.tpl` then looks like:

```
GITHUB_TOKEN=op://<your-vault>/<your-item>/GITHUB_TOKEN
SLACK_WEBHOOK_URL=op://<your-vault>/<your-item>/SLACK_WEBHOOK_URL
```

```yaml
# in config.yaml
secrets:
  source: "1password"
  env_file: ".env.1password.tpl"
```

```bash
./secscan.sh run          # auto-wraps with: op run --env-file=.env.1password.tpl -- docker run ...
```

The file `.env.1password.tpl` is `.gitignore`d. The committed
`.env.1password.tpl.example` is the placeholder template — keep this safe to share,
and never commit your filled-in copy.

### Option C — Docker secrets / CI

For container orchestrators (Docker Swarm, K8s, GitHub Actions, etc.), populate
`GITHUB_TOKEN` (and friends) via your platform's secret mechanism so it appears
in the container's environment. With `secrets.source: env`, `secscan.sh` (or a
direct `docker run`) will pick it up.

---

## How dedup works

Each finding gets a deterministic fingerprint (`rule_id + file_path + normalized
snippet`, line-number-free) that is embedded as an HTML comment in the issue body.
On the next run, sub-issues of the parent (open AND closed) are listed, fingerprints
parsed back out, and any new finding whose fingerprint is already present is skipped.

This means: once an issue is closed (fixed OR won't-fix), it never refiles. If you
need re-surfacing of regressions, that's the external fixing system's concern.

---

## Troubleshooting

`./secscan.sh check` reports the status of every prerequisite:

```
== config ==
  ✓ /path/to/config.yaml
== docker ==
  ✓ docker is running
== image ==
  ✓ secscan:latest present              # ⚠ "not built yet" if you skipped `build`
== secrets (1password) ==
  ✓ op (1Password CLI) installed
  ✓ op signed in
  ✓ /path/to/.env.1password.tpl present
== slack ==
  · disabled                            # or "enabled — mode: webhook:SLACK_WEBHOOK_URL"
```

Common failure modes and what `check` says:

| Symptom | Fix |
|---|---|
| `config not found` | `cp config.example.yaml config.yaml` |
| `GITHUB_TOKEN unset` (env source) | `export GITHUB_TOKEN=…` or switch to `secrets.source: "1password"` |
| `op not installed` (1Password source) | `brew install 1password-cli && op signin` |
| `.env.1password.tpl missing` | `cp .env.1password.tpl.example .env.1password.tpl && $EDITOR …` |
| `SLACK_… unset` (slack.enabled=true) | Either export the var, add it to the 1Password env file, or set `slack.enabled: false` |
| `image not built yet` | `./secscan.sh build` |
| `docker daemon not reachable` | Start Docker Desktop |

---

## Local development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q          # 130 tests, all stdlib + a couple of mocks
```

The scanner binaries (osv-scanner, gitleaks, semgrep) live only inside the Docker
image — local tests use SARIF fixtures and mocked subprocesses. To exercise the
real binaries, run via `./secscan.sh run`.

---

## Spec

See [secscan-spec.md](secscan-spec.md) for the full design.
