# security-scan

[![CI](https://github.com/leverj/security-scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/leverj/security-scanner/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Stateless single-repo security scanner. Detects a repo's stack, runs OSV-Scanner +
Gitleaks + Semgrep + Trivy + Trufflehog, and files each finding as a deduplicated
issue into a user-provided GitHub Projects v2 board.

State lives in GitHub Issues + their project membership. No internal database.
Closing/fixing findings is out of scope — another system owns that.

---

## Quick start

```bash
# 1. Create (or pick) a GitHub Projects v2 board for security findings.
#    Note its number (visible in the URL: /projects/<number>).
#    On first run security-scan provisions two single-select fields on the board:
#      - Severity   (critical, high, medium, low, info)
#      - Category   (dependency, secret, sast, iac, license)

# 2. Copy the example config
cp config/config.example.yaml config/config.yaml
$EDITOR config/config.yaml   # set repo, ref, project.owner, project.number

# 3. Set up secrets — pick ONE of the two paths in the next section

# 4. Verify your setup, then run
./security-scan.sh check           # green checks across the board?
./security-scan.sh build
./security-scan.sh run             # defaults to --dry-run; add --no-dry-run to actually file issues
```

---

## Setup: secrets

security-scan needs a GitHub Personal Access Token, and optionally a Slack webhook URL.
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
# Create a PAT at https://github.com/settings/tokens (classic; fine-grained
# doesn't expose Projects v2 mutations as of late 2025).
#   Scopes: `repo` (full) — to create + read issues on the target repo
#           `project`     — to read/write the Projects v2 board (add items, set fields)
export GITHUB_TOKEN=github_pat_...

# Optional Slack — get a webhook from https://api.slack.com/apps
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...

./security-scan.sh run
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
cp config/.env.1password.tpl.example config/.env.1password.tpl
$EDITOR config/.env.1password.tpl
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
./security-scan.sh run          # auto-wraps with: op run --env-file=.env.1password.tpl -- docker run ...
```

The file `.env.1password.tpl` is `.gitignore`d. The committed
`.env.1password.tpl.example` is the placeholder template — keep this safe to share,
and never commit your filled-in copy.

### Option C — Docker secrets / CI

For container orchestrators (Docker Swarm, K8s, GitHub Actions, CircleCI, etc.),
populate `GITHUB_TOKEN` (and friends) via your platform's secret mechanism so it
appears in the container's environment. With `secrets.source: env`,
`security-scan.sh` (or a direct `docker run`) will pick it up.

---

## How to run

Three supported integration paths. All three invoke the same image
(`leverj/security-scan:latest`) with the same `config.yaml`. The choice is
about where the scan runs, not what it does.

| Path | Use when | Cost |
|---|---|---|
| **CLI** (`docker run` from your laptop) | Ad-hoc / one-off scans, debugging config | Free |
| **GitHub Actions** | The target repo lives on GitHub and you want the scan in CI | Free on public repos; ~$0.04/run on private (covered by free tier for most teams) |
| **CircleCI** | You already run CI on CircleCI (e.g. iOS pipeline on a self-hosted Mac) | Whatever your CircleCI plan charges; $0 on self-hosted runners |

For all paths you need:

- A GitHub PAT with `repo` + `project` scopes (the auto-provisioned
  `GITHUB_TOKEN` in GitHub Actions does NOT have `project` scope — use a
  user/org PAT stored in repo secrets).
- A `config.yaml` in your target repo (typical location: `.security-scan/config.yaml`).
- A GitHub Projects v2 board the PAT can write to.

### CLI

Run from anywhere with Docker + the PAT in your shell:

```bash
export GITHUB_TOKEN="ghp_..."        # PAT with repo + project scopes
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/..."   # optional

# A) Scan a repo you've already checked out (fast — no clone)
docker run --rm \
  -v "$PWD/.security-scan:/config:ro" \
  -v "$PWD:/work" \
  -e GITHUB_TOKEN -e SLACK_WEBHOOK_URL \
  leverj/security-scan:latest \
  --repo-dir /work

# B) Clone fresh from cfg.repo@cfg.ref (default behavior)
docker run --rm \
  -v "$PWD/.security-scan:/config:ro" \
  -e GITHUB_TOKEN -e SLACK_WEBHOOK_URL \
  leverj/security-scan:latest
```

Add `--dry-run` to the args list to scan + normalize without filing anything.

Pin by digest in scripts so a fresh `:latest` push can't surprise you mid-run:

```bash
DIGEST=$(docker manifest inspect leverj/security-scan:latest | jq -r '.manifests[0].digest')
docker run ... "leverj/security-scan@${DIGEST}" --repo-dir /work
```

### GitHub Actions (self-hosted Mac mini or github-hosted Linux)

Drop this into `.github/workflows/security-scan.yml` in the target repo:

```yaml
name: security-scan

on:
  schedule:
    - cron: '0 9 * * *'        # 02:00 PT daily
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: security-scan-${{ github.ref }}
  cancel-in-progress: false

jobs:
  scan:
    # github-hosted: runs-on: ubuntu-latest
    # self-hosted Mac mini:
    runs-on: [self-hosted, macOS, ARM64]
    timeout-minutes: 30

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0       # gitleaks/trufflehog scan full history

      - name: Run security-scan
        env:
          GITHUB_TOKEN:      ${{ secrets.SECURITY_SCAN_TOKEN }}
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
        run: |
          docker pull -q leverj/security-scan:latest
          docker run --rm \
            -v "$PWD/.security-scan:/config:ro" \
            -v "$PWD:/work" \
            -e GITHUB_TOKEN -e SLACK_WEBHOOK_URL \
            leverj/security-scan:latest \
            --repo-dir /work
```

Repo secrets to set: `SECURITY_SCAN_TOKEN` (the PAT),
`SLACK_WEBHOOK_URL` (optional).

### CircleCI (self-hosted Mac mini)

Drop this into `.circleci/config.yml` in the target repo:

```yaml
version: 2.1

jobs:
  security-scan:
    machine: true
    resource_class: leverj/mac-mini    # your registered self-hosted runner
    steps:
      - checkout
      - run:
          name: Run security-scan
          command: |
            docker pull -q leverj/security-scan:latest
            docker run --rm \
              -v "${PWD}/.security-scan:/config:ro" \
              -v "${PWD}:/work" \
              -e GITHUB_TOKEN -e SLACK_WEBHOOK_URL \
              leverj/security-scan:latest \
              --repo-dir /work
          environment:
            GITHUB_TOKEN:      $SECURITY_SCAN_TOKEN
            SLACK_WEBHOOK_URL: $SLACK_WEBHOOK_URL

workflows:
  nightly:
    triggers:
      - schedule:
          cron: "0 9 * * *"        # 02:00 PT daily
          filters:
            branches:
              only: [main]
    jobs: [security-scan]
```

Project env vars to set in CircleCI: `SECURITY_SCAN_TOKEN`,
`SLACK_WEBHOOK_URL` (optional).

Self-hosted Mac mini setup (applies to both GitHub Actions and CircleCI):

- Docker Desktop running + auto-start on login.
- Prevent sleep when plugged in (or `caffeinate -dimsu` in a launchd plist).
- Single runner = one job at a time — pick a cron hour the iOS pipeline is idle.
- Disk hygiene: `docker system prune -af --filter "until=720h"` weekly to bound image cache growth.

---

## How dedup works

Each finding gets a deterministic fingerprint (`rule_id + file_path + normalized
snippet`, line-number-free) that is embedded as an HTML comment in the issue body.
On the next run, all items in the target Projects v2 board (open AND closed) are
listed, fingerprints parsed back out, and any new finding whose fingerprint is
already present is skipped.

This means: once an issue is closed (fixed OR won't-fix), it never refiles. If you
need re-surfacing of regressions, that's the external fixing system's concern.

---

## Troubleshooting

`./security-scan.sh check` reports the status of every prerequisite:

```
== config ==
  ✓ /path/to/config.yaml
== docker ==
  ✓ docker is running
== image ==
  ✓ security-scan:latest present              # ⚠ "not built yet" if you skipped `build`
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
| `config not found` | `cp config/config.example.yaml config/config.yaml` |
| `GITHUB_TOKEN unset` (env source) | `export GITHUB_TOKEN=…` or switch to `secrets.source: "1password"` |
| `op not installed` (1Password source) | `brew install 1password-cli && op signin` |
| `.env.1password.tpl missing` | `cp config/.env.1password.tpl.example config/.env.1password.tpl && $EDITOR …` |
| `SLACK_… unset` (slack.enabled=true) | Either export the var, add it to the 1Password env file, or set `slack.enabled: false` |
| `image not built yet` | `./security-scan.sh build` |
| `docker daemon not reachable` | Start Docker Desktop |

---

## Local development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q          # 130 tests, all stdlib + a couple of mocks
```

The scanner binaries (osv-scanner, gitleaks, semgrep) live only inside the Docker
image — local tests use SARIF fixtures and mocked subprocesses. To exercise the
real binaries, run via `./security-scan.sh run`.

---

## Publish a new image

The image is published from your local machine — no CI secrets needed.

```bash
docker login                 # uses your Docker Hub credentials
./security-scan.sh publish   # builds multi-arch, prompts, pushes :latest
```

Only the `leverj/security-scan:latest` tag is published. Each push creates a
new immutable image digest that the consumer skill watches — versioned tags
would just accumulate on Docker Hub. The script verifies `pyproject.toml`'s
version matches `SECURITY-SCAN-MANIFEST.yaml`'s before publishing (the
version label lives inside the manifest, not as a docker tag) and prints
the resulting digest after push so you can confirm the skill will see it.

Pass `--no-push` to do a release dry-run that builds locally without
pushing, or `--single-arch` to skip multi-arch buildx. Full flag list:
`./security-scan.sh publish --help`.

## Use as a Claude Code skill

The companion bundle at [`leverj/ai-skills`](https://github.com/leverj/ai-skills)
ships a `security-scan` skill that drives this image directly:

```
/plugin marketplace add leverj/ai-skills
/plugin install leverj@leverj-ai-skills
# then: /leverj:security-scan run
```

The skill pulls and runs the published Docker image
`leverj/security-scan:<tag>`, bind-mounts your `config/` directory at
`/config:ro`, and offers a user-confirmed upgrade flow when a newer image
version is available (the image ships a `SECURITY-SCAN-MANIFEST.yaml` describing
its version + any config fields the skill should add to your local
`config.yaml`).

## LLM SAST (companion tool)

LLM SAST (Codex + Gemma with bidirectional cross-validation) **does not** ship
in this container. It moved to a host-side companion tool that lives in the
[leverj/ai-skills](https://github.com/leverj/ai-skills) plugin under
`tools/security-scan-llm/`.

Why split: `codex` is a CLI tied to the user's ChatGPT/Codex login; `gemma`
talks to a local Ollama daemon. Neither resource is reachable from inside the
container, so making the LLM lanes a host concern keeps the container
deterministic + CI-friendly while preserving the LLM coverage for developers
running locally. Both substrates file into the **same** Projects v2 board with
a **byte-identical** fingerprint scheme; findings dedup across runs.

Install:

```bash
pipx install <ai-skills-clone>/tools/security-scan-llm
security-scan-llm --config /path/to/config.yaml --repo-dir .
```

## Spec

See [security-scan-spec.md](security-scan-spec.md) for the full design.
