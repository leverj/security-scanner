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

For container orchestrators (Docker Swarm, K8s, GitHub Actions, etc.), populate
`GITHUB_TOKEN` (and friends) via your platform's secret mechanism so it appears
in the container's environment. With `secrets.source: env`, `security-scan.sh` (or a
direct `docker run`) will pick it up.

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

## Redaction before remote LLMs

The Codex SAST scanner, the Gemma SAST scanner, and the cross-validation step
all hand source-derived content (snippets, file contents, finding messages) to
external models. Before any of that leaves the box:

- Known-token shapes are rewritten — AWS keys, GitHub tokens/PATs, Stripe,
  Slack, Google API, OpenAI/Anthropic-style `sk-…`, JWTs, PEM blocks, and
  `NAME=value` assignments where `NAME` is a secret-shaped key.
- High-Shannon-entropy substrings (≥ 4.0 over ≥ 20 chars) are rewritten to
  `<REDACTED:high-entropy>`.
- For Gemma (Ollama) and the Gemma direction of cross-validation, the scanner
  refuses to send anything at all if `base_url` doesn't resolve to loopback or
  RFC1918. Same for `triage.base_url` — if set to a non-local host, triage is
  disabled at construction time.

This is defence-in-depth: it lets cross-validation and Codex SAST run with
substantially less risk of leaking real production credentials hardcoded in
source. The list isn't exhaustive — treat the scanned repo as trusted code
you're auditing, not as adversarial input.

## Spec

See [security-scan-spec.md](security-scan-spec.md) for the full design.
