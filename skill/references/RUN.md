# secscan — runbook

How to invoke secscan, what flags exist, what exit codes mean, and how to
recover from common failures. The agent (you) reads this when actually
operating the scanner for the user.

## The three commands

```bash
$SECSCAN_HOME/secscan.sh build     # docker build the image (once, or after upgrades)
$SECSCAN_HOME/secscan.sh check     # verify prereqs — run this before each run if unsure
$SECSCAN_HOME/secscan.sh run [...] # actually scan
```

## `run` flags

```
--config <path>           Use a specific config.yaml. Its parent dir is mounted.
--config-dir <path>       Use a specific config DIR; expects config.yaml inside.
--dry-run                 Don't file any issues (DEFAULT — bias toward safety).
--no-dry-run              Actually create issues / project items.
--                        Everything after is passed verbatim to `python -m secscan`.
extra args                Forwarded to the scanner CLI.
```

Defaults:
- `--dry-run` is added unless the caller passes `--no-dry-run`.
- `--config-dir` defaults to `$SECSCAN_HOME/config/` (override:
  `SECSCAN_CONFIG_DIR` env).
- `--config` defaults to `<config-dir>/config.yaml` (override:
  `SECSCAN_CONFIG` env).
- Image tag is `secscan:latest` (override: `SECSCAN_IMAGE`).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (findings may have been filed; existence of findings is not an error) |
| 2 | Bad config — fail before any scanner ran |
| 3 | All scanners failed — refused to report "all clear" |
| 4 | GitHub API failure (project not found, auth, etc.) |
| other non-zero | docker / shell / unexpected error |

## Recipes

### First-time dry-run

```bash
$SECSCAN_HOME/secscan.sh check                     # are we wired?
$SECSCAN_HOME/secscan.sh run                       # dry-run by default
```

The summary line at the end looks like:

```
summary: created=0 dup-skipped=0 fuzzy-dup-skipped=0 below-floor=0
        total-findings=42 scanners-completed=5 scanners-failed=0
```

If `created` is the number you expected to file, proceed to the real run.

### Real run (after dry-run looks good)

```bash
$SECSCAN_HOME/secscan.sh run --no-dry-run
```

**Hard rule:** never pass `--no-dry-run` unless the user explicitly confirmed
in the current turn. The default is there to prevent surprise issue creation.

### Custom config dir (e.g. multiple projects)

```bash
$SECSCAN_HOME/secscan.sh run --config-dir ~/.config/secscan/project-foo
```

The whole `~/.config/secscan/project-foo/` is bind-mounted at `/config` in
the container, so it should look exactly like the repo's `config/` layout
(at minimum: `config.yaml`).

### Enable LLM SAST + cross-validation

Edit `config.yaml`:

```yaml
scanners:
  codex: true
  gemma: true
```

Then run. The first time you turn these on, do a `--dry-run` against a small
repo to calibrate signal/noise before pointing at a large codebase.

**Prereq checks before flipping these on:**
- Codex: `command -v codex && codex doctor` shows `auth mode: chatgpt`
  ("not logged in" → user must run `codex login` first).
- Gemma: `curl -sf $(grep base_url config/config.yaml | head -1 | awk '{print $2}' | tr -d '\"')/api/tags`
  returns JSON (Ollama reachable) AND the model in `triage.model` /
  `gemma.model` is pulled (`ollama list | grep gemma4:26b`).

## What "completed" vs "failed" means

A scanner that did NOT complete contributes **zero findings**. This is by
design — a crashed scanner must never read as "all clear" to downstream
tooling. The summary line distinguishes `scanners-completed` vs
`scanners-failed`. Investigate any failure before trusting a run.

When a single scanner is failing repeatedly, you can flip it off in
`config.yaml` (`scanners.<name>: false`) to unblock the rest while you fix it.

## Common failures

| Symptom | Cause | Fix |
|---|---|---|
| `config not found at <path>` | No `config.yaml` in config dir | `cp config/config.example.yaml config/config.yaml` and edit |
| `GITHUB_TOKEN not set` (env source) | Shell var unset | `export GITHUB_TOKEN=...` OR switch to 1Password (see CONFIG.md) |
| `op (1Password CLI) not installed` | 1Password path requires `op` | `brew install 1password-cli && op signin` |
| `op not signed in` | Signed-out 1P session | `op signin` |
| `.env.1password.tpl missing` | Per-user 1P env file not created | `cp config/.env.1password.tpl.example config/.env.1password.tpl && $EDITOR …` |
| `image not built yet` | No `secscan:latest` image | `$SECSCAN_HOME/secscan.sh build` |
| `docker daemon not reachable` | Docker Desktop not running | Start Docker Desktop |
| `GitHub API 404: project not found` | Wrong `project.owner` / `project.number`, or PAT missing `project` scope | Verify URL and PAT scopes (see CONFIG.md) |
| `scanner codex: NOT COMPLETED (auth failed — run `codex login` first)` | Codex CLI not authed | User runs `codex login` |
| `scanner gemma: NOT COMPLETED (ollama unreachable: ...)` | Ollama down or wrong URL | Start Ollama, or fix `gemma.base_url` |

## Logs and artifacts

- **stderr** is where secscan logs (one-line-per-event format).
- **Findings**: in the GitHub repo + the Projects v2 board configured under
  `project:`.
- **SBOM** (when `scanners.syft: true`): written under `work/` inside the
  container; the wrapper script wipes the container's `/work` on exit but
  the SBOM path is logged via stderr (`sbom: cyclonedx -> /work/sbom-...`).
- **Slack** (when `slack.enabled: true`): per-category digest with severity
  breakdown.

## How dedup behaves

Each finding has a deterministic fingerprint embedded in the issue body as
an HTML comment. On the next run, all project items (open AND closed) are
listed, fingerprints parsed back out, and any new finding whose fingerprint
already exists is **skipped — even if the existing issue is closed**.

Closed = "humans triaged this; never re-file." If you need regression
re-surfacing, that's the external fixing system's concern, not secscan's.

## Reporting back to the user

After a run, surface:
1. The final summary line verbatim.
2. Any `scanners-failed` count above zero, with the per-scanner errors.
3. A link to the project board: `https://github.com/orgs/<owner>/projects/<number>`.
4. The dry-run / real-run mode, explicitly.

Do **not** paste the full stderr log into your reply — it can be long. Quote
relevant excerpts only.
