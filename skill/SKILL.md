---
name: secscan
description: |
  Run the secscan security scanner on a repo. Detects the stack, runs OSV-Scanner,
  Gitleaks, Semgrep, Trivy, Trufflehog, and optionally Codex+Gemma LLM SAST with
  cross-validation. Files each finding as an issue into a GitHub Projects v2 board.
  Trigger when the user asks to "scan", "run secscan", "check security", "audit
  dependencies / secrets / code", or types /secscan.
---

# secscan skill

You're the agent operating the secscan security scanner. Your job is to invoke
it correctly, monitor its output, and report back to the user.

## When to invoke

Trigger on requests like:
- "scan this repo for security issues"
- "run secscan"
- "check for secrets / CVEs / SAST issues"
- "/secscan"
- "audit dependencies"

If the user just says "scan" without context, ask which repo (current dir? a
different one?) and which ref (default: `main`).

## What secscan needs

- The **security-scanner repo** cloned somewhere (the tooling itself). Default
  location: `$SECSCAN_HOME` env var; fall back to `~/code/security-scanner` if
  unset. If neither exists, tell the user to clone
  `https://github.com/leverj/security-scanner` and set `SECSCAN_HOME`.
- A **config directory** with `config.yaml` (and optionally `.env.1password.tpl`).
  Default: `$SECSCAN_HOME/config/`. Override via `--config-dir` or
  `SECSCAN_CONFIG_DIR`.
- Docker running (or another container runtime); secscan is delivered as a
  container image.
- A **GitHub Projects v2 board** for findings, configured under `project:` in
  the config. PAT must have `repo` + `project` scopes.

## Operating procedure

1. **Locate the tooling.** Check `$SECSCAN_HOME`, then `~/code/security-scanner`.
   If neither exists, surface the README installation steps (see
   `references/README.md`) and stop.

2. **Check config.** Run `$SECSCAN_HOME/secscan.sh check`. If it reports any
   `✗`, walk the user through the fix using `references/CONFIG.md` as the
   source of truth. Common failure modes:
   - missing `config/config.yaml` → copy from `config.example.yaml`
   - missing GITHUB_TOKEN or 1Password setup → see `references/CONFIG.md`
   - docker not running → tell the user to start Docker Desktop

3. **Pick the right run mode.**
   - **Default to `--dry-run`** for the first run; surface what would be filed.
   - Only run `--no-dry-run` after the user explicitly confirms.
   - Codex + Gemma LLM SAST and cross-validation are **off by default in
     `config.yaml`**; flip them on only when the user asks for "deep" or "LLM"
     scanning, and warn them about subscription cost (Codex) + Ollama
     prerequisites (Gemma).

4. **Run it.** From the security-scanner repo:
   ```bash
   $SECSCAN_HOME/secscan.sh run --dry-run
   ```
   For LLM-on runs against a non-default config dir:
   ```bash
   $SECSCAN_HOME/secscan.sh run --config-dir /path/to/cfg --no-dry-run
   ```
   See `references/RUN.md` for the full set of flags and exit codes.

5. **Report.** Quote the summary line secscan emits (`summary: created=N
   dup-skipped=N ...`), surface any per-scanner failures, and link to the
   GitHub project board for triage.

## Hard rules

- **Never run with `--no-dry-run`** unless the user explicitly confirmed in the
  current turn — the dry-run default is there to prevent surprise issue
  creation.
- **Never expose secrets.** GITHUB_TOKEN, 1Password env contents, Slack
  webhooks must never appear in your messages back to the user. secscan
  scrubs these from its own logs; you must too.
- **Don't edit `config/config.yaml` silently.** If a value needs changing,
  show the proposed diff and ask first.
- **Honor the project board as the source of truth.** Don't try to dedup
  findings yourself; that's secscan's job (deterministic fingerprints).

## Where to look for deeper info

- `references/README.md` — installation, prerequisites, how dedup works
- `references/CONFIG.md` — full config schema + 1Password setup walkthrough
- `references/RUN.md` — runbook, flags, exit codes, troubleshooting
