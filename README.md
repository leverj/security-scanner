# secscan

Stateless single-repo security scanner. Detects a repo's stack, runs OSV-Scanner +
Gitleaks + Semgrep, and files each finding as a deduplicated GitHub sub-issue under
a user-provided parent issue.

State lives in GitHub Issues. No internal database. Closing/fixing findings is out
of scope — another system owns that.

## Quick start

```bash
# 1. Create config.yaml (see config.example.yaml)
cp config.example.yaml config.yaml

# 2. Export GITHUB_TOKEN (PAT with `repo` scope on the target repo)
export GITHUB_TOKEN=ghp_...

# 3. Run via Docker
docker build -t secscan .
docker run --rm \
  -v "$PWD/config.yaml":/config/config.yaml:ro \
  -e GITHUB_TOKEN \
  secscan
```

For a non-destructive trial, add `--dry-run` at the end — no GitHub issues are created.

## Local development

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q
```

## How dedup works

Each finding gets a deterministic fingerprint (`rule_id + file_path + normalized
snippet`, line-number-free) that is embedded as an HTML comment in the issue body.
On the next run, sub-issues of the parent (open AND closed) are listed, fingerprints
parsed back out, and any new finding whose fingerprint is already present is skipped.

This means: once an issue is closed (fixed OR won't-fix), it never refiles. If you
need re-surfacing of regressions, that's the external fixing system's concern.

## Spec

See [secscan-spec.md](secscan-spec.md) for the full design.
