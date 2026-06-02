# secscan — reference

The agent (you) reads this when the user needs background on what secscan is,
how to install it, or what it produces. It's a condensed view; the root
`README.md` in the security-scanner repo is the authoritative source.

## What it is

Stateless single-repo security scanner. Detects a repo's tech stack, runs
several scanners on it, and files every finding as a deduplicated GitHub issue
attached to a Projects v2 board.

The scanners (most run by default; LLM ones opt-in):

| Scanner | What it finds | Default |
|---|---|---|
| OSV-Scanner | Vulnerable language packages (npm, pip, go, ...) | on |
| Gitleaks | Hardcoded secrets / keys (pattern + history) | on |
| Trufflehog | Verified-live secrets (validates against the vendor) | on |
| Semgrep | SAST patterns (eval, SQL concat, XSS, etc.) | on |
| Trivy | Vulns + secrets + IaC + license (all in one) | on |
| Syft | SBOM artifact (CycloneDX JSON) | on |
| Codex | LLM SAST via OpenAI Codex CLI (subscription) | **off** |
| Gemma | LLM SAST via local Ollama | **off** |

When **both** Codex and Gemma are on, cross-validation runs — each tool
reviews the other's findings ("real / false_positive / uncertain"). False
positive verdicts downgrade severity one notch; critical is asymmetric (never
auto-downgrades). Findings are never suppressed.

## Where state lives

There is no internal database. The single source of truth is a **GitHub
Projects v2 board** the user owns. Each finding becomes an issue in the repo
plus a project item with `Severity` + `Category` single-select fields set.
Dedup is done by walking project items and reading deterministic fingerprints
embedded in issue bodies — once a finding is filed (or closed), it's never
re-filed.

PAT scopes required: **`repo` + `project`** (classic PAT; fine-grained
doesn't yet expose Projects v2 mutations).

## Install

```bash
git clone https://github.com/leverj/security-scanner.git ~/code/security-scanner
export SECSCAN_HOME=~/code/security-scanner   # add to .zshrc / .bashrc
cd $SECSCAN_HOME

cp config/config.example.yaml config/config.yaml
$EDITOR config/config.yaml                    # see CONFIG.md

./secscan.sh build                            # docker build secscan:latest
./secscan.sh check                            # verify everything is wired
./secscan.sh run                              # defaults to --dry-run
```

For 1Password-managed secrets and full config schema, see **CONFIG.md**.
For day-to-day operations and troubleshooting, see **RUN.md**.

## Files inside `$SECSCAN_HOME/`

```
secscan/                       # python package — scanners, sync, normalization
secscan.sh                     # wrapper around `docker run`
Dockerfile                     # builds secscan:latest (Python + all scanner binaries)
config/                        # bind-mounted at /config inside the container
  config.yaml                  # main settings (gitignored)
  config.example.yaml          # template (committed)
  .env.1password.tpl           # 1Password env file (gitignored)
  .env.1password.tpl.example   # template (committed)
skill/                         # this skill bundle — what you're reading
```

The whole `config/` directory is the unit of bind-mount, so any file related
to secrets resolution rides along with the main config.

## Spec

The full design is in `$SECSCAN_HOME/secscan-spec.md` if the user wants the
deep dive (data model, fingerprint scheme, dedup rules, hostile-repo posture).
