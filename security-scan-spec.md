# security-scan — Architecture & Build Spec (v2)

> **Note (v0.4.0):** the Codex + Gemma LLM SAST lanes, their bidirectional
> cross-validation, and the Gemma-driven triage (prose/intro/fuzzy-dup) have
> been **removed from this container**. They live in a host-side companion
> tool, [`security-scan-llm`](https://github.com/leverj/ai-skills/tree/master/tools/security-scan-llm),
> shipped via the `leverj/ai-skills` plugin. The container itself is now
> deterministic-only and suitable for a CI-friendly GitHub Action. Sections
> below that describe LLM runners, cross-validation, or Gemma triage describe
> behavior that now applies to `security-scan-llm`, not to this container.
> Both substrates file into the same GitHub Projects v2 board with a
> byte-identical fingerprint scheme.

A single‑repo, stateless, self‑hosted security scanner that detects a repo's tech stack,
runs the right scanners, and files each finding as a deduplicated issue into a user‑provided
**GitHub Projects v2 board**. Distributed as a Docker image (`leverj/security-scan`)
with a baked‑in manifest that lets consumers (e.g. the `leverj/ai-skills` skill) do
user‑confirmed version upgrades with automated config migration. Closing / fixing findings
is **out of scope** — another system owns that.

v1 of this spec described a parent‑epic + sub‑issue model. v2 replaces that
with a flat Projects v2 board (no sub‑issue tree) and adds the image manifest contract.
v0.4.0 (current) moves the LLM SAST lanes out of the container into the
`security-scan-llm` companion tool.

---

## 1. Goals & non‑goals

**Goals**
- Generic: nothing org‑specific. A user supplies a repo, a branch, a Projects v2 board
  (owner + number), and a PAT with `repo` + `project` scopes; it works for anyone.
- Stateless container: no internal database. All persistent state lives in **GitHub
  Issues + their Projects v2 board membership**. Config + secrets come from a mapped
  config directory / env.
- Auto‑detect the stack and run only the relevant scanners.
- Deterministic, auditable dedup. LLMs never own correctness‑critical decisions.
- "Model proposes, code disposes" — irreversible actions (create issue, add project item,
  set custom field, post Slack) are deterministic Python; the model only enriches
  (prose, triage, cross‑validation verdicts).
- Distributable: the image is the contract. Consumers (skills, CI jobs) drive the image
  and pull a manifest out of it to know what version's inside and what config the new
  version expects.

**Non‑goals (explicitly deferred)**
- Closing / reopening / fixing issues (external system).
- A local file DB (project items + their bodies are the state).
- Multi‑repo orchestration, parallel scanning, GitHub App auth.
- DAST / pen‑test lane, DefectDojo, CISO/compliance dashboard.
- Hostile‑repo sandboxing (v1+v2 assume you scan **your own** repo — trusted code).
- Live config‑schema enforcement at the boundary; we rely on the consumer skill to do
  the manifest‑driven migration step before invoking the image.

---

## 2. Locked design decisions

| # | Decision | Rationale |
|---|----------|-----------|
| Storage | **Findings file as issues in the target repo and as items on a GitHub Projects v2 board** owned by the user. Each item carries `Severity` + `Category` single‑select fields. | Removes the 100‑sub‑issue cap that blocked the original sub‑issue model. Flat board + custom fields give a better triage UI. |
| Dedup | **Deterministic fingerprint is the source of truth; LLMs are fuzzy tie‑breakers + prose writers only.** | Reproducible, auditable. No LLM can dup‑spam or silently drop a finding. |
| Create rule | **Dedup against OPEN *and* CLOSED project items; never re‑file a fingerprint that already exists in any state.** | Simplest, quietest. Any closed issue (fixed or won't‑fix) permanently suppresses re‑filing. Accepted blind spot: a fixed‑then‑regressed finding is not re‑surfaced (that's the external fixing system's concern). |
| State | **GitHub Issues + Projects v2 only.** No file DB. | Dedup needs the set of existing project items (open+closed) + their embedded fingerprints. |
| LLM | **Optional.** Core path is fully deterministic and runs with no GPU/cloud‑subscription. Gemma (Ollama) + Codex (subscription CLI) are opt‑in feature flags. | "Generic, anyone can run it" must not require a GPU or a paid subscription. |
| Cross‑validation | **When both Codex and Gemma scanners are on, each reviews the other's findings.** False‑positive verdicts downgrade severity one notch; critical never auto‑downgrades. Findings are never suppressed. | LLM blind spots are asymmetric. Surfacing disagreement to humans is better than silently dropping findings. |
| Auth | **PAT via env** (1Password / Docker‑secret injection optional). PAT requires `repo` + `project` scopes. | Single repo, single owner. (GitHub App deferred to the multi‑tenant version.) |
| Distribution | **Published Docker image `leverj/security-scan:<tag>`** on Docker Hub. Multi‑arch (amd64+arm64). Image carries a baked‑in `/app/SECURITY-SCAN-MANIFEST.yaml`. | Consumers pin a tag, query Docker Hub for upgrades, read the manifest from the candidate image to learn what changed before pulling for real. |
| Concurrency | **Sequential.** | One repo, daily cadence. |
| Repo execution | **Never execute repo code.** Lockfile parsing + static analysis + LLM reading only. | Safety. The cloned tree is scanned in `read-only` mode by the LLM lanes too. |

---

## 3. Module breakdown

```
security_scan/
  config.py          # load + validate config (YAML) and env (token)
  detect.py          # stack detection (manifest walk; emits per-scanner targets)
  runners/           # one module per scanner; each returns SARIF (or is normalized to it)
    osv.py           # OSV-Scanner       (SCA: npm/yarn/pnpm, RubyGems, SwiftPM, pip, go, cargo, …)
    gitleaks.py      # Gitleaks          (secrets, git-history aware)
    semgrep.py       # Semgrep           (SAST, bundled offline rule packs)
    trivy.py         # Trivy             (vuln + secret + IaC + license, all in one)
    trufflehog.py    # Trufflehog        (verified-live secrets — validates against vendor)
    syft.py          # Syft              (SBOM — CycloneDX artifact only, no findings)
    codex.py         # OPTIONAL          OpenAI Codex via local `codex` CLI (subscription)
    gemma.py         # OPTIONAL          Local Gemma via Ollama
  normalize.py       # SARIF -> internal Finding model (one shape for all scanners)
  fingerprint.py     # deterministic, line-number-free fingerprint + marker (de)serialize
  github.py          # clone + GraphQL ProjectsV2 ops (resolve_project, list_project_items,
                     #                                 add_to_project, set_project_field) + REST create_issue
  triage.py          # OPTIONAL Gemma 4 (Ollama): fuzzy-dedup tie-break + issue/Slack prose
  cross_validate.py  # OPTIONAL bidirectional review when codex AND gemma scanners are both on
  notify.py          # OPTIONAL Slack digest
  sync.py            # the create-decision logic (dedup -> create-only -> set fields)
  main.py            # orchestrator: config -> clone -> detect -> scan -> normalize ->
                     #               cross-validate -> sync -> notify
  rules/             # bundled Semgrep rules: javascript, python, secrets, xss, sqli, supabase
```

**Hard dependency boundary:** `detect/runners/normalize/fingerprint/github/sync` are
deterministic and must work with `triage.py`, `notify.py`, `cross_validate.py`, and the
LLM runners (`codex.py`, `gemma.py`) absent or failing. The LLM lanes and Slack are
strictly additive.

---

## 4. Internal Finding model

Everything normalizes to this one shape (from SARIF). Keep it small and scanner‑agnostic.

```python
@dataclass
class Finding:
    scanner: str           # "osv" | "gitleaks" | "semgrep" | "trivy" | "trufflehog" | "codex" | "gemma"
    category: str          # "dependency" | "secret" | "secret-verified" | "sast" | "iac" | "license"
    rule_id: str           # e.g. "GHSA-xxxx", "generic-api-key", "codex.auth-bypass"
    severity: str          # normalized: critical|high|medium|low|info
    file_path: str         # repo-relative, forward slashes
    line: int | None       # for display only — NEVER part of the fingerprint
    title: str             # short, human title (deterministic default; Gemma may rewrite)
    message: str           # scanner message / advisory summary
    masked_preview: str    # for secrets: masked value only — NEVER the raw secret
    sarif_fingerprint: str | None   # SARIF partialFingerprints/fingerprints if present
    extra: dict            # ecosystem, installed/fixed version, CVE/GHSA, cross_validation, …
```

**Severity normalization:** map each tool's scale to `critical/high/medium/low/info`.
SARIF `level` (error/warning/note) + `security-severity` property → normalized severity.

**Cross‑validation annotation** lives in `extra["cross_validation"]` when applicable:
```python
{"validator": "gemma" | "codex",
 "verdict":   "real" | "false_positive" | "uncertain",
 "reason":    "<= 300 chars",
 "original_severity": "<pre-downgrade severity>"}
```

---

## 5. Fingerprint & marker

**Primary identity (deterministic, line‑number‑free):**
```
key_basis = rule_id + "\0" + file_path + "\0" + snippet_or_secretfp
fingerprint = "fp_" + sha256(key_basis).hexdigest()[:16]
```
- Prefer the SARIF‑provided `fingerprints` / `partialFingerprints` when the tool emits
  them (most do) — they're designed for exactly this and survive line drift.
- `snippet_or_secretfp`:
  - SAST: whitespace‑normalized snippet of the matched region (or enclosing symbol name);
  - secrets: the scanner's hash of the value (Gitleaks emits one) — **never the raw secret**;
  - deps: empty (`rule_id` already = GHSA/CVE, unique per package‑advisory).
- **Line numbers are excluded** so reformatting/refactoring doesn't spawn duplicates.

**Marker** embedded in every issue body (hidden HTML comment):
```
<!-- security-scan: fp=fp_ab12cd34ef56 rule=GHSA-xxxx cat=dependency -->
```

The parser also accepts the legacy `<!-- secscan: ... -->` marker (issues filed by the
pre‑rename code) so dedup against pre‑existing items still works without backfill.

`github.py` lists **all** items on the Projects v2 board (any state), parses these
markers from each item's issue body, and builds the set of already‑filed fingerprints.

---

## 6. Create‑decision logic (`sync.py`)

```python
existing_items = github.list_project_items(project.id)         # paginated GraphQL
existing_fps = {marker.fp for it in existing_items if (marker := parse_marker(it.body))}

for f in findings:
    if not f.meets_floor(severity_floor):
        result.skipped_floor += 1
        continue

    fp = f.sarif_fingerprint or compute_fingerprint(f)
    if fp in existing_fps:
        result.skipped_dup += 1
        continue

    # OPTIONAL fuzzy tie-break (only if Gemma triage available): catch renamed/moved
    # code that changed file_path (and thus fp).
    if triage.enabled and triage.is_duplicate_of_existing(f, existing_items):
        result.skipped_fuzzy_dup += 1
        continue

    title, body = triage.write_issue(f) if triage.enabled else default_issue(f)
    body = inject_marker(body, fp, f)                           # marker always injected by code
    issue   = github.create_issue(title, body, labels=_labels_for(f))
    item_id = github.add_to_project(project.id, issue["node_id"])
    github.set_project_field(project.id, item_id, project.severity, f.severity)
    github.set_project_field(project.id, item_id, project.category, f.category)
    existing_fps.add(fp)
```

**Invariants (enforced in `github.py`, not trusted to the model):**
- Create + add‑to‑project + set‑field only. **No** edit/close/reopen/delete of issues.
- The deterministic marker is always injected by code, even if Gemma wrote the prose.
- Never write a raw secret into a body — only `masked_preview`.
- A scanner that did **not** run/complete contributes **no** findings (so a crashed
  scanner can't look like "all clear").

---

## 7. Config schema (`config/config.yaml`, the config dir is bind‑mounted read‑only)

```yaml
repo: "leverj/ezel"
ref:  "dev"

project:                       # the GitHub Projects v2 board findings file into
  owner: "leverj"              #   org or user
  number: 5                    #   project number from the URL: /projects/<number>

github_token_env: "GITHUB_TOKEN"   # env var holding the PAT (value NEVER in config.yaml)

scanners:
  osv: true
  gitleaks: true
  semgrep: true
  trivy: true
  trufflehog: true
  syft: true                   # SBOM artifact (no project items filed)
  codex: false                 # OPTIONAL — OpenAI Codex via subscription
  gemma: false                 # OPTIONAL — local Gemma via Ollama

codex:                         # tunables for the codex runner
  binary: "codex"
  model: null                  # null => use codex CLI's configured default
  timeout: 1200

gemma:                         # tunables for the gemma scanner (falls back to triage:* when null)
  base_url: null
  model: null
  keep_alive: null
  timeout: 1800
  max_files: 60                # cap to keep prompt size bounded
  max_file_bytes: 12000
  max_total_bytes: 200000

cross_validate:                # only active when both scanners.codex AND scanners.gemma are true
  enabled: true
  codex_timeout: 300
  gemma_timeout: 180

paths:
  exclude: ["archive/", "vendor/", ".github/scripts/"]

severity_floor: "low"          # info | low | medium | high | critical

triage:                        # optional Gemma triage (issue prose / fuzzy dedup / Slack intro)
  enabled: false
  provider: "ollama"
  model: "gemma4:26b"
  base_url: "http://host.docker.internal:11434"
  keep_alive: "5m"
  prewarm: true
  intro_timeout: 120
  intro_enabled: true
  prose_enabled: false
  fuzzy_dup_enabled: false

slack:
  enabled: false
  webhook_url_env: "SLACK_WEBHOOK_URL"        # OR channel_id_env + bot_token_env
```

Token and any Slack secret arrive via **env** (the container reads `os.environ[...]`),
never written into `config.yaml`. 1Password / Docker secrets can populate those env
vars on the host.

The whole **`config/` directory** is the bind‑mount unit. A `secrets.source: 1password`
setup keeps the `.env.1password.tpl` file inside the same directory so it rides along.

---

## 8. Stack detection (`detect.py`)

1. **Manifest walk (primary, zero‑API, reliable):** walk the cloned tree (honoring
   `paths.exclude`) for manifests/lockfiles and map to scanners + ecosystems:
   - `package.json` + `package-lock.json` | `yarn.lock` | `pnpm-lock.yaml` → npm/yarn/pnpm (OSV)
   - `Gemfile.lock` → RubyGems (OSV); `Package.resolved` → SwiftPM (OSV)
   - `requirements.txt` | `poetry.lock` | `Pipfile.lock` → pip (OSV)
   - `go.mod`/`go.sum` → Go (OSV); `Cargo.lock` → Rust (OSV)
   - any source files → Semgrep (its own language autodetect); whole tree → Gitleaks
2. **Whole‑tree scanners** (Trivy, Trufflehog, Syft) run once on the repo root, no manifest gating.
3. **Framework detection** — currently surfaces `supabase` when `supabase/config.toml`
   exists or `@supabase/supabase-js` is in any `package.json`. Used to enable the
   Supabase Semgrep rule pack.
4. **LLM scanners** (codex, gemma) run only when there's at least one recognized source file.
5. Stacks with no available scanner → printed as "detected, no scanner" and skipped (don't fail the run).

Handles monorepos: there can be many manifests in many dirs.

---

## 9. Scanners (`runners/`) — all emit SARIF (or are normalized to it); none execute repo code

- **OSV‑Scanner** — `osv-scanner --format sarif --recursive <root>` (parses lockfiles;
  no install). Covers npm/yarn/pnpm, RubyGems, SwiftPM, pip, Go, Cargo from one tool.
- **Gitleaks** — `gitleaks detect --report-format sarif --source <root>` (git‑history
  aware; emits a per‑secret fingerprint).
- **Semgrep** — `semgrep scan --config <bundled-rules> --sarif --metrics=off …` (static;
  bundled rule packs include `javascript`, `python`, `secrets`, `xss`, `sqli`, `supabase`).
- **Trivy** — `trivy <vuln+secret+iac+license>` against the cloned tree; SARIF output;
  multi‑category normalization in `normalize.py`.
- **Trufflehog** — JSONL output (not SARIF), normalized in `normalize.py`. `--only-verified`
  surfaces secrets the scanner validated live against the vendor (CWE‑798 critical).
- **Syft** — produces a CycloneDX SBOM JSON written to `/work/`. No project items filed;
  the runner's "SARIF" is a tiny metadata wrapper so the orchestrator can log + reference it.
- **Codex** (optional) — `codex exec -s read-only --output-schema schema.json -o out.json …`
  with a strict JSON output contract. Subscription auth (`codex login`); no API key.
  `extra["scanner"] = "codex"`; rule_ids namespaced `codex.<id>`.
- **Gemma** (optional) — Ollama `/api/chat` with `format=json`, batched source files
  (capped by file count + per‑file bytes + total bytes). Same JSON contract as codex.
  `extra["scanner"] = "gemma"`; rule_ids namespaced `gemma.<id>`.

Pin scanner versions (in the Dockerfile) so "new vs resolved" diffing isn't polluted by
the scanners themselves changing. Each runner returns SARIF JSON (or `None` + a "did
not complete" flag — which must keep that category out of any future close logic the
external system builds).

---

## 10. Gemma 4 triage (`triage.py`) — optional, guard‑railed

Distinct from the **gemma scanner** (which produces findings). Triage is post‑processing:

1. **Fuzzy dedup tie‑break** — for findings whose deterministic fp is new, decide if it's
   actually a renamed/moved version of an existing item. (Off by default;
   `triage.fuzzy_dup_enabled`.)
2. **Prose** — draft issue title/body. (Off by default; `triage.prose_enabled`.)
3. **Slack intro** — one short framing sentence prepended to the deterministic per‑category
   Slack digest. (On by default; `triage.intro_enabled`.)

Guardrails (in code, not the prompt): validate every JSON response against its schema and
fall back to deterministic output on malformed responses; feed only the scanner's factual
fields (never invent fix versions); the deterministic marker + masked previews are injected
by code regardless of what the model returns. If Ollama is unreachable, the run still
completes — every Gemma path has a deterministic fallback.

---

## 11. Cross‑validation (`cross_validate.py`) — optional, off unless both LLM scanners enabled

When `scanners.codex` AND `scanners.gemma` are both true:

1. For every Codex finding → ask Gemma (via Ollama): "real / false_positive / uncertain
   + brief reason".
2. For every Gemma finding → ask Codex (via subprocess): same prompt.
3. Annotate `finding.extra["cross_validation"]` with the verdict + reason.
4. If verdict is `false_positive`: downgrade severity one notch (`high → medium`,
   `medium → low`, `low → info`). **`critical` is asymmetric — it NEVER auto‑downgrades.**
   The cost of missing a real critical is higher than the cost of one noisy critical
   in the board.
5. **Findings are NEVER suppressed.** Disagreement is surfaced via the annotation;
   humans triage on the project board.

If either validator is unreachable, the verdict for that direction is `uncertain` and
severity stays unchanged — never block the run on a validator failure.

---

## 12. Docker & secrets

```
Dockerfile: python:3.11-slim + pinned osv-scanner, gitleaks, semgrep, trivy, trufflehog, syft, git

Volumes (bind-mounted at runtime — no VOLUME directive, so anonymous volumes never
accumulate when --rm is used):
  /config   (ro)  -> the user's whole config directory (config.yaml + .env.1password.tpl + …)
  /rules    (ro)  -> optional override of the image-baked semgrep rules
  /work     (rw)  -> ephemeral per-run clone + SBOM output (wiped each run)

Secrets:
  GITHUB_TOKEN, SLACK_* via env (docker run --env-file, Docker secret, or 1Password injection)

Entrypoint:
  python -m security_scan --config /config/config.yaml --work-dir /work
```

Stateless: the container holds no state between runs; everything durable is in GitHub
Issues + the Projects v2 board. The clone lives in `/work` and is wiped each run.

**Image manifest** (`/app/SECURITY-SCAN-MANIFEST.yaml`) — see §15.

---

## 13. Execution flow (`main.py`)

```
1.  load config + token  (fail fast if token missing / project unresolved)
2.  shallow|full clone repo@ref into /work
3.  resolve Projects v2 board (GraphQL); idempotently ensure Severity + Category single-select fields
4.  detect stack -> list of (scanner, targets)
5.  run each enabled+relevant scanner -> SARIF/JSON  (record which completed)
6.  normalize results -> Findings ; drop paths in exclude ; drop < severity_floor
7.  if both codex AND gemma ran -> cross_validate.cross_validate(findings, …)
8.  fingerprint each Finding (or use SARIF-supplied fingerprint)
9.  list existing project items -> existing fingerprints
10. for each new fingerprint:
      (optional Gemma fuzzy-dup check) -> create_issue + add_to_project + set Severity/Category
11. (optional) Slack digest (Gemma-written intro + deterministic per-category sections)
12. print a deterministic summary (created N, skipped M dup, scanners run/failed)
```

A scanner that did NOT complete contributes ZERO findings — so a crashed scanner never
reads as "all clear" to downstream tooling.

---

## 14. Test plan

- **Unit:** fingerprint stability (same finding across line shifts → same fp; rename →
  different fp, caught by fuzzy pass); marker round‑trip (inject → parse); legacy marker
  compat; SARIF→Finding for one fixture per scanner; severity normalization; exclude‑path
  filtering; masked‑preview never contains the raw value.
- **Dedup logic:** given a fixture set of existing project items (open + closed) and a
  finding set, assert create‑only + never‑re‑file (closed fp ⇒ skipped).
- **Cross‑validation:** unit‑tested with mocked Ollama HTTP and mocked codex subprocess.
  Verifies asymmetric downgrade (critical never), never‑suppress invariant, and graceful
  degradation when a validator is unreachable.
- **GraphQL ops:** mocked `requests.Session` — resolve_project, list_project_items
  (paginated), add_to_project, set_project_field; dry‑run path makes zero HTTP calls.
- **Scanner integration:** run each scanner against a tiny synthetic repo with one
  planted issue each; assert SARIF parses and the finding surfaces.
- **Graceful degradation:** Ollama down → deterministic path still files issues; a
  scanner binary missing → that category skipped with a note, others unaffected.
- **End‑to‑end dry‑run:** `--dry-run` (no issue creation) prints what *would* be filed.
  Verifies the project resolution + listing path against a real board.
- **Safety:** assert no `npm install`/`bundle install`/`pod install` is ever invoked;
  assert the token never appears in logs or issue bodies; codex sandbox is `read-only`;
  raw secrets are never in issue bodies.

---

## 15. Image manifest contract

The image bakes `SECURITY-SCAN-MANIFEST.yaml` at `/app/SECURITY-SCAN-MANIFEST.yaml`.
Only the `:latest` tag is published on Docker Hub; each push gets a new
immutable digest that consumers watch via the registry API. Consumers read
the manifest without starting the scanner:

```bash
docker run --rm --entrypoint cat \
  leverj/security-scan:latest /app/SECURITY-SCAN-MANIFEST.yaml
```

The `version` field inside the manifest is the human-readable identifier
(shown to users in upgrade prompts). It is **not** mirrored as a docker tag —
the tag is always `:latest`; identity is the digest.

Top‑level keys:

| Key | Purpose |
|---|---|
| `version` | Image version (human-readable identifier; matches `pyproject.toml`). Surfaced in upgrade prompts. |
| `config_schema_version` | Bumps only when the YAML schema changes in a breaking way. |
| `docker_image` | Full repo name (`leverj/security-scan`) for use by consumers. |
| `released` | Release date. |
| `changelog` | Short bullet list — surfaced verbatim to the user on the upgrade prompt. |
| `breaking_changes` | List of `{id, summary, user_action}` items requiring explicit user confirmation. |
| `config.new_fields` | Fields the consumer should ADD to a user's config.yaml when missing, with documented defaults. |
| `config.renamed_fields` | Fields the consumer should rename in place. May require user input where the rename isn't 1:1. |
| `config.removed_fields` | Fields the consumer should strip with confirmation. |
| `image_paths` | Documentation of where things live inside the image (mount targets, source). |

The `publish` subcommand of `security-scan.sh` refuses to push unless
`pyproject.toml`'s version and the manifest's version match. This is the
contract that lets the consumer skill in `leverj/ai-skills` evolve in lockstep
with the image — schema migration is declared by the image, not coded into
the skill.

---

## 16. Build/release flow

1. Develop on a feature branch; CI lints + tests + does a no‑push docker build on each PR.
2. Merge to `main`.
3. Run `./security-scan.sh publish` from your local shell (you must be
   `docker login`'d). The script:
   - Verifies `pyproject.toml`'s version matches the manifest's.
   - Builds multi‑arch (amd64 + arm64) with `--sbom=true --provenance=mode=max`.
   - Pushes ONLY `leverj/security-scan:latest`.
   - Smoke‑tests the manifest is readable from the just‑pushed image and
     prints the new digest.
4. The companion skill in `leverj/ai-skills` (or any other consumer) sees
   that `:latest` has a new digest (queried via Docker Hub's API or
   `docker manifest inspect`), pulls the new image, fetches the candidate
   manifest, surfaces the changelog + migrations to the user, and applies
   them on confirmation.

We deliberately don't publish per‑version tags. Each push to `:latest`
creates a new immutable digest; the digest is the identity. Rollbacks are
done by pinning a specific digest in the consumer's state (the skill stores
`pinned_digest` for exactly this purpose).

---

## 17. Lineage & deferred roadmap

- v1 generalized `ezel_scan.py` (a hand‑rolled per‑repo scanner) into a generic, Dockerized
  single‑repo tool using parent‑epic + sub‑issue storage.
- v2 (this spec) drops the sub‑issue tree in favor of Projects v2 (lifts the 100‑item cap,
  adds custom fields, simpler triage UI), adds Codex + Gemma LLM SAST + cross‑validation,
  and adds the image manifest contract for consumer skills.
- Deferred, in rough order: GitHub App auth → multi‑repo + parallelism (per‑project state) →
  DAST/pen‑test lane (staging only, authorized targets) → Live Supabase Security Advisor
  parity (DB‑connected lane, see [`leverj/security-scanner#4`](https://github.com/leverj/security-scanner/issues/4)) →
  DefectDojo/Dependency‑Track aggregation when correlating many tools/repos → CISO/GRC
  dashboard as an always‑on backend the daily job feeds.
