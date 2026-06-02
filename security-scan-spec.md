# security-scan — Architecture & Build Spec (v1)

A single‑repo, stateless, self‑hosted security scanner that detects a repo's tech stack,
runs the right scanners, and files each finding as a deduplicated GitHub sub‑issue under a
user‑provided parent issue. Optional local‑LLM (Gemma 4) triage and Slack digest. Closing /
fixing findings is **out of scope** — another system owns that.

This document is written to be handed to Claude Code and built module by module.

---

## 1. Goals & non‑goals

**Goals (v1)**
- Generic: nothing org‑specific. A user supplies a repo, a branch, a parent issue number, and a token; it works for anyone.
- Stateless container: no internal database. All persistent state lives in **GitHub Issues**. Config + secrets come from mapped volumes / env.
- Auto‑detect the stack and run only the relevant scanners.
- Deterministic, auditable dedup. The LLM never owns correctness‑critical decisions.
- "Model proposes, code disposes" — irreversible actions (create issue, post Slack) are deterministic Python; the model only enriches.

**Non‑goals (explicitly deferred)**
- Closing / reopening / fixing issues (external system).
- A local file DB (GitHub Issues is the state).
- Multi‑repo orchestration, parallel scanning, GitHub App auth.
- DAST / pen‑test lane, DefectDojo, CISO/compliance dashboard, CISO Assistant.
- Hostile‑repo sandboxing (v1 assumes you scan **your own** repo — trusted code).

---

## 2. Locked design decisions

| # | Decision | Rationale |
|---|----------|-----------|
| Dedup | **Deterministic fingerprint is the source of truth; Gemma is a fuzzy tie‑breaker + prose writer only.** | Reproducible, auditable. The LLM can't dup‑spam or silently drop a finding. |
| Create rule | **Dedup against OPEN *and* CLOSED sub‑issues; never re‑file a fingerprint that already exists in any state.** | Simplest, quietest. Any closed issue (fixed or won't‑fix) permanently suppresses re‑filing. Accepted blind spot: a fixed‑then‑regressed finding is not re‑surfaced (that's the external fixing system's concern). |
| State | **GitHub Issues only.** No file DB in v1. | Dedup needs only the set of existing sub‑issues (open+closed) + their embedded fingerprints. |
| LLM | **Optional.** Core path is fully deterministic and runs with no GPU/model. Gemma adds triage/prose/fuzzy‑match when available. | "Generic, anyone can run it" must not require a GPU. |
| Auth | **PAT via env** (1Password/Docker‑secret injection optional). | Single repo, single owner. (GitHub App deferred to the multi‑tenant version.) |
| Concurrency | **Sequential.** | One repo, daily cadence. |
| Repo execution | **Never execute repo code.** Lockfile parsing + static analysis only. | Safety; matches the proven `ezel_scan.py` discipline. |

---

## 3. Module breakdown

```
security-scan/
  config.py        # load + validate config (YAML) and env (token)
  detect.py        # stack detection (manifest walk + optional Linguist cross-check)
  runners/         # one module per scanner, each returns SARIF (or is normalized to it)
    osv.py         # OSV-Scanner  (SCA: npm/yarn/pnpm, RubyGems, SwiftPM, pip, go, cargo, ...)
    gitleaks.py    # Gitleaks     (secrets, git-history aware)
    semgrep.py     # Semgrep      (SAST, bundled offline ruleset)
  normalize.py     # SARIF -> internal Finding model (one shape for all scanners)
  fingerprint.py   # deterministic, line-number-free fingerprint + marker (de)serialize
  github.py        # clone, list sub-issues (open+closed), create issue, link sub-issue
  triage.py        # OPTIONAL Gemma 4 (Ollama): fuzzy-dedup tie-break + issue/Slack prose
  notify.py        # OPTIONAL Slack digest
  sync.py          # the create-decision logic (dedup -> create-only)
  main.py          # orchestrator: config -> clone -> detect -> run -> normalize ->
                   #               fingerprint -> sync -> notify
```

**Hard dependency boundary:** `detect/runners/normalize/fingerprint/github/sync` are deterministic and must work with `triage.py` and `notify.py` absent or failing. `triage` and `notify` are strictly additive.

---

## 4. Internal Finding model

Everything normalizes to this one shape (from SARIF). Keep it small and scanner‑agnostic.

```python
@dataclass
class Finding:
    scanner: str           # "osv" | "gitleaks" | "semgrep"
    category: str          # "dependency" | "secret" | "sast"
    rule_id: str           # e.g. "GHSA-xxxx", "generic-api-key", "ezel-command-injection"
    severity: str          # normalized: critical|high|medium|low|info
    file_path: str         # repo-relative, forward slashes
    line: int | None       # for display only — NEVER part of the fingerprint
    title: str             # short, human title (deterministic default; Gemma may rewrite)
    message: str           # scanner message / advisory summary
    masked_preview: str    # for secrets: masked value only — NEVER the raw secret
    sarif_fingerprint: str | None   # SARIF partialFingerprints/fingerprints if present
    extra: dict            # ecosystem, installed/fixed version, CVE/GHSA, range, etc.
```

**Severity normalization:** map each tool's scale to `critical/high/medium/low/info`. SARIF `level` (error/warning/note) + `security-severity` property → normalized severity.

---

## 5. Fingerprint & marker

**Primary identity (deterministic, line‑number‑free):**
```
key_basis = rule_id + "\0" + file_path + "\0" + snippet_or_secretfp
fingerprint = "fp_" + sha256(key_basis).hexdigest()[:16]
```
- Prefer the SARIF‑provided `fingerprints` / `partialFingerprints` when the tool emits them (most do) — they're designed for exactly this and survive line drift.
- `snippet_or_secretfp`: for SAST, a whitespace‑normalized snippet of the matched region (or the enclosing symbol name); for secrets, the scanner's hash of the value (Gitleaks emits one) — **never the raw secret**; for deps, empty (rule_id already = GHSA/CVE which is unique per package‑advisory). Result is stable across line moves.
- **Line numbers are excluded** so reformatting/refactoring doesn't spawn duplicates.

**Marker** embedded in every issue body (hidden HTML comment), so a future run can read it back:
```
<!-- security-scan: fp=fp_ab12cd34ef56 rule=GHSA-xxxx cat=dependency -->
```

`github.py` lists **all** sub‑issues of the parent (state=all), parses these markers, and builds the set of already‑filed fingerprints.

---

## 6. Create‑decision logic (`sync.py`)

```
existing_fps = { marker.fp for issue in github.list_subissues(parent, state="all")
                            if marker := parse_marker(issue.body) }

for f in findings:
    fp = f.sarif_fingerprint or compute_fingerprint(f)

    if fp in existing_fps:
        continue                      # already filed (open OR closed) -> never re-file

    # OPTIONAL fuzzy tie-break (only if Gemma available): catch renamed/moved code that
    # changed file_path (and thus fp). Ask Gemma: does this finding match any existing
    # issue's (rule + snippet) at a different path with high confidence?
    if triage.enabled and triage.is_duplicate_of_existing(f, existing_issues):
        continue

    title, body = triage.write_issue(f) if triage.enabled else default_issue(f)
    body = inject_marker(body, fp, f)              # always inject the deterministic marker
    issue = github.create_issue(title, body)       # create-only
    github.link_subissue(parent, issue)
    existing_fps.add(fp)                           # avoid intra-run dupes
```

**Invariants (enforced in `github.py`, not trusted to the model):**
- Create and link only. **No** edit/close/reopen/delete of issues.
- The deterministic marker is always injected by code, even if Gemma wrote the prose.
- Never write a raw secret into a body — only `masked_preview`.
- A scanner that did **not** run/complete contributes **no** findings (so a crashed scanner can't look like "all clear").

---

## 7. Config schema (`config.yaml`, mounted read‑only)

```yaml
repo: "leverj/ezel"            # owner/name
ref: "dev"                     # branch
parent_issue: 451              # user creates this; tool files sub-issues under it
github_token_env: "GITHUB_TOKEN"   # name of env var holding the PAT (value never in config)

scanners:                      # which to run; auto-skipped if stack not present
  osv: true
  gitleaks: true
  semgrep: true

paths:
  exclude: ["archive/", "vendor/", ".github/scripts/"]   # globs skipped everywhere

severity_floor: "low"          # don't file below this (info-only by default)

triage:                        # all optional
  enabled: false
  provider: "ollama"
  model: "gemma4:26b"
  base_url: "http://host.docker.internal:11434"
  keep_alive: "5m"

slack:
  enabled: false
  channel_id_env: "SLACK_CHANNEL_ID"   # or a webhook URL via env
```

Token and any Slack secret arrive via **env** (the container reads `os.environ[...]`), never written into `config.yaml`. 1Password / Docker secrets can populate those env vars on the host.

---

## 8. Stack detection (`detect.py`)

1. **Manifest walk (primary, zero‑API, reliable):** walk the cloned tree (honoring `paths.exclude`) for manifests/lockfiles and map to scanners + ecosystems:
   - `package.json` + `package-lock.json` | `yarn.lock` | `pnpm-lock.yaml` → npm/yarn/pnpm (OSV)
   - `Gemfile.lock` → RubyGems (OSV);  `Package.resolved` → SwiftPM (OSV)
   - `requirements.txt` | `poetry.lock` | `Pipfile.lock` → pip (OSV)
   - `go.mod`/`go.sum` → Go (OSV);  `Cargo.lock` → Rust (OSV)
   - any source files → Semgrep (its own language autodetect); whole tree → Gitleaks
2. **GitHub Linguist cross‑check (optional hint):** `GET /repos/{o}/{r}/languages` as a sanity check that the walk didn't miss a language. Do **not** rely on it as the only source (it misses ecosystems/lockfiles and odd monorepo layouts).
3. Stacks with no available scanner → printed as "detected, no scanner" and skipped (don't fail the run).

Handles monorepos: there can be many manifests in many dirs (e.g. `ezel` had npm in 5 locations + Swift + RubyGems).

---

## 9. Scanners (`runners/`) — all emit SARIF, never execute repo code

- **OSV‑Scanner** — `osv-scanner --format sarif --recursive <root>` (parses lockfiles; no install). Covers npm/yarn/pnpm, RubyGems, SwiftPM, pip, Go, Cargo from one tool.
- **Gitleaks** — `gitleaks detect --report-format sarif --source <root>` (git‑history aware; emits a per‑secret fingerprint).
- **Semgrep** — `semgrep scan --config <bundled-rules> --sarif --metrics=off --exclude archive` (static; bundle the JS/TS/React + Swift/iOS + Android rules from `ezel_scan.py` so no network rule fetch).

Pin scanner versions (in the Dockerfile) so "new vs resolved" diffing isn't polluted by the scanners themselves changing. Each runner returns SARIF JSON (or `None` + a "did not complete" flag — which must keep that category out of any future close logic the external system builds).

---

## 10. Gemma 4 triage (`triage.py`) — optional, guard‑railed

Talks to Ollama (`/api/chat` with `tools` for native function calling; `keep_alive` so the ~16 GB model loads only during the run and frees ~5 min after). Three jobs, all additive:

1. **Fuzzy dedup tie‑break** — for findings whose deterministic fp is new, decide if it's actually a renamed/moved version of an existing issue (returns an existing issue number or "new"). Must cite the finding it's judging.
2. **Prioritization / context** — order findings, add a one‑line "why this matters" using only the scanner's factual fields. Must **not** lower severity below `severity_floor` without an explicit flagged reason.
3. **Prose** — draft issue title/body and the Slack digest text.

Guardrails (in code, not the prompt): validate every tool call against its JSON schema and reject/retry malformed ones; feed only the scanner's factual fields (never invent fix versions); the deterministic marker + masked previews are injected by code regardless of what the model returns. If Ollama is unreachable or `triage.enabled=false`, fall back to deterministic `default_issue()` templating — the run still completes.

---

## 11. Docker & secrets

```
Dockerfile: python:3.x-slim + pinned osv-scanner, gitleaks, semgrep, git
Volumes:
  /config   (ro)   -> config.yaml
  /rules    (ro)   -> bundled semgrep rules (or baked into the image)
  /work     (rw)   -> ephemeral per-run clone + scratch (can be tmpfs)
Secrets:
  GITHUB_TOKEN, SLACK_* via env (docker run --env-file, Docker secret, or 1Password injection)
Entrypoint: python -m security-scan --config /config/config.yaml
```
Stateless: the container holds no state between runs; everything durable is in GitHub Issues. The clone lives in `/work` and is wiped each run. Token file (if used instead of env) must be `600` and is never logged (mask in all output).

---

## 12. Execution flow (`main.py`)

```
1. load config + token (fail fast if token missing / parent_issue unset)
2. shallow|full clone repo@ref into /work  (full clone only if a history-secret scan is wanted)
3. detect stack -> list of (scanner, targets)
4. run each enabled+relevant scanner -> SARIF  (record which completed)
5. normalize SARIF -> Findings ; drop paths in exclude ; drop < severity_floor
6. fingerprint each Finding
7. list parent's sub-issues (open+closed) -> existing fingerprints
8. for each new fingerprint: (optional Gemma fuzzy-dup check) -> create + link sub-issue
9. (optional) Gemma-written Slack digest -> post once
10. print a deterministic summary (created N, skipped M dup, scanners run/failed)
```

---

## 13. Test plan

- **Unit:** fingerprint stability (same finding across line shifts → same fp; rename → different fp, caught by fuzzy pass); marker round‑trip (inject → parse); SARIF→Finding for one fixture per scanner; severity normalization; exclude‑path filtering; masked‑preview never contains the raw value.
- **Dedup logic:** given a fixture set of existing sub‑issues (open + closed) and a finding set, assert create‑only + never‑re‑file (closed fp ⇒ skipped).
- **Scanner integration:** run each scanner against a tiny synthetic repo with one planted issue each; assert SARIF parses and the finding surfaces.
- **Graceful degradation:** Ollama down → deterministic path still files issues; a scanner binary missing → that category skipped with a note, others unaffected.
- **End‑to‑end dry‑run:** `--dry-run` (no issue creation) prints what *would* be filed. Verify against a real repo before wiring the token.
- **Safety:** assert no `npm install`/`bundle install`/`pod install` is ever invoked; assert the token never appears in logs or issue bodies.

---

## 14. Build order for Claude Code (milestones)

1. `config.py` + `Finding` model + `fingerprint.py` (+ unit tests) — the deterministic core.
2. `github.py` (clone, list sub‑issues open+closed, create+link) with a `--dry-run`.
3. `runners/` + `normalize.py` for one scanner (Semgrep), end‑to‑end on a synthetic repo.
4. Add OSV‑Scanner + Gitleaks runners.
5. `detect.py` (manifest walk) + `sync.py` (create‑decision) → full deterministic pipeline.
6. Dockerfile + volumes + env secrets; dry‑run in container against a real repo.
7. `notify.py` (Slack) — optional.
8. `triage.py` (Gemma 4 via Ollama) — optional, last; everything must already work without it.

Ship after step 6 as a working deterministic tool; 7–8 are additive.

---

## 15. Lineage & deferred roadmap

- v1 generalizes the proven `ezel_scan.py` (stack detection, secret masking, conservative create‑only sub‑issue sync, bundled Semgrep rules) into a config‑driven, Dockerized, single‑repo tool.
- Deferred, in rough order: GitHub App auth → multi‑repo + parallelism (WAL or per‑repo state) → DAST/pen‑test lane (staging only, authorized targets) → DefectDojo/Dependency‑Track aggregation when correlating many tools/repos → CISO/GRC dashboard (CISO Assistant for compliance) as an always‑on backend the daily job feeds.
