"""Orchestrator: config -> clone -> detect -> run -> normalize -> sync -> notify.

Fail-fast on missing token / project config (handled in config.load_config). A
scanner that did NOT complete contributes ZERO findings — so a crashed scanner
can never look like "all clear" to downstream tooling.
"""

from __future__ import annotations

import argparse
import importlib
import shutil
import sys
import tempfile
from pathlib import Path

from security_scan.config import Config, ConfigError, load_config
from security_scan.detect import DetectionResult, ScannerTarget, detect_stack
from security_scan.github import GitHub, GitHubError
from security_scan.models import Finding
from security_scan.normalize import normalize_sarif
from security_scan.notify import post_digest
from security_scan.runners import RunnerResult
from security_scan.sync import SyncResult, sync


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="security_scan",
        description="Stateless single-repo security scanner; files findings into a GitHub Projects v2 board.",
    )
    parser.add_argument("--config", required=True, help="Path to config.yaml")
    parser.add_argument("--dry-run", action="store_true", help="Detect/scan/normalize but do not create any GitHub issues")
    parser.add_argument("--work-dir", default=None, help="Where to clone the repo (default: a tempdir under /tmp)")
    parser.add_argument("--keep-work", action="store_true", help="Keep the cloned tree after the run")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    return run(cfg, dry_run=args.dry_run, work_dir=args.work_dir, keep_work=args.keep_work)


def run(cfg: Config, dry_run: bool = False, work_dir: str | None = None, keep_work: bool = False) -> int:
    work_root = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="security_scan-"))
    repo_dir = work_root / cfg.repo_name

    gh = GitHub(cfg.github_token, cfg.repo_owner, cfg.repo_name, dry_run=dry_run)

    try:
        print(f"clone: {cfg.repo}@{cfg.ref} -> {repo_dir}", file=sys.stderr)
        if repo_dir.exists():
            shutil.rmtree(repo_dir)
        gh.clone(cfg.ref, repo_dir, shallow=True)

        detection = detect_stack(
            repo_dir,
            {
                "osv":        cfg.scanners.osv,
                "gitleaks":   cfg.scanners.gitleaks,
                "semgrep":    cfg.scanners.semgrep,
                "trivy":      cfg.scanners.trivy,
                "trufflehog": cfg.scanners.trufflehog,
                "syft":       cfg.scanners.syft,
            },
            exclude=cfg.paths.exclude,
        )
        _log_detection(detection)

        findings, completed_scanners, failed, sbom_artifacts = _scan_and_normalize(detection, cfg, repo_dir)
        _scan_images(cfg, repo_dir, findings, completed_scanners, failed)
        _scan_supabase_live(cfg, findings, completed_scanners, failed)
        _log_scanner_summary(completed_scanners, failed)
        for sbom in sbom_artifacts:
            print(
                f"sbom: {sbom.get('format')} -> {sbom.get('path')} ({sbom.get('components')} components)",
                file=sys.stderr,
            )

        # Cross-validation: if both codex AND gemma ran, each tool reviews the other's
        # findings. Strictly additive — bad reviews downgrade severity but never drop.
        if (cfg.cross_validate.enabled
                and "codex" in completed_scanners
                and "gemma" in completed_scanners):
            from security_scan.cross_validate import cross_validate
            before = sum(1 for f in findings if f.scanner in ("codex", "gemma"))
            print(f"cross-validate: reviewing {before} LLM finding(s) bidirectionally", file=sys.stderr)
            cross_validate(
                findings,
                repo_dir=repo_dir,
                codex_enabled=True, gemma_enabled=True,
                codex_binary=cfg.codex.binary, codex_model=cfg.codex.model,
                codex_timeout=cfg.cross_validate.codex_timeout,
                ollama_url=(cfg.gemma.base_url or cfg.triage.base_url),
                gemma_model=(cfg.gemma.model or cfg.triage.model),
                gemma_keep_alive=(cfg.gemma.keep_alive or cfg.triage.keep_alive),
                gemma_timeout=cfg.cross_validate.gemma_timeout,
            )

        triage = _maybe_triage(cfg)

        # Resolve the Projects v2 target (and ensure Severity/Category fields exist).
        # Fails fast with a clear message if the PAT lacks the 'project' scope or
        # the project number is wrong.
        project = gh.resolve_project(cfg.project.owner, cfg.project.number)
        print(
            f"project: {cfg.project.owner}/projects/{cfg.project.number} resolved",
            file=sys.stderr,
        )

        if dry_run:
            print(
                f"DRY-RUN: would sync {len(findings)} findings into "
                f"{cfg.project.owner}/projects/{cfg.project.number}",
                file=sys.stderr,
            )
        result = sync(findings, gh, project, severity_floor=cfg.severity_floor, triage=triage)

        # Slack digest (additive, never blocking). We hand it the ACTIONABLE
        # findings (the ones we actually filed); notify._default_digest also
        # reads result.created_findings as the canonical source.
        if cfg.slack.enabled:
            intro = (
                triage.write_slack_intro(
                    result.created_findings, result, cfg.repo, cfg.ref,
                    cfg.project.owner, cfg.project.number,
                )
                if (triage and triage.enabled)
                else None
            )
            post_digest(
                cfg.slack, result.created_findings, result,
                cfg.repo, cfg.ref, cfg.project.owner, cfg.project.number, intro=intro,
            )

        _print_summary(result, completed_scanners, failed, dry_run)
        # Exit 0 even when findings exist — the tool's job is to file, not to gate.
        # Non-zero only on infrastructure failure (already returned above) or all scanners failing.
        if not completed_scanners and (cfg.scanners.osv or cfg.scanners.gitleaks or cfg.scanners.semgrep):
            print("error: no scanner completed successfully", file=sys.stderr)
            return 3
        return 0

    except GitHubError as e:
        print(f"github: {e}", file=sys.stderr)
        return 4
    finally:
        # Always wipe the clone itself (it contains repo content; with the old
        # token-in-URL pattern it also held credentials). Preserving `work_root`
        # is still respected when the caller supplied one and didn't ask to keep.
        if not keep_work:
            if repo_dir.exists():
                shutil.rmtree(repo_dir, ignore_errors=True)
            # Remove the containing tempdir only when we created it ourselves.
            if work_dir is None and work_root.exists():
                shutil.rmtree(work_root, ignore_errors=True)


def _scan_and_normalize(
    detection: DetectionResult, cfg: Config, repo_dir: Path
) -> tuple[list[Finding], list[str], list[tuple[str, str]], list[dict]]:
    """Run each detected scanner once; collect normalized findings + SBOM artifacts.

    All scanners run once against the repo root. OSV-Scanner with `--recursive`
    finds every lockfile across all ecosystems in a single pass; invoking it
    per-ecosystem-dir was wasteful AND broke on Xcode-style layouts where
    `Package.resolved` is nested away from `Package.swift`. A scanner that fails
    contributes zero findings (so a crashed scanner never reads as 'all clear').
    """
    findings: list[Finding] = []
    completed: set[str] = set()
    failed: list[tuple[str, str]] = []
    sbom_artifacts: list[dict] = []

    semgrep_rules = _resolve_semgrep_rules(cfg)

    # Collapse multi-target scanners (e.g. several OSV ecosystem dirs) to a single
    # whole-tree invocation. We preserve the detected ecosystems in the printed
    # detection summary; the runner sees only one target = repo root.
    scanners_to_run: dict[str, ScannerTarget] = {}
    for t in detection.targets:
        if t.scanner in scanners_to_run:
            continue
        scanners_to_run[t.scanner] = ScannerTarget(
            scanner=t.scanner, ecosystem=None, targets=[repo_dir]
        )

    for t in scanners_to_run.values():
        result = _invoke_runner(t, cfg, repo_dir, semgrep_rules)
        _absorb(result, t, cfg.paths.exclude, findings, completed, failed, sbom_artifacts)

    return findings, sorted(completed), failed, sbom_artifacts


def _invoke_runner(t: ScannerTarget, cfg: Config, repo_dir: Path, semgrep_rules: Path | str | None) -> RunnerResult:
    """Dynamically import the runner so missing optional bits never block import-time."""
    mod = importlib.import_module(f"security_scan.runners.{t.scanner}")
    if t.scanner == "osv":
        return mod.run(t.targets[0], exclude=cfg.paths.exclude)
    if t.scanner == "gitleaks":
        return mod.run(repo_dir)
    if t.scanner == "semgrep":
        if not semgrep_rules:
            return RunnerResult("semgrep", None, False, "no semgrep rules configured")
        return mod.run(repo_dir, rules_dir=semgrep_rules, exclude=cfg.paths.exclude)
    if t.scanner == "trivy":
        return mod.run(repo_dir, exclude=cfg.paths.exclude)
    if t.scanner == "trufflehog":
        return mod.run(repo_dir, exclude=cfg.paths.exclude)
    if t.scanner == "syft":
        sbom_path = repo_dir.parent / f"sbom-{cfg.repo_name}.cyclonedx.json"
        return mod.run(repo_dir, output_path=sbom_path)
    if t.scanner == "codex":
        return mod.run(
            repo_dir,
            binary=cfg.codex.binary,
            model=cfg.codex.model,
            timeout=cfg.codex.timeout,
        )
    if t.scanner == "gemma":
        # Fall back to triage's Ollama config when gemma-specific values are unset
        # — most users only configure Ollama once.
        base_url = cfg.gemma.base_url or cfg.triage.base_url
        model = cfg.gemma.model or cfg.triage.model
        keep_alive = cfg.gemma.keep_alive or cfg.triage.keep_alive
        return mod.run(
            repo_dir,
            base_url=base_url,
            model=model,
            keep_alive=keep_alive,
            timeout=cfg.gemma.timeout,
            max_files=cfg.gemma.max_files,
            max_file_bytes=cfg.gemma.max_file_bytes,
            max_total_bytes=cfg.gemma.max_total_bytes,
            exclude=cfg.paths.exclude,
        )
    return RunnerResult(t.scanner, None, False, f"unknown scanner: {t.scanner}")


def _scan_images(
    cfg: Config, repo_dir: Path,
    findings: list[Finding], completed: list[str], failed: list[tuple[str, str]],
) -> None:
    """Image-scan lane (issue #9). Runs `trivy image` over base images parsed
    from the repo's Dockerfile(s) and, if opt-in is set, over a pulled or
    locally-built image. Findings are appended to `findings` and the scanner
    name `image:<source>` is added to completed/failed lists for the summary
    line.

    Unlike per-target scanners, this can emit multiple RunnerResults — one per
    image — so it's wired in directly rather than through `_invoke_runner`."""
    cfg_img = cfg.image_scan
    if not (cfg_img.base_images or cfg_img.built_image.enabled):
        return

    from security_scan.runners.image import ImageScanConfig as _ImageScanConfig
    from security_scan.runners.image import run as _image_run

    img_cfg = _ImageScanConfig(
        base_images=cfg_img.base_images,
        built_image_enabled=cfg_img.built_image.enabled,
        built_image_ref=cfg_img.built_image.ref,
        build_locally=cfg_img.built_image.build_locally,
        timeout=cfg_img.timeout,
        trivy_binary=cfg_img.trivy_binary,
        docker_binary=cfg_img.docker_binary,
    )

    results = _image_run(repo_dir, img_cfg)
    if not results:
        return

    any_done = False
    for r in results:
        if r.completed and r.sarif is not None:
            new = normalize_sarif(r.sarif, "image", cfg.paths.exclude)
            findings.extend(new)
            any_done = True
        elif r.error:
            # One image-scan failure shouldn't blanket-skip the others.
            failed.append((f"image:{_image_label(r)}", r.error))
    if any_done and "image" not in completed:
        completed.append("image")


def _image_label(r: RunnerResult) -> str:
    """Best-effort label for image-scan failures. SARIF carries the image_ref
    in result.properties; for outright failures (no SARIF) we fall back to
    `unknown`."""
    if not r.sarif:
        return "unknown"
    for run in (r.sarif.get("runs") or []):
        for res in (run.get("results") or []):
            ref = (res.get("properties") or {}).get("security_scan_image_ref")
            if ref:
                return str(ref)
    return "unknown"


def _scan_supabase_live(
    cfg: Config, findings: list[Finding],
    completed: list[str], failed: list[tuple[str, str]],
) -> None:
    """Live Supabase Security Advisor lane (epic #4).

    Resolves credentials from env (via the names referenced in cfg.supabase.*_env),
    opens a read-only psycopg connection, and runs the vendored lint checks.
    Failure-mode parity with other runners: a connection error contributes zero
    findings and shows up in the `failed` list, never as "all clear"."""
    if not cfg.supabase.enabled:
        return

    # Resolve env vars now — config.py validated the names are set; we fail
    # at runtime if the env vars themselves are empty.
    import os

    from security_scan.runners.supabase_live import SupabaseConnConfig
    from security_scan.runners.supabase_live import run as _supabase_run

    def _env(name: str | None) -> str | None:
        if not name:
            return None
        v = os.environ.get(name, "")
        return v or None

    dsn = _env(cfg.supabase.url_env)
    conn = SupabaseConnConfig(
        dsn=dsn,
        host=_env(cfg.supabase.host_env),
        port=cfg.supabase.port,
        dbname=_env(cfg.supabase.db_env),
        user=_env(cfg.supabase.user_env),
        password=_env(cfg.supabase.password_env),
        sslmode=cfg.supabase.sslmode,
        connect_timeout=cfg.supabase.connect_timeout,
        query_timeout_ms=cfg.supabase.query_timeout_ms,
        checks=cfg.supabase.checks,
    )
    if not dsn and not all([conn.host, conn.dbname, conn.user, conn.password]):
        failed.append(("supabase_live",
                       "credentials env var(s) unset — check your secrets pipeline"))
        return

    result = _supabase_run(conn)
    if not result.completed or result.sarif is None:
        failed.append(("supabase_live", result.error or "unknown error"))
        return
    payload = result.sarif.get("_supabase_findings") if isinstance(result.sarif, dict) else None
    if isinstance(payload, list):
        findings.extend(payload)
    if "supabase_live" not in completed:
        completed.append("supabase_live")


def _absorb(
    result: RunnerResult,
    t: ScannerTarget,
    exclude: list[str],
    findings: list[Finding],
    completed: set[str],
    failed: list[tuple[str, str]],
    sbom_artifacts: list[dict] | None = None,
) -> None:
    if not result.completed or result.sarif is None:
        failed.append((t.scanner, result.error or "unknown error"))
        print(f"scanner {t.scanner}: NOT COMPLETED ({result.error})", file=sys.stderr)
        return
    completed.add(result.scanner)
    # Syft carries an SBOM artifact descriptor, not findings. Record it for logging.
    if result.scanner == "syft" and sbom_artifacts is not None:
        meta = result.sarif.get("_syft_sbom") if isinstance(result.sarif, dict) else None
        if isinstance(meta, dict):
            sbom_artifacts.append(meta)
        return
    findings.extend(normalize_sarif(result.sarif, result.scanner, exclude=exclude))


def _resolve_semgrep_rules(cfg: Config) -> Path | str | None:
    """Resolve the Semgrep rules dir/config. Order:
      1. cfg.semgrep_rules_dir (explicit path)
      2. /rules (Docker mount per spec §11) — only if non-empty
      3. <package>/rules (bundled, when installed editable)
      4. "auto" — Semgrep's hosted rule pack (last resort; needs network)

    The /rules check requires actual content: Docker's VOLUME declaration creates
    an empty mountpoint when nothing is bind-mounted, which would otherwise mask
    the bundled rules and produce a confusing semgrep "no rules" exit 7.
    """
    if cfg.semgrep_rules_dir:
        return cfg.semgrep_rules_dir
    mount = Path("/rules")
    if mount.is_dir() and _has_rule_files(mount):
        return mount
    bundled = Path(__file__).parent / "rules"
    if bundled.is_dir() and _has_rule_files(bundled):
        return bundled
    # Last resort: Semgrep's hosted registry (only useful if the container has network)
    return "auto"


def _has_rule_files(d: Path) -> bool:
    """True iff `d` contains at least one *.yaml / *.yml / *.json file (semgrep rule formats)."""
    try:
        for p in d.rglob("*"):
            if p.is_file() and p.suffix.lower() in (".yaml", ".yml", ".json"):
                return True
    except OSError:
        return False
    return False


def _maybe_triage(cfg: Config):
    if not cfg.triage.enabled:
        return None
    try:
        # Lazy import to avoid touching `requests` when triage is off.
        from security_scan.triage import Triage
        t = Triage(cfg.triage)
        # Kick off model warm-up in the background; scans run in parallel.
        t.start_warmup()
        return t
    except Exception as e:
        print(f"triage: disabled ({e})", file=sys.stderr)
        return None


def _log_detection(d: DetectionResult) -> None:
    print(f"detect: {len(d.targets)} scanner target(s)", file=sys.stderr)
    for t in d.targets:
        eco = f"/{t.ecosystem}" if t.ecosystem else ""
        print(f"  - {t.scanner}{eco}: {len(t.targets)} target(s)", file=sys.stderr)
    for fw in d.detected_frameworks:
        print(f"  + framework: {fw} (scoped ruleset applies)", file=sys.stderr)
    for note in d.detected_no_scanner:
        print(f"  ! {note}", file=sys.stderr)


def _log_scanner_summary(completed: list[str], failed: list[tuple[str, str]]) -> None:
    if completed:
        print(f"scanners completed: {', '.join(completed)}", file=sys.stderr)
    for name, err in failed:
        print(f"scanner failed: {name} — {err}", file=sys.stderr)


def _print_summary(result: SyncResult, completed: list[str], failed: list[tuple[str, str]], dry_run: bool) -> None:
    prefix = "[DRY-RUN] " if dry_run else ""
    print(
        f"{prefix}summary: created={len(result.created)} "
        f"dup-skipped={result.skipped_dup} "
        f"fuzzy-dup-skipped={result.skipped_fuzzy_dup} "
        f"below-floor={result.skipped_floor} "
        f"total-findings={result.total_findings} "
        f"scanners-completed={len(completed)} "
        f"scanners-failed={len(failed)}",
        file=sys.stderr,
    )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(cli())
