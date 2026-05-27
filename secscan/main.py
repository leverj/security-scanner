"""Orchestrator: config -> clone -> detect -> run -> normalize -> sync -> notify.

Fail-fast on missing token / parent_issue (handled in config.load_config). A
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

from secscan.config import Config, ConfigError, load_config
from secscan.detect import DetectionResult, ScannerTarget, detect_stack
from secscan.github import GitHub, GitHubError
from secscan.models import Finding
from secscan.normalize import normalize_sarif
from secscan.notify import post_digest
from secscan.runners import RunnerResult
from secscan.sync import SyncResult, sync


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secscan",
        description="Stateless single-repo security scanner; files findings as GitHub sub-issues.",
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
    work_root = Path(work_dir) if work_dir else Path(tempfile.mkdtemp(prefix="secscan-"))
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
        _log_scanner_summary(completed_scanners, failed)
        for sbom in sbom_artifacts:
            print(
                f"sbom: {sbom.get('format')} -> {sbom.get('path')} ({sbom.get('components')} components)",
                file=sys.stderr,
            )

        triage = _maybe_triage(cfg)

        if dry_run:
            print(f"DRY-RUN: would sync {len(findings)} findings against parent #{cfg.parent_issue}", file=sys.stderr)
        result = sync(findings, gh, cfg.parent_issue, severity_floor=cfg.severity_floor, triage=triage)

        # Slack digest (additive, never blocking). We hand it the ACTIONABLE
        # findings (the ones we actually filed); notify._default_digest also
        # reads result.created_findings as the canonical source.
        if cfg.slack.enabled:
            intro = (
                triage.write_slack_intro(
                    result.created_findings, result, cfg.repo, cfg.ref, cfg.parent_issue
                )
                if (triage and triage.enabled)
                else None
            )
            post_digest(
                cfg.slack, result.created_findings, result,
                cfg.repo, cfg.ref, cfg.parent_issue, intro=intro,
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
    mod = importlib.import_module(f"secscan.runners.{t.scanner}")
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
    return RunnerResult(t.scanner, None, False, f"unknown scanner: {t.scanner}")


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
        from secscan.triage import Triage
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
