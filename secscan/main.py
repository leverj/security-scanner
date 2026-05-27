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
            {"osv": cfg.scanners.osv, "gitleaks": cfg.scanners.gitleaks, "semgrep": cfg.scanners.semgrep},
            exclude=cfg.paths.exclude,
        )
        _log_detection(detection)

        findings, completed_scanners, failed = _scan_and_normalize(detection, cfg, repo_dir)
        _log_scanner_summary(completed_scanners, failed)

        triage = _maybe_triage(cfg)

        if dry_run:
            print(f"DRY-RUN: would sync {len(findings)} findings against parent #{cfg.parent_issue}", file=sys.stderr)
        result = sync(findings, gh, cfg.parent_issue, severity_floor=cfg.severity_floor, triage=triage)

        # Slack digest (additive, never blocking).
        if cfg.slack.enabled:
            digest = triage.write_slack_digest(findings, result, cfg.repo, cfg.ref, cfg.parent_issue) if (triage and triage.enabled) else None
            post_digest(cfg.slack, findings, result, cfg.repo, cfg.ref, cfg.parent_issue, digest_text=digest)

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
) -> tuple[list[Finding], list[str], list[tuple[str, str]]]:
    """Run each detected scanner once; collect normalized findings.

    OSV is invoked once per detected ecosystem-dir. Gitleaks/Semgrep run once
    against the whole tree. A scanner that fails contributes zero findings (so
    a crashed scanner never reads as 'all clear').
    """
    findings: list[Finding] = []
    completed: set[str] = set()
    failed: list[tuple[str, str]] = []

    # Group osv targets so we run osv once per dir; gitleaks/semgrep once total.
    osv_targets = [t for t in detection.targets if t.scanner == "osv"]
    other_targets = [t for t in detection.targets if t.scanner != "osv"]

    semgrep_rules = _resolve_semgrep_rules(cfg)

    for t in osv_targets:
        result = _invoke_runner(t, cfg, repo_dir, semgrep_rules)
        _absorb(result, t, cfg.paths.exclude, findings, completed, failed)

    seen_other: set[str] = set()
    for t in other_targets:
        if t.scanner in seen_other:
            continue
        seen_other.add(t.scanner)
        result = _invoke_runner(t, cfg, repo_dir, semgrep_rules)
        _absorb(result, t, cfg.paths.exclude, findings, completed, failed)

    return findings, sorted(completed), failed


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
    return RunnerResult(t.scanner, None, False, f"unknown scanner: {t.scanner}")


def _absorb(
    result: RunnerResult,
    t: ScannerTarget,
    exclude: list[str],
    findings: list[Finding],
    completed: set[str],
    failed: list[tuple[str, str]],
) -> None:
    if not result.completed or result.sarif is None:
        failed.append((t.scanner, result.error or "unknown error"))
        print(f"scanner {t.scanner}: NOT COMPLETED ({result.error})", file=sys.stderr)
        return
    completed.add(result.scanner)
    findings.extend(normalize_sarif(result.sarif, result.scanner, exclude=exclude))


def _resolve_semgrep_rules(cfg: Config) -> Path | str | None:
    """Resolve the Semgrep rules dir/config. Order:
      1. cfg.semgrep_rules_dir (explicit path)
      2. /rules (Docker mount per spec §11)
      3. <package>/rules (bundled, when installed editable)
      4. "auto" — Semgrep's hosted rule pack (last resort; needs network)
    """
    if cfg.semgrep_rules_dir:
        return cfg.semgrep_rules_dir
    if Path("/rules").is_dir():
        return Path("/rules")
    bundled = Path(__file__).parent / "rules"
    if bundled.is_dir() and any(bundled.iterdir()):
        return bundled
    # Last resort: Semgrep's hosted registry (only useful if the container has network)
    return "auto"


def _maybe_triage(cfg: Config):
    if not cfg.triage.enabled:
        return None
    try:
        # Lazy import to avoid touching `requests` when triage is off.
        from secscan.triage import Triage
        return Triage(cfg.triage)
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
