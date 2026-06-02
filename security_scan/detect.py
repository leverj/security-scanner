"""Stack detection — manifest walk, zero-API, pure stdlib.

Walks a cloned repo tree, maps lockfiles/manifests to OSV ecosystems, and decides
which scanners (osv / gitleaks / semgrep) should run on which targets. Honours
`paths.exclude` (fnmatch globs + dir-prefix style). Linguist cross-check is out
of scope here — no HTTP from this module.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

# Always-skip dirs (regardless of user excludes) — noise + scanner-irrelevant.
_ALWAYS_SKIP = {".git", "node_modules", ".venv", "__pycache__"}

# Map of lockfile/manifest -> OSV ecosystem. Order matters only for grouping;
# we de-dup per-directory below.
_LOCK_TO_ECO: dict[str, str] = {
    "package-lock.json": "npm",
    "yarn.lock": "yarn",
    "pnpm-lock.yaml": "pnpm",
    "Gemfile.lock": "rubygems",
    "Package.resolved": "swiftpm",
    "requirements.txt": "pip",
    "poetry.lock": "pip",
    "Pipfile.lock": "pip",
    "go.mod": "go",
    "Cargo.lock": "cargo",
}

# Manifests that we recognize but have no scanner for — surface as a note.
_UNSCANNED_MANIFESTS: dict[str, str] = {
    "pom.xml": "Java/Maven",
    "build.gradle": "Java/Gradle",
    "build.gradle.kts": "Java/Gradle",
    "composer.json": "PHP/Composer",
    "pubspec.yaml": "Dart/Flutter",
}

# File extensions Semgrep handles in its built-in language set.
_SEMGREP_EXTS = {
    ".js", ".jsx", ".ts", ".tsx",
    ".py",
    ".rb",
    ".go",
    ".java",
    ".swift",
    ".kt", ".kts",
    ".c", ".h",
    ".cc", ".cpp", ".cxx", ".hpp", ".hh",
    ".php",
}


@dataclass
class ScannerTarget:
    scanner: str            # "osv" | "gitleaks" | "semgrep"
    ecosystem: str | None   # OSV ecosystem name, else None
    targets: list[Path]     # directories (osv) or root (gitleaks, semgrep)


@dataclass
class DetectionResult:
    targets: list[ScannerTarget] = field(default_factory=list)
    detected_no_scanner: list[str] = field(default_factory=list)
    detected_frameworks: list[str] = field(default_factory=list)


def _norm_rel(p: Path, root: Path) -> str:
    """Repo-relative, forward-slash. Empty string for root itself."""
    try:
        rel = p.resolve().relative_to(root.resolve())
    except ValueError:
        rel = p
    s = str(rel).replace(os.sep, "/")
    return "" if s == "." else s


def _is_excluded(rel: str, patterns: list[str]) -> bool:
    """Match rel ("a/b/c") against fnmatch globs and dir-prefix-style entries.

    Dir-prefix style: "archive/" means anything under archive/.
    Plain names: "vendor" matches the literal segment anywhere.
    """
    if not rel:
        return False
    for pat in patterns:
        if not pat:
            continue
        # Directory-prefix style: "archive/" or "archive/legacy/"
        if pat.endswith("/"):
            prefix = pat.rstrip("/")
            if rel == prefix or rel.startswith(prefix + "/"):
                return True
            continue
        # fnmatch glob — try against the full rel path AND each ancestor segment.
        if fnmatch.fnmatch(rel, pat):
            return True
        # Match any ancestor dir against the pattern, so "vendor" excludes a/vendor/b too.
        parts = rel.split("/")
        for i in range(len(parts)):
            if fnmatch.fnmatch(parts[i], pat):
                return True
            if fnmatch.fnmatch("/".join(parts[: i + 1]), pat):
                return True
    return False


def _walk(root: Path, exclude: list[str]) -> tuple[dict[Path, set[str]], set[str], bool, set[str]]:
    """Single os.walk: collect (dir -> set of lockfile names), unscanned-manifest notes,
    whether any semgrep-compatible source file exists, and detected framework hints
    (e.g. "supabase"). Frameworks unlock additional scoped rule packs without changing
    which scanners run.
    """
    by_dir: dict[Path, set[str]] = {}
    notes: set[str] = set()
    has_source = False
    frameworks: set[str] = set()

    for dirpath, dirnames, filenames in os.walk(root):
        d = Path(dirpath)
        rel_dir = _norm_rel(d, root)

        # Prune always-skip and excluded dirs in-place so os.walk doesn't descend.
        kept = []
        for name in dirnames:
            if name in _ALWAYS_SKIP:
                continue
            child_rel = f"{rel_dir}/{name}" if rel_dir else name
            if _is_excluded(child_rel, exclude):
                continue
            kept.append(name)
        dirnames[:] = kept

        for fname in filenames:
            if fname in _LOCK_TO_ECO:
                by_dir.setdefault(d, set()).add(fname)
            if fname in _UNSCANNED_MANIFESTS:
                notes.add(_UNSCANNED_MANIFESTS[fname])
            if not has_source:
                ext = os.path.splitext(fname)[1].lower()
                if ext in _SEMGREP_EXTS:
                    has_source = True
            if "supabase" not in frameworks:
                if fname == "config.toml" and d.name == "supabase":
                    frameworks.add("supabase")
                elif fname == "package.json":
                    try:
                        if "@supabase/" in (d / fname).read_text(errors="ignore"):
                            frameworks.add("supabase")
                    except OSError:
                        pass

    return by_dir, notes, has_source, frameworks


def _ecosystems_for_dir(d: Path, lockfiles: set[str]) -> list[str]:
    """Resolve which OSV ecosystems apply for a directory's lockfile set.

    Node-family special case: yarn.lock / pnpm-lock.yaml only count when a
    sibling package.json is present (per the spec). package-lock.json implies npm.
    Multiple pip lockfiles in one dir collapse to a single 'pip' entry.
    """
    has_pkg_json = (d / "package.json").is_file()
    ecos: list[str] = []

    if "package-lock.json" in lockfiles and has_pkg_json:
        ecos.append("npm")
    if "yarn.lock" in lockfiles and has_pkg_json:
        ecos.append("yarn")
    if "pnpm-lock.yaml" in lockfiles and has_pkg_json:
        ecos.append("pnpm")

    if "Gemfile.lock" in lockfiles:
        ecos.append("rubygems")
    if "Package.resolved" in lockfiles:
        ecos.append("swiftpm")

    if lockfiles & {"requirements.txt", "poetry.lock", "Pipfile.lock"}:
        ecos.append("pip")

    if "go.mod" in lockfiles:  # go.sum alone is not sufficient
        ecos.append("go")
    if "Cargo.lock" in lockfiles:
        ecos.append("cargo")

    # De-dup while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for e in ecos:
        if e not in seen:
            seen.add(e)
            out.append(e)
    return out


def detect_stack(
    root: Path,
    scanners_enabled: dict[str, bool],
    exclude: list[str] | None = None,
) -> DetectionResult:
    """Walk `root` and emit one ScannerTarget per (ecosystem, dir) plus whole-tree
    gitleaks/semgrep targets when enabled and applicable.

    `scanners_enabled` keys: "osv", "gitleaks", "semgrep". Missing keys = False.
    """
    exclude = list(exclude or [])
    by_dir, unscanned_notes, has_source, frameworks = _walk(root, exclude)

    osv_on = bool(scanners_enabled.get("osv"))
    gitleaks_on = bool(scanners_enabled.get("gitleaks"))
    semgrep_on = bool(scanners_enabled.get("semgrep"))
    trivy_on = bool(scanners_enabled.get("trivy"))
    trufflehog_on = bool(scanners_enabled.get("trufflehog"))
    syft_on = bool(scanners_enabled.get("syft"))
    codex_on = bool(scanners_enabled.get("codex"))
    gemma_on = bool(scanners_enabled.get("gemma"))

    targets: list[ScannerTarget] = []
    notes: list[str] = []

    # Build (dir, ecosystem) pairs deterministically.
    eco_dirs: list[tuple[Path, str]] = []
    for d in sorted(by_dir.keys(), key=lambda p: _norm_rel(p, root)):
        for eco in _ecosystems_for_dir(d, by_dir[d]):
            eco_dirs.append((d, eco))

    if eco_dirs:
        if osv_on:
            for d, eco in eco_dirs:
                targets.append(ScannerTarget(scanner="osv", ecosystem=eco, targets=[d]))
        else:
            seen_eco: set[str] = set()
            for _, eco in eco_dirs:
                if eco in seen_eco:
                    continue
                seen_eco.add(eco)
                notes.append(f"{eco} ecosystem detected but osv scanner disabled")

    # Gitleaks: whole tree when enabled. (Always something to scan; secrets aren't
    # gated on language detection.)
    if gitleaks_on:
        targets.append(ScannerTarget(scanner="gitleaks", ecosystem=None, targets=[root]))
    else:
        # Only worth a note if there's anything in the tree at all.
        if any(root.iterdir()) if root.is_dir() else False:
            notes.append("source tree present but gitleaks scanner disabled")

    # Semgrep: whole tree when enabled AND there's a recognized source file.
    if semgrep_on and has_source:
        targets.append(ScannerTarget(scanner="semgrep", ecosystem=None, targets=[root]))
    elif (not semgrep_on) and has_source:
        notes.append("source code detected but semgrep scanner disabled")

    # Trivy / Trufflehog / Syft: whole-tree scanners that auto-detect their own
    # inputs (containers, IaC, language packages, secrets). No manifest gating.
    if trivy_on:
        targets.append(ScannerTarget(scanner="trivy", ecosystem=None, targets=[root]))
    if trufflehog_on:
        targets.append(ScannerTarget(scanner="trufflehog", ecosystem=None, targets=[root]))
    if syft_on:
        targets.append(ScannerTarget(scanner="syft", ecosystem=None, targets=[root]))
    # LLM-driven SAST: only worth running on repos that actually have source.
    if codex_on and has_source:
        targets.append(ScannerTarget(scanner="codex", ecosystem=None, targets=[root]))
    if gemma_on and has_source:
        targets.append(ScannerTarget(scanner="gemma", ecosystem=None, targets=[root]))

    # Unscanned ecosystems (Java, PHP, Dart, ...) — always note, scanner-agnostic.
    for label in sorted(unscanned_notes):
        notes.append(f"{label} detected, no scanner configured")

    # Deterministic ordering: (scanner, ecosystem or "", first target relpath).
    targets.sort(key=lambda t: (t.scanner, t.ecosystem or "", _norm_rel(t.targets[0], root)))

    return DetectionResult(
        targets=targets,
        detected_no_scanner=notes,
        detected_frameworks=sorted(frameworks),
    )
