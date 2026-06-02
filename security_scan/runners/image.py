"""Image-scanning runner — covers the three modes from issue #9.

  (A) Dockerfile audit         — handled by `runners/trivy.py` (`--scanners
                                 misconfig` on the cloned tree). Not duplicated
                                 here.

  (B) Base-image scan          — parse every `FROM` line in the repo's
                                 Dockerfile(s), run `trivy image <ref>` per
                                 base, aggregate findings. Cacheable across
                                 runs.

  (C) Built-image scan         — opt-in. Two sub-modes:
                                 - `ref: <published-tag>`  → pull + scan (no
                                   build).
                                 - `build_locally: true`   → `docker build .`
                                   the cloned tree, then scan the resulting
                                   local image. Requires the docker socket
                                   mounted into the security-scan container.

All findings carry `properties.security_scan_image_source` so normalize.py can
slot them under `category: image` and the project board can filter on them.

The runner is a thin wrapper over `trivy image`. It NEVER `docker build`s on
behalf of the user unless `build_locally=True` AND
SECURITY_SCAN_ALLOW_BUILD=1 is set in the env (defence-in-depth against an
accidental opt-in). For ref-only pulls, the daemon is the same trust boundary
as `docker pull`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from . import RunnerResult, _run

# `FROM` line shapes we recognize. Multi-stage builds use `FROM <ref> AS <name>`;
# stage aliases (e.g. `FROM builder AS final`) are NOT real images — we filter
# them out by skipping any ref that doesn't look like a registry/repo[:tag] or
# digest.
_FROM_RE = re.compile(
    r"""^\s*FROM\s+              # FROM keyword
        (?:--platform=\S+\s+)?   # optional platform flag
        (?P<ref>\S+)             # image reference
        (?:\s+AS\s+\S+)?\s*$     # optional alias
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Heuristic for "this looks like a real image ref, not a stage alias":
# either a registry-shape character (`:`, `/`, `@`) is present, OR it's a
# known short base name (alpine, ubuntu, debian, etc.). Without the
# whitelist, `FROM alpine` and `FROM nginx` were being silently dropped as
# if they were stage aliases.
_LOOKS_LIKE_IMAGE_RE = re.compile(r"[/:@]")
_WELL_KNOWN_BASES: frozenset[str] = frozenset({
    "alpine", "ubuntu", "debian", "centos", "fedora", "rockylinux",
    "amazonlinux", "rhel",
    "busybox", "scratch",
    "nginx", "httpd", "redis", "postgres", "mysql", "mariadb", "mongo",
    "rabbitmq", "memcached", "elasticsearch",
    "node", "python", "ruby", "openjdk", "eclipse-temurin", "amazoncorretto",
    "golang", "rust", "php", "haskell", "erlang", "elixir",
    "haproxy", "traefik", "envoy", "caddy",
    "ghcr.io", "registry",  # less likely to appear bare but harmless
})


def _looks_like_image(ref: str) -> bool:
    """True iff `ref` is plausibly a registry-pullable image reference (not
    just a multi-stage alias like `builder`)."""
    if not ref:
        return False
    if _LOOKS_LIKE_IMAGE_RE.search(ref):
        return True
    return ref.lower() in _WELL_KNOWN_BASES


@dataclass
class ImageScanConfig:
    """Per-run image-scan settings extracted from config.yaml."""
    base_images: bool = True
    built_image_enabled: bool = False
    built_image_ref: str | None = None
    build_locally: bool = False
    timeout: int = 600
    trivy_binary: str = "trivy"
    docker_binary: str = "docker"
    # Repo paths to skip when discovering Dockerfiles. Same dir-prefix /
    # fnmatch shape as `paths.exclude` in the main config.
    exclude: list[str] | None = None

    def __post_init__(self):
        # `ref` and `build_locally` are documented as mutually exclusive but
        # nothing previously enforced it; the runner would silently use `ref`.
        # Surface the conflict early so the user notices.
        if self.built_image_enabled and self.built_image_ref and self.build_locally:
            raise ValueError(
                "image_scan.built_image: `ref` and `build_locally` are mutually "
                "exclusive — set one or the other, not both"
            )


def run(repo_dir: Path, cfg: ImageScanConfig) -> list[RunnerResult]:
    """Dispatch to the enabled sub-modes. Returns one RunnerResult per image
    scanned (or one with completed=False per failure). Caller flattens.

    Returning a list (instead of a single RunnerResult) lets the project board
    surface base-image findings separately from built-image findings even when
    they share a `trivy` provenance.
    """
    results: list[RunnerResult] = []

    if cfg.base_images:
        for ref in _discover_base_images(repo_dir, exclude=cfg.exclude or []):
            results.append(_scan_image(ref, cfg, source="base"))

    if cfg.built_image_enabled:
        results.append(_scan_built(repo_dir, cfg))

    return results


# ---- Mode B: base images ----------------------------------------------------


def _discover_base_images(repo_dir: Path, exclude: list[str] | None = None) -> list[str]:
    """Walk `repo_dir` for `Dockerfile`-style files, extract every `FROM` ref,
    de-dup. We accept `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, and
    `Containerfile` (Podman). Skips `.git`, `node_modules`, `vendor`.

    `exclude` is honored same as `paths.exclude` in the main config: any
    Dockerfile under an excluded prefix/glob is skipped — otherwise users
    pulling a vendor-mirror would trigger unwanted base-image pulls.

    Stage aliases (multi-stage builds) and unresolved ARG-style refs are filtered
    out — only refs that look like real registry pulls are returned.
    """
    seen: set[str] = set()
    out: list[str] = []
    skip = {".git", "node_modules", "vendor", ".venv", "__pycache__"}
    patterns = list(exclude or [])

    for dirpath, dirnames, filenames in os.walk(repo_dir):
        kept: list[str] = []
        for d in dirnames:
            if d in skip:
                continue
            child_rel = os.path.relpath(os.path.join(dirpath, d), repo_dir).replace(os.sep, "/")
            if _path_excluded(child_rel, patterns):
                continue
            kept.append(d)
        dirnames[:] = kept

        for fname in filenames:
            if not _is_dockerfile_name(fname):
                continue
            file_rel = os.path.relpath(os.path.join(dirpath, fname), repo_dir).replace(os.sep, "/")
            if _path_excluded(file_rel, patterns):
                continue
            try:
                text = (Path(dirpath) / fname).read_text(errors="ignore")
            except OSError:
                continue
            for raw_ref in _extract_from_refs(text):
                if raw_ref in seen:
                    continue
                seen.add(raw_ref)
                out.append(raw_ref)
    return out


def _path_excluded(rel: str, patterns: list[str]) -> bool:
    """Match `rel` ("a/b/c") against dir-prefix-style and fnmatch patterns.
    Same semantics as `detect._is_excluded` — kept local so the runner stays
    standalone."""
    import fnmatch
    if not rel:
        return False
    for pat in patterns:
        if not pat:
            continue
        if pat.endswith("/"):
            prefix = pat.rstrip("/")
            if rel == prefix or rel.startswith(prefix + "/"):
                return True
            continue
        if fnmatch.fnmatch(rel, pat):
            return True
        parts = rel.split("/")
        for i in range(len(parts)):
            if fnmatch.fnmatch(parts[i], pat):
                return True
            if fnmatch.fnmatch("/".join(parts[: i + 1]), pat):
                return True
    return False


def _is_dockerfile_name(fname: str) -> bool:
    lower = fname.lower()
    if lower == "dockerfile" or lower == "containerfile":
        return True
    if lower.startswith("dockerfile."):
        return True
    if lower.endswith(".dockerfile"):
        return True
    return False


def _extract_from_refs(text: str) -> list[str]:
    """Parse `FROM` lines from a Dockerfile body. We collect refs that look
    like real registry pulls and drop stage aliases (multi-stage builds), refs
    starting with `$` (un-resolved ARGs), and the literal `scratch` (no
    content to scan).

    Stage aliases are detected by the absence of a registry-shape character
    (`:`, `/`, `@`) AND not being a well-known short base name.
    """
    refs: list[str] = []
    for line in text.splitlines():
        m = _FROM_RE.match(line)
        if not m:
            continue
        ref = m.group("ref").strip()
        if not ref:
            continue
        if ref.startswith("$"):
            continue
        if ref.lower() == "scratch":
            continue
        if not _looks_like_image(ref):
            # Bare name like "builder" — assume it's a stage alias.
            continue
        refs.append(ref)
    return refs


# ---- Mode C: built image ----------------------------------------------------


def _scan_built(repo_dir: Path, cfg: ImageScanConfig) -> RunnerResult:
    """Scan a built (or to-be-built) image.

    Precedence:
      1. If `built_image_ref` is set, pull + scan it (no build).
      2. Else if `build_locally` is True AND SECURITY_SCAN_ALLOW_BUILD=1 in env,
         `docker build .` the repo_dir and scan the resulting image.
      3. Otherwise skip (returning a clear error).
    """
    if cfg.built_image_ref:
        return _scan_image(cfg.built_image_ref, cfg, source="built")

    if not cfg.build_locally:
        return RunnerResult(
            "image", None, False,
            "image_scan.built_image.enabled=true but neither `ref` nor `build_locally` is set",
        )

    if os.environ.get("SECURITY_SCAN_ALLOW_BUILD") != "1":
        return RunnerResult(
            "image", None, False,
            "build_locally requires SECURITY_SCAN_ALLOW_BUILD=1 in the env "
            "(docker build executes RUN lines from the target repo)",
        )

    if shutil.which(cfg.docker_binary) is None:
        return RunnerResult(
            "image", None, False,
            f"docker binary not found: {cfg.docker_binary} "
            "(mount the daemon socket and install docker CLI in the image)",
        )

    tag = f"security-scan-build:{os.urandom(4).hex()}"
    cmd = [cfg.docker_binary, "build", "-q", "-t", tag, str(repo_dir)]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=cfg.timeout * 4, check=False,
        )
    except subprocess.TimeoutExpired:
        return RunnerResult("image", None, False, f"docker build timeout after {cfg.timeout * 4}s")
    except FileNotFoundError:
        return RunnerResult("image", None, False, f"docker binary not found: {cfg.docker_binary}")
    if proc.returncode != 0:
        return RunnerResult(
            "image", None, False,
            f"docker build failed (rc={proc.returncode}): {proc.stderr.strip()[:300]}",
        )

    try:
        return _scan_image(tag, cfg, source="built")
    finally:
        # Best-effort cleanup of the temp image so we don't fill the daemon.
        try:
            subprocess.run(
                [cfg.docker_binary, "rmi", "-f", tag],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass


# ---- shared: invoke `trivy image` ------------------------------------------


def _scan_image(ref: str, cfg: ImageScanConfig, *, source: str) -> RunnerResult:
    """Run `trivy image --format sarif <ref>` and tag every finding with the
    source (`base` or `built`) so normalize.py can route them to `category: image`."""
    if shutil.which(cfg.trivy_binary) is None:
        return RunnerResult("image", None, False, f"binary not found: {cfg.trivy_binary}")

    cmd = [
        cfg.trivy_binary,
        "image",
        "--format", "sarif",
        "--quiet",
        "--scanners", "vuln,secret",  # licenses/misconfig don't make sense here
        "--skip-db-update",
        "--skip-java-db-update",
        "--no-progress",
        ref,
    ]
    try:
        rc, stdout, stderr = _run(cmd, cwd=Path.cwd(), timeout=cfg.timeout)
    except subprocess.TimeoutExpired:
        return RunnerResult("image", None, False, f"trivy image {ref}: timeout after {cfg.timeout}s")
    except FileNotFoundError:
        return RunnerResult("image", None, False, f"binary not found: {cfg.trivy_binary}")
    except Exception as e:
        return RunnerResult("image", None, False, f"{type(e).__name__}: {e}")

    import json
    try:
        sarif = json.loads(stdout)
    except (json.JSONDecodeError, ValueError) as e:
        if rc != 0:
            return RunnerResult("image", None, False,
                                f"trivy image {ref}: exit {rc}: {stderr.strip()[:300]}")
        return RunnerResult("image", None, False, f"trivy image {ref}: parse error: {e}")

    # Stamp every result so normalize.py knows this came from the image lane.
    _tag_sarif(sarif, image_ref=ref, source=source)
    return RunnerResult("image", sarif, True, None)


def _tag_sarif(sarif: dict, *, image_ref: str, source: str) -> None:
    """Mutate `sarif` in place — add a property block on every result that
    carries the originating image ref + which mode produced it. Normalizer
    reads these to assign category=image and to render the image ref in the
    finding's body."""
    for run in (sarif.get("runs") or []):
        for result in (run.get("results") or []):
            props = result.setdefault("properties", {})
            props["security_scan_image_ref"] = image_ref
            props["security_scan_image_source"] = source  # "base" or "built"


