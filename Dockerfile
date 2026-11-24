# syntax=docker/dockerfile:1.7
# security-scan — single-repo security scanner. Stateless. State lives in GitHub Issues.
#
# Mount points (bind-mount at runtime — no VOLUME directive, so anonymous volumes
# never accumulate when --rm is used):
#   /config   ro   -> config.yaml
#   /rules    ro   -> optional override of the image-baked semgrep rules
#   /work     rw   -> ephemeral clone + SBOM output (the container wipes it on exit)
#
# Secrets via env:  GITHUB_TOKEN, SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN+SLACK_CHANNEL_ID
#
# ---------------------------------------------------------------------------
# Cross-arch build without emulating the scanner binaries.
#
# The Go tools (osv-scanner, gitleaks, trivy, trufflehog, syft) are downloaded
# and verified in `fetch`, which runs on the BUILD platform: each archive is
# checked against the upstream release's SHA-256 checksum file and the
# extracted binary's ELF machine type is checked against the TARGET platform.
# Nothing in that stage executes a target-arch binary, so building linux/amd64
# on an Apple Silicon Mac needs no Rosetta and never runs a Go tool under
# QEMU (osv-scanner 2.3.8 aborts there with "regexp: expression too large").
# The trivy vulnerability DBs are architecture-independent, so `trivydb`
# downloads them with a build-platform trivy.
#
# The final stage still runs apt/dpkg, pip and npm for the target platform;
# for a foreign target that goes through binfmt/QEMU, which those
# interpreters tolerate. Target-arch runtime behaviour is verified after the
# build (see .github/workflows/ci.yml), not by running tools during it.
# ---------------------------------------------------------------------------

# Pin scanner versions so "new vs resolved" diffs aren't polluted by upstream churn.
# When bumping, prefer the most recent stable release: each rebuild against a newer
# Go toolchain is what closes the stdlib CVEs Docker Scout flags inside our binaries.
ARG OSV_SCANNER_VERSION=2.3.8
ARG GITLEAKS_VERSION=8.30.1
ARG SEMGREP_VERSION=1.164.0
ARG TRIVY_VERSION=0.71.0
ARG TRUFFLEHOG_VERSION=3.95.5
ARG SYFT_VERSION=1.44.0
# Node.js is used solely to host the Socket CLI (npm-distributed) for the
# opt-in supply_chain lane. Pin nodesource major to keep the install stable.
ARG NODE_MAJOR=22
ARG SOCKET_CLI_VERSION=1.0.55

# --- fetch: verified target-arch Go binaries (runs on the build platform) ----
FROM --platform=$BUILDPLATFORM python:3.14-slim AS fetch
ARG TARGETARCH
ARG OSV_SCANNER_VERSION GITLEAKS_VERSION TRIVY_VERSION TRUFFLEHOG_VERSION SYFT_VERSION
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl file \
    && rm -rf /var/lib/apt/lists/*
COPY --chmod=0755 <<'SH' /usr/local/bin/fetch-verified
#!/bin/sh
# fetch-verified <base-url> <asset> <checksums-file> <out> [member]
# Downloads <asset>, checks it against <checksums-file> from the same release,
# then installs it (or <member> extracted from the tarball) as <out>.
set -eu
base=$1 asset=$2 sums=$3 out=$4 member=${5:-}
tmp=$(mktemp -d)
curl -fsSL -o "$tmp/$asset" "$base/$asset"
curl -fsSL -o "$tmp/$sums" "$base/$sums"
(cd "$tmp" && grep -E "[[:space:]]\*?$asset\$" "$sums" | sha256sum -c -)
if [ -n "$member" ]; then
  tar -xzf "$tmp/$asset" -C "$tmp" "$member"
  install -m 0755 "$tmp/$member" "$out"
else
  install -m 0755 "$tmp/$asset" "$out"
fi
rm -rf "$tmp"
SH
COPY --chmod=0755 <<'SH' /usr/local/bin/check-elf
#!/bin/sh
# check-elf <TARGETARCH> <binary>... : fail unless each is an ELF for that arch.
set -eu
want=$1; shift
case "$want" in
  amd64) pat='ELF 64-bit LSB .*x86-64' ;;
  arm64) pat='ELF 64-bit LSB .*(ARM aarch64|aarch64)' ;;
  *) echo "unsupported arch: $want" >&2; exit 1 ;;
esac
for b in "$@"; do
  file -b "$b" | grep -Eq "$pat" || { echo "$b: $(file -b "$b") (want $want)" >&2; exit 1; }
  echo "$b: ok ($want)"
done
SH
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) osv=linux_amd64 gl=linux_x64   tv=Linux-64bit gh=linux_amd64 ;; \
      arm64) osv=linux_arm64 gl=linux_arm64 tv=Linux-ARM64 gh=linux_arm64 ;; \
      *) echo "unsupported arch: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    mkdir -p /out; \
    fetch-verified "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}" \
      "osv-scanner_${osv}" osv-scanner_SHA256SUMS /out/osv-scanner; \
    fetch-verified "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}" \
      "gitleaks_${GITLEAKS_VERSION}_${gl}.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" /out/gitleaks gitleaks; \
    fetch-verified "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
      "trivy_${TRIVY_VERSION}_${tv}.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" /out/trivy trivy; \
    fetch-verified "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}" \
      "trufflehog_${TRUFFLEHOG_VERSION}_${gh}.tar.gz" "trufflehog_${TRUFFLEHOG_VERSION}_checksums.txt" /out/trufflehog trufflehog; \
    fetch-verified "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}" \
      "syft_${SYFT_VERSION}_${gh}.tar.gz" "syft_${SYFT_VERSION}_checksums.txt" /out/syft syft; \
    check-elf "$TARGETARCH" /out/*

# --- trivydb: arch-independent DBs, fetched with a build-platform trivy ------
FROM --platform=$BUILDPLATFORM fetch AS trivydb
ARG BUILDARCH
ARG TRIVY_VERSION
RUN set -eux; \
    case "$BUILDARCH" in amd64) tv=Linux-64bit ;; arm64) tv=Linux-ARM64 ;; *) exit 1 ;; esac; \
    fetch-verified "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
      "trivy_${TRIVY_VERSION}_${tv}.tar.gz" "trivy_${TRIVY_VERSION}_checksums.txt" /usr/local/bin/trivy-build trivy; \
    mkdir -p /var/cache/trivy; \
    trivy-build --cache-dir /var/cache/trivy image --download-db-only; \
    trivy-build --cache-dir /var/cache/trivy image --download-java-db-only

# --- final image (target platform) -------------------------------------------
FROM python:3.14-slim AS base
ARG SEMGREP_VERSION NODE_MAJOR SOCKET_CLI_VERSION

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Refresh OS packages with the latest security patches before installing.
# `apt-get upgrade -y` is what closes Docker Scout's "fixable critical or high
# vulnerabilities" findings against the base image's OS layer.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        git ca-certificates curl tar xz-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Go tools: checksum- and arch-verified in `fetch`.
COPY --from=fetch /out/ /usr/local/bin/

# --- semgrep (pip — official channel) -------------------------------------
# Upgrade pip/wheel/setuptools together so Scout doesn't catch a stale wheel
# left behind from `ensurepip` bundling.
# python:3.13-slim no longer ships setuptools, and semgrep's transitive
# opentelemetry-instrumentation dep imports `pkg_resources` (provided by
# setuptools). Pin setuptools < 80 because newer setuptools dropped the
# bundled `pkg_resources` module.
RUN pip install --no-cache-dir --upgrade pip wheel "setuptools>=70,<80" \
    && pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}"

# Pre-cached trivy DBs so first-run is fast and offline-OK (the runner passes
# --skip-db-update). Owned by the non-root scanner user (uid 1000, added
# below): `trivy image` creates a `fanal/` subdirectory at runtime to cache
# extracted image layers, so the dir must be writable, not just readable.
ENV TRIVY_CACHE_DIR=/var/cache/trivy
COPY --from=trivydb --chown=1000:1000 /var/cache/trivy /var/cache/trivy

# --- socket CLI (supply-chain lane, opt-in) ------------------------------
# Adds Node.js + @socketsecurity/cli for the opt-in supply-chain lane.
# When `scanners.supply_chain: false` (default), the binary is present but
# never invoked — zero runtime cost. The size cost (~80MB Node + ~20MB CLI)
# is the price of having a CI-friendly supply-chain lane in the same image.
RUN set -eux; \
    curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash -; \
    apt-get install -y --no-install-recommends nodejs; \
    apt-get clean; rm -rf /var/lib/apt/lists/*; \
    npm install -g "@socketsecurity/cli@${SOCKET_CLI_VERSION}"

# --- security-scan itself -------------------------------------------------------
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY security_scan /app/security_scan
COPY README.md /app/README.md
# Manifest the consuming skill reads to see version + needed config migrations.
# Pull it out without starting the scanner:
#   docker run --rm --entrypoint cat leverj/security-scan:<tag> /app/SECURITY-SCAN-MANIFEST.yaml
COPY SECURITY-SCAN-MANIFEST.yaml /app/SECURITY-SCAN-MANIFEST.yaml
RUN pip install --no-cache-dir "/app[live]"

# Make sure the mount points exist (no VOLUME directive — keeps `--rm` from
# leaving anonymous volumes behind on each run).
RUN mkdir -p /config /rules /work

# --- non-root user -------------------------------------------------------
# Run the scanner as an unprivileged user. /work is the only path the
# container itself writes to (clones, SBOM output, gitleaks temp report);
# /config is bind-mounted read-only and /rules is read-only. The trivy DB
# cache (set above) is already world-readable.
#
# uid/gid 1000 matches the typical first non-root user on Linux hosts, so
# files written under a host-mounted /work end up with a recognizable owner.
RUN groupadd --system --gid 1000 scanner \
    && useradd  --system --uid 1000 --gid 1000 \
                --home-dir /home/scanner --create-home --shell /sbin/nologin \
                scanner \
    && chown -R scanner:scanner /work /home/scanner

USER scanner

# Default entrypoint runs the scanner against /config/config.yaml.
ENTRYPOINT ["python", "-m", "security_scan", "--config", "/config/config.yaml", "--work-dir", "/work"]
CMD []
