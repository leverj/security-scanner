# security-scan — single-repo security scanner. Stateless. State lives in GitHub Issues.
#
# Mount points (bind-mount at runtime — no VOLUME directive, so anonymous volumes
# never accumulate when --rm is used):
#   /config   ro   -> config.yaml
#   /rules    ro   -> optional override of the image-baked semgrep rules
#   /work     rw   -> ephemeral clone + SBOM output (the container wipes it on exit)
#
# Secrets via env:  GITHUB_TOKEN, SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN+SLACK_CHANNEL_ID

FROM python:3.12-slim AS base

# Pin scanner versions so "new vs resolved" diffs aren't polluted by upstream churn.
ARG OSV_SCANNER_VERSION=1.9.2
ARG GITLEAKS_VERSION=8.21.2
ARG SEMGREP_VERSION=1.97.0
ARG TRIVY_VERSION=0.70.0
ARG TRUFFLEHOG_VERSION=3.95.3
ARG SYFT_VERSION=1.44.0

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

# --- osv-scanner ----------------------------------------------------------
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) osv_arch=linux_amd64 ;; \
      arm64) osv_arch=linux_arm64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${osv_arch}"; \
    chmod +x /usr/local/bin/osv-scanner; \
    osv-scanner --version

# --- gitleaks -------------------------------------------------------------
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) gl_arch=linux_x64 ;; \
      arm64) gl_arch=linux_arm64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${gl_arch}.tar.gz"; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    rm /tmp/gitleaks.tar.gz; \
    chmod +x /usr/local/bin/gitleaks; \
    gitleaks version

# --- semgrep (pip — official channel) -------------------------------------
# python:3.12-slim no longer ships setuptools, and semgrep's transitive
# opentelemetry-instrumentation dep imports `pkg_resources` (provided by
# setuptools). Pin setuptools < 80 because newer setuptools dropped the
# bundled `pkg_resources` module.
RUN pip install --no-cache-dir "setuptools>=70,<80" "semgrep==${SEMGREP_VERSION}" \
    && semgrep --version

# --- trivy (Aqua) — vuln + secret + iac + license, all in one ------------
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) tv_arch=Linux-64bit ;; \
      arm64) tv_arch=Linux-ARM64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trivy.tar.gz \
      "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_${tv_arch}.tar.gz"; \
    tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy; \
    rm /tmp/trivy.tar.gz; \
    chmod +x /usr/local/bin/trivy; \
    trivy --version

# Pre-cache the trivy DBs at build time so first-run is fast and offline-OK.
# (The runner passes --skip-db-update.) Cache lives in a world-readable
# location so the non-root scanner user (added below) can read it.
ENV TRIVY_CACHE_DIR=/var/cache/trivy
RUN mkdir -p $TRIVY_CACHE_DIR \
    && trivy --cache-dir $TRIVY_CACHE_DIR image --download-db-only \
    && trivy --cache-dir $TRIVY_CACHE_DIR image --download-java-db-only \
    && chmod -R a+rX $TRIVY_CACHE_DIR

# --- trufflehog — verified secret detection ------------------------------
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) th_arch=linux_amd64 ;; \
      arm64) th_arch=linux_arm64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/trufflehog.tar.gz \
      "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_${th_arch}.tar.gz"; \
    tar -xzf /tmp/trufflehog.tar.gz -C /usr/local/bin trufflehog; \
    rm /tmp/trufflehog.tar.gz; \
    chmod +x /usr/local/bin/trufflehog; \
    trufflehog --version

# --- syft — SBOM generation ----------------------------------------------
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) sy_arch=linux_amd64 ;; \
      arm64) sy_arch=linux_arm64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/syft.tar.gz \
      "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_${sy_arch}.tar.gz"; \
    tar -xzf /tmp/syft.tar.gz -C /usr/local/bin syft; \
    rm /tmp/syft.tar.gz; \
    chmod +x /usr/local/bin/syft; \
    syft --version

# --- security-scan itself -------------------------------------------------------
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY security_scan /app/security_scan
COPY README.md /app/README.md
# Manifest the consuming skill reads to see version + needed config migrations.
# Pull it out without starting the scanner:
#   docker run --rm --entrypoint cat leverj/security-scan:<tag> /app/SECURITY-SCAN-MANIFEST.yaml
COPY SECURITY-SCAN-MANIFEST.yaml /app/SECURITY-SCAN-MANIFEST.yaml
RUN pip install --no-cache-dir /app

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
