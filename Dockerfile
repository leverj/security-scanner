# secscan — single-repo security scanner. Stateless. State lives in GitHub Issues.
#
# Volumes (mount at runtime):
#   /config   ro   -> config.yaml
#   /rules    ro   -> bundled semgrep rules (overrides the image-baked ones)
#   /work     rw   -> ephemeral clone + scratch (tmpfs friendly)
#
# Secrets via env:  GITHUB_TOKEN, SLACK_WEBHOOK_URL or SLACK_BOT_TOKEN+SLACK_CHANNEL_ID

FROM python:3.11-slim AS base

# Pin scanner versions so "new vs resolved" diffs aren't polluted by upstream churn.
ARG OSV_SCANNER_VERSION=1.9.2
ARG GITLEAKS_VERSION=8.21.2
ARG SEMGREP_VERSION=1.97.0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git ca-certificates curl tar xz-utils \
    && rm -rf /var/lib/apt/lists/*

# --- osv-scanner ----------------------------------------------------------
# Releases publish prebuilt linux amd64/arm64 binaries; pick the right arch.
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

# --- semgrep (pip install — official distribution channel) ---------------
RUN pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && semgrep --version

# --- secscan itself -------------------------------------------------------
WORKDIR /app
COPY pyproject.toml /app/pyproject.toml
COPY secscan /app/secscan
COPY README.md /app/README.md
RUN pip install --no-cache-dir /app

# Bundled Semgrep rules — image-baked default; can be overridden by mounting /rules.
COPY secscan/rules /opt/secscan/rules
ENV SECSCAN_DEFAULT_RULES=/opt/secscan/rules

VOLUME ["/config", "/rules", "/work"]
ENV SECSCAN_WORK_DIR=/work

# Default entrypoint runs the scanner against /config/config.yaml. Override with
# --dry-run, --work-dir, etc. via `docker run ... secscan --dry-run`.
ENTRYPOINT ["python", "-m", "secscan", "--config", "/config/config.yaml", "--work-dir", "/work"]
CMD []
