# syntax=docker/dockerfile:1.7
#
# SecureScan v0.2.0 container image.
#
# Purpose
# -------
# This image is the *fallback distribution channel* for SecureScan in
# CI/CD. The primary install path is `pipx install securescan` (or
# `pip install securescan`), which works on any runner that already has
# the underlying scanner CLIs (semgrep, bandit, trivy, ...) on PATH.
# When those binaries are NOT pre-installed on the runner, the GitHub
# Action falls back to running this image, which has every supported
# scanner CLI baked in at a pinned version.
#
# Scanner inclusion policy
# ------------------------
# Included (pre-installed in this image):
#   - semgrep, bandit, safety, pip-licenses, checkov  (pip)
#   - trivy                                           (pinned tarball)
#   - npm / npx                                       (Node 20 LTS, for npm-audit)
#   - nmap                                            (apt)
#   - baseline, secrets/gitleaks, dast-builtin,
#     dockerfile, license-checker                    (Python-builtin scanners,
#                                                      no external CLI needed)
#
# Excluded (intentional):
#   - OWASP ZAP        - ~700 MB JVM-based daemon. Users who want DAST via
#                        ZAP run it separately (e.g. `zaproxy/zap` container)
#                        and pass `--zap-host` to securescan.
#   - gitleaks binary  - the in-tree `scanners/gitleaks.py` is a Python
#                        gitignore/repo-hygiene checker that doesn't shell
#                        out to the upstream `gitleaks` binary, and the
#                        secrets scanner only invokes `git`, which is
#                        already installed below.
#
# Reproducibility
# ---------------
# The base image is pinned by manifest-list digest (multi-arch, resolves
# to amd64/arm64 transparently). Source: Docker Hub
#   https://hub.docker.com/_/python  ->  3.12-slim
# Re-pin by running:
#   docker buildx imagetools inspect python:3.12-slim --format '{{.Manifest.Digest}}'
#
# Trivy is pinned to a specific GitHub release; bump the TRIVY_VERSION
# ARG below to upgrade. Node.js is installed from the upstream .tar.xz
# (NOT the Debian package) so we don't pull in the system python3 and
# friends -- bump NODE_VERSION as needed.

############################
# Stage 1: builder         #
############################
FROM python:3.12-slim@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3 AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy the whole backend project. We let pip resolve the layout from
# pyproject.toml so this Dockerfile keeps working whether the package
# lives under `src/` or `securescan/` (SS9 is renaming concurrently).
COPY . /build/

# Build a wheel for the project itself and resolve all runtime deps as
# wheels into /build/wheels so the runtime stage doesn't need a compiler.
# We include the [pdf] extra so weasyprint and its rendering chain are
# staged into the runtime image -- the container is the supported way
# to run `securescan scan --output report-pdf` without manually
# installing the Cairo / Pango / GObject system libraries.
# Also stage a clean source-only artifact at /artifact that the runtime
# stage will copy in. This keeps the runtime image free of build droppings
# (egg-info, wheels, __pycache__).
RUN pip install --upgrade pip wheel build \
    && pip wheel '.[pdf]' --wheel-dir /build/wheels \
    && mkdir -p /artifact \
    && cp pyproject.toml /artifact/ \
    && if [ -d src ]; then cp -r src /artifact/src; fi \
    && if [ -d securescan ]; then cp -r securescan /artifact/securescan; fi


############################
# Stage 2: runtime         #
############################
FROM python:3.12-slim@sha256:46cb7cc2877e60fbd5e21a9ae6115c30ace7a077b9f8772da879e4590c18c2e3 AS runtime

ARG TRIVY_VERSION=0.70.0
ARG NODE_VERSION=20.20.2

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    SECURESCAN_IN_CONTAINER=1

# System scanner deps + tools needed to fetch trivy + nodesource setup.
# All in one layer with the apt-cache cleanup, to keep image size down.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        gnupg \
        nmap \
        unzip \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js 20 LTS from the official upstream tarball. We
# deliberately bypass NodeSource / the Debian package because the .deb
# pulls in python3 + a bunch of system Python packages we don't need
# (we already have python:3.12-slim's user-space Python). The tarball
# install is ~3x smaller and gives the same `npm` / `npx` we need for
# the npm-audit scanner.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
        amd64) node_arch="x64" ;; \
        arm64) node_arch="arm64" ;; \
        *) echo "unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    url="https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz"; \
    curl -fsSL "${url}" -o /tmp/node.tar.xz; \
    mkdir -p /opt/node; \
    tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1; \
    rm -f /tmp/node.tar.xz; \
    rm -rf /opt/node/CHANGELOG.md /opt/node/README.md \
           /opt/node/share/man /opt/node/share/doc \
           /opt/node/include \
           /opt/node/lib/node_modules/npm/docs \
           /opt/node/lib/node_modules/npm/man \
           /opt/node/lib/node_modules/npm/changelogs \
           /opt/node/lib/node_modules/corepack; \
    ln -s /opt/node/bin/node /usr/local/bin/node; \
    ln -s /opt/node/bin/npm /usr/local/bin/npm; \
    ln -s /opt/node/bin/npx /usr/local/bin/npx; \
    /usr/local/bin/node --version; \
    /usr/local/bin/npm --version; \
    npm config set update-notifier false --location=global; \
    npm cache clean --force

# Install Trivy from the official tarball, pinned by version.
# Slimmer than the apt repo and gives a single static binary.
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "${arch}" in \
        amd64) trivy_arch="64bit" ;; \
        arm64) trivy_arch="ARM64" ;; \
        *) echo "unsupported arch: ${arch}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"; \
    curl -fsSL "${url}" -o /tmp/trivy.tar.gz; \
    tar -xzf /tmp/trivy.tar.gz -C /tmp trivy; \
    install -m 0755 /tmp/trivy /usr/local/bin/trivy; \
    rm -f /tmp/trivy.tar.gz /tmp/trivy; \
    trivy --version

# All Python install + slimming in a single layer so the freed bytes
# actually leave the image (otherwise the deleted files stay alive in
# earlier layers). This single RUN:
#   1. Installs the pinned scanner CLIs from PyPI.
#   2. Installs the SecureScan dep wheels staged by the builder, with
#      --no-deps (the builder already resolved transitive closure).
#      The builder used the [pdf] extra, so the weasyprint rendering
#      chain (weasyprint, pydyf, pyphen, pillow, fonttools, brotli,
#      tinycss2, cssselect2, webencodings) is included here -- the
#      container is the supported PDF-reporting install path; pip
#      users opt in via `pip install 'securescan[pdf]'` instead.
#   3. Uninstalls dashboard-only chains we don't need for CLI scanning:
#      - fastapi/starlette (HTTP API, only used by `securescan serve`)
#      - uvicorn[standard] extras (httptools, websockets, watchfiles, ...)
#   4. Strips C headers, docs, man pages, locales, __pycache__, bundled
#      test directories, and pip/setuptools/wheel themselves.
# `serve` will fail at runtime in this image -- by design; the
# container is for scanning, not hosting the dashboard.
RUN --mount=type=bind,from=builder,source=/build/wheels,target=/tmp/wheels \
    set -eux; \
    pip install --no-cache-dir \
        "semgrep==1.90.0" \
        "bandit==1.7.10" \
        "safety==3.2.11" \
        "pip-licenses==5.0.0" \
        "checkov==3.2.334"; \
    # Install dep wheels staged in the builder stage. Skip the project
    # wheel itself; we ship source instead -- see /app COPY below.
    for w in /tmp/wheels/*.whl; do \
        case "$w" in \
            */securescan-*) continue ;; \
            *) pip install --no-cache-dir --no-deps "$w" ;; \
        esac; \
    done; \
    pip uninstall -y \
        fastapi starlette \
        uvicorn uvloop httptools watchfiles websockets \
        || true; \
    # Pin setuptools<81 so `pkg_resources` is still shipped (semgrep
    # via opentelemetry imports it); pin typer<0.16 so safety's CLI
    # entrypoint still finds `typer.rich_utils` as an attribute.
    pip install --no-cache-dir --no-deps --force-reinstall \
        "setuptools<81" \
        "typer<0.16"; \
    rm -rf /usr/include /usr/local/include; \
    rm -rf /usr/share/doc /usr/share/man /usr/share/info \
           /usr/share/locale/* /usr/share/gtk-doc \
           /usr/share/bash-completion /usr/share/bug; \
    find /usr/local -depth -type d -name __pycache__ -exec rm -rf {} +; \
    # Drop test directories that are clearly named `tests` (plural).
    # Avoid `testing` which networkx and some other libs use as a real
    # functional submodule.
    find /usr/local/lib/python3.12/site-packages \
        -type d -name tests -prune -exec rm -rf {} +; \
    rm -rf /usr/share/nmap/nselib/data /usr/share/doc/nmap; \
    rm -rf /usr/lib/node_modules/npm/docs \
           /usr/lib/node_modules/npm/man \
           /usr/lib/node_modules/npm/changelogs; \
    # Drop pip + wheel; keep setuptools (just reinstalled above) and
    # aiohttp because checkov imports it eagerly at top level.
    pip uninstall -y pip wheel || true; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* \
           /root/.cache /var/tmp/*

# Copy the project source as-is. Whichever package layout `main` is
# carrying (`src/` today, `securescan/` after SS9), the directory ends
# up under /app and the entry-point shim below picks it up.
COPY --from=builder /artifact /app
ENV PYTHONPATH=/app

# Write a small console-script entry point that tolerates either
# package layout. Replaces the auto-generated `securescan` shim that
# pip would have placed for us if we'd installed the wheel directly.
# Also handles `--version` (the typer app does not implement one) by
# reading installed package metadata so the HEALTHCHECK can rely on it.
RUN printf '%s\n' \
        '#!/usr/local/bin/python' \
        'import sys' \
        'if len(sys.argv) >= 2 and sys.argv[1] in ("--version", "-V"):' \
        '    try:' \
        '        from importlib.metadata import version, PackageNotFoundError' \
        '        try:' \
        '            v = version("securescan")' \
        '        except PackageNotFoundError:' \
        '            v = "0.0.0+source"' \
        '    except Exception:' \
        '        v = "unknown"' \
        '    print("securescan " + v)' \
        '    sys.exit(0)' \
        'try:' \
        '    from securescan.cli import app' \
        'except ImportError:' \
        '    from src.cli import app' \
        'if __name__ == "__main__":' \
        '    sys.exit(app() or 0)' \
        > /usr/local/bin/securescan \
    && chmod 0755 /usr/local/bin/securescan

# Run as a non-root user. UID 65532 matches the upstream "nonroot"
# convention used by distroless / chainguard images so volume-mount
# permissions line up with what users expect.
RUN groupadd --system --gid 65532 nonroot \
    && useradd --system --uid 65532 --gid 65532 --home /home/nonroot --shell /sbin/nologin nonroot \
    && mkdir -p /home/nonroot /workspace \
    && chown -R nonroot:nonroot /home/nonroot /workspace

USER 65532:65532
WORKDIR /workspace

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["securescan", "--version"]

ENTRYPOINT ["securescan"]
CMD ["--help"]
