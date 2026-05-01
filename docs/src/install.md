# Install

SecureScan ships three install paths. Pick the one that matches **how
you intend to run it**, not necessarily where it ends up.

<!-- toc -->

## 1. Container (recommended for production)

The image is multi-arch (amd64 + arm64), comes with all 14 scanners
pre-installed at pinned versions, and is what the GitHub Action falls
back to when wheel-mode prerequisites are not met.

```bash
docker pull ghcr.io/metbcy/securescan:v0.11.0
docker run --rm -v "$PWD:/work" -w /work \
  ghcr.io/metbcy/securescan:v0.11.0 \
  diff . --base-ref origin/main --head-ref HEAD --output github-pr-comment
```

To run the dashboard backend:

```bash
docker run --rm -p 8000:8000 \
  -e SECURESCAN_API_KEY="$(openssl rand -hex 32)" \
  ghcr.io/metbcy/securescan:v0.11.0 \
  serve --host 0.0.0.0 --port 8000
```

```admonish important
Production deployments **must** verify the image signature with
`cosign` before running. See
[Verifying signed artifacts](./deployment/verifying-artifacts.md).
```

The image follows the release schedule documented in
[Release process](./reference/release-process.md). All tags from
`v0.2.0` onward are signed.

## 2. Wheel from PyPI

```bash
pip install securescan                  # latest stable
pip install securescan==0.11.0          # exact pin

# Or, isolated, via pipx:
pipx install securescan
```

```admonish note
PDF reports (`securescan scan ... --output report-pdf`) require the
optional `[pdf]` extra, which pulls in WeasyPrint and its Cairo /
Pango / GObject system-library chain:

    pip install 'securescan[pdf]'

The container image ships `weasyprint` pre-installed, so PDF reports
work out of the box there. Without the extra, requesting
`--output report-pdf` raises a clear `RuntimeError` pointing back at
this install step.
```

The wheel only ships SecureScan itself. The underlying scanner CLIs
(`semgrep`, `bandit`, `safety`, `pip-licenses`, `checkov`, `trivy`,
`npm`, `nmap`, ZAP, …) need to be installed separately and on `PATH`
for the scanners that wrap them to run. Use `securescan status` to
see which ones are detected:

```bash
$ securescan status
Scanner       Type         Available  Version
semgrep       code         yes        1.71.0
bandit        code         yes        1.7.5
trivy         dependency   yes        0.49.1
checkov       iac          no         (run: pip install checkov)
zap           dast         no         (run: brew install zaproxy)
nmap          network      yes        7.94
...
```

If you do not want to manage scanner installs yourself, use the
container instead.

### Verify the wheel signature

Every tagged release is signed with sigstore-python. To verify the
wheel:

```bash
RELEASE=v0.11.0
gh release download $RELEASE -R Metbcy/securescan \
  -p 'securescan-*.whl' -p 'securescan-*.whl.sigstore.json'

pip install sigstore
sigstore verify identity \
  --cert-identity "https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/${RELEASE}" \
  --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --bundle securescan-${RELEASE#v}-py3-none-any.whl.sigstore.json \
  securescan-${RELEASE#v}-py3-none-any.whl
```

The `*.sigstore.json` bundles ship as GitHub Release assets. PyPI
itself does not host them.

## 3. GitHub Action (CI/CD)

The composite action wraps `securescan diff`, posts the upserted PR
comment, and uploads SARIF. It tries the wheel first and falls back
to the pinned container image when scanner binaries are not on
`PATH`.

```yaml
# .github/workflows/securescan.yml
on: pull_request

permissions:
  contents: read
  pull-requests: write    # required for the upserted PR comment
  security-events: write  # required for SARIF upload

jobs:
  securescan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # diff needs both base and head commits
      - uses: Metbcy/securescan@v1
        with:
          scan-types: code,dependency
          fail-on-severity: high
```

See [GitHub Action](./cli/github-action.md) for the full input
reference, inline-review mode, and permission requirements.

## From source (development)

Only needed if you are contributing to SecureScan itself.

```bash
git clone https://github.com/Metbcy/securescan
cd securescan/backend
python3 -m venv venv && source venv/bin/activate
pip install -e .
pip install semgrep bandit safety pip-licenses checkov  # plus any others you want
securescan serve --host 127.0.0.1 --port 8000
```

In a second shell:

```bash
cd securescan/frontend
npm install
npm run dev    # http://localhost:3000
```

See [Contributing](./contributing.md) for the test/lint/release loop.

## What gets installed where

| Path                                              | Contents                                                              |
| ------------------------------------------------- | --------------------------------------------------------------------- |
| `securescan` (binary on PATH)                     | Python entry point. Routes to `serve`, `scan`, `diff`, `compare`, …   |
| `~/.config/securescan/.env`                       | Optional persisted env vars (ZAP creds, etc). [Local config](./deployment/local-config.md). |
| SQLite DB (default `~/.securescan/scans.db`)      | Scans, findings, triage state, API keys, webhooks, deliveries.        |
| `/tmp/securescan-backend.log` (when serving)      | Structured scan-lifecycle log lines.                                  |

```admonish note
The dashboard frontend is a separate Next.js app. The container ships
**only** the backend; deploy the frontend independently or use
`docker compose up` from the repo root for an all-in-one local stack.
```

## Next

- [Quick start: your first scan](./quick-start.md) — end-to-end walkthrough.
- [Production checklist](./deployment/production-checklist.md) — when you go past `localhost`.
