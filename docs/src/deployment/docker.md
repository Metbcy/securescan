# Docker

The container image is the recommended production deployment path —
multi-arch (amd64 + arm64), all 14 scanners pre-installed, signed
with cosign on every tagged release.

<!-- toc -->

## Image

```text
ghcr.io/metbcy/securescan:<tag>
```

| Tag           | Meaning                                                |
| ------------- | ------------------------------------------------------ |
| `v0.11.0`     | Specific tagged release. Immutable, signed with cosign. |
| `v1`          | Floating major-version tag. Auto-tracks `v1.x.y`.      |

```admonish important
**Pin to a specific tag in production.** Use `v0.11.0` or `v1`. The
`:latest` tag is **not** published — `cosign verify` only works
against tagged releases, so an unsigned floating reference is not
something we ship.
```

## Run the backend

Minimum:

```bash
docker run --rm -p 8000:8000 \
  -e SECURESCAN_API_KEY="$(openssl rand -hex 32)" \
  ghcr.io/metbcy/securescan:v0.11.0 \
  serve --host 0.0.0.0 --port 8000
```

Production-shape:

```bash
docker run -d \
  --name securescan-backend \
  -p 127.0.0.1:8000:8000 \
  -e SECURESCAN_AUTH_REQUIRED=1 \
  -e SECURESCAN_API_KEY="$(cat /run/secrets/securescan-api-key)" \
  -e SECURESCAN_EVENT_TOKEN_SECRET="$(cat /run/secrets/securescan-event-token-secret)" \
  -e SECURESCAN_LOG_FORMAT=json \
  -e SECURESCAN_RATE_LIMIT_PER_MIN=120 \
  -e SECURESCAN_IN_CONTAINER=1 \
  -v securescan-data:/data \
  -v securescan-config:/root/.config/securescan \
  --restart unless-stopped \
  ghcr.io/metbcy/securescan:v0.11.0 \
  serve --host 0.0.0.0 --port 8000 --workers 1
```

Notes:

- Bind to `127.0.0.1:8000` and put a TLS-terminating reverse proxy
  (nginx, Traefik) in front. The bundled uvicorn serves plain HTTP.
- `--workers 1` is **required** for SSE and the in-process webhook
  dispatcher. See [Single-worker constraint](./single-worker.md).
- The `securescan-data` volume holds the SQLite DB. Back it up.
- `securescan-config` persists `~/.config/securescan/.env` for ZAP
  credentials etc. See [Local config](./local-config.md).

## Run a one-shot scan from the CLI

```bash
docker run --rm \
  -v "$PWD:/work" -w /work \
  ghcr.io/metbcy/securescan:v0.11.0 \
  diff . --base-ref origin/main --head-ref HEAD \
         --output github-pr-comment
```

Image entry point routes to the same `securescan` CLI as `pip
install securescan`. Anything you can do with `securescan` directly
works inside the container.

## docker compose

The repo ships a `docker-compose.yml` for local development that
brings up backend + frontend together:

```bash
cd ~/Documents/securescan
docker compose up
```

Visit `http://localhost:3000` for the dashboard,
`http://localhost:8000/docs` for the API.

This stack is **not** production-shape — the frontend is the dev
build, the backend has no auth, no TLS, no rate limit tuning. Use it
to evaluate, then build a real deploy from this page.

## Kubernetes (sketch)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: securescan }
spec:
  replicas: 1                                      # NOT >1; see single-worker constraint
  selector: { matchLabels: { app: securescan } }
  template:
    metadata: { labels: { app: securescan } }
    spec:
      containers:
        - name: securescan
          image: ghcr.io/metbcy/securescan:v0.11.0
          args: [ "serve", "--host", "0.0.0.0", "--port", "8000", "--workers", "1" ]
          ports: [{ containerPort: 8000 }]
          envFrom:
            - secretRef: { name: securescan-secrets }
          env:
            - { name: SECURESCAN_AUTH_REQUIRED,  value: "1" }
            - { name: SECURESCAN_LOG_FORMAT,     value: "json" }
            - { name: SECURESCAN_IN_CONTAINER,   value: "1" }
          livenessProbe:
            httpGet: { path: /health, port: 8000 }
            initialDelaySeconds: 5
            periodSeconds: 10
          readinessProbe:
            httpGet: { path: /ready, port: 8000 }
            initialDelaySeconds: 2
            periodSeconds: 5
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          persistentVolumeClaim: { claimName: securescan-data }
```

The `securescan-secrets` Secret should contain at minimum:

```text
SECURESCAN_API_KEY=...
SECURESCAN_EVENT_TOKEN_SECRET=...
```

```admonish warning
`replicas: 1`. SecureScan is single-worker because the event bus
and webhook dispatcher are in-process. To scale horizontally,
deploy multiple separate Deployments behind a sticky-session
ingress keyed on `scan_id`. See [Single-worker constraint](./single-worker.md).
```

## Image contents

The bundled scanners are pinned at build time. To see versions:

```bash
docker run --rm ghcr.io/metbcy/securescan:v0.11.0 status
```

| Tool          | How it ships         |
| ------------- | -------------------- |
| `semgrep`     | pip wheel            |
| `bandit`      | pip wheel            |
| `safety`      | pip wheel            |
| `pip-licenses`| pip wheel            |
| `checkov`     | pip wheel            |
| `trivy`       | apt + GitHub release |
| `npm-audit`   | bundled `npm`        |
| `nmap`        | apt                  |
| `zap`         | NOT bundled — too large; install on the host or run separately |
| `gitleaks`    | apt + GitHub release |

ZAP is the only scanner not in the image. For DAST scans, run ZAP as
a separate container and point SecureScan at it via
`SECURESCAN_ZAP_ADDRESS`.

## Container vs wheel

| Concern                         | Container                              | Wheel (PyPI)                                       |
| ------------------------------- | -------------------------------------- | -------------------------------------------------- |
| Reproducible scanner versions   | ✅ pinned at image build               | ❌ depends on host                                  |
| Easy install                    | ✅ `docker run`                        | ✅ `pip install securescan`                        |
| Easy upgrade                    | ✅ image bump                          | ✅ `pip install -U securescan`                     |
| Smaller install                 | ❌ ~600MB                              | ✅ ~10MB plus whatever scanners you install        |
| Run ZAP / nmap                  | Need separate ZAP; nmap inside         | Run on host                                        |
| Signed artifact                 | ✅ cosign                              | ✅ sigstore-python (`*.sigstore.json` bundle)      |

The GitHub Action picks the right one for you: tries the wheel
first, falls back to the container if scanner binaries are missing.

## Verifying the image

Before running in production, verify the cosign signature:

```bash
cosign verify ghcr.io/metbcy/securescan:v0.11.0 \
  --certificate-identity 'https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/v0.11.0' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Full guide: [Verifying signed artifacts](./verifying-artifacts.md).

## Next

- [Production checklist](./production-checklist.md) — the full pre-flight.
- [Configuration reference](./configuration.md) — every env var.
- [Single-worker constraint](./single-worker.md) — why and how to scale.
- [Verifying signed artifacts](./verifying-artifacts.md) — cosign + sigstore.
