# Configuration reference

Every environment variable SecureScan reads, what it controls, and
its default. All variables are optional unless flagged otherwise.

<!-- toc -->

## Authentication

| Variable                          | Default | Description                                                                                                  |
| --------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------ |
| `SECURESCAN_API_KEY`              | (unset) | Legacy single-shared-key auth. Treated as a synthetic principal with all scopes. When unset and no DB keys exist, runs in dev mode. |
| `SECURESCAN_AUTH_REQUIRED`        | `0`     | When `1`, backend exits with code 2 at startup if no credentials configured. Required for hardened deploys. |
| `SECURESCAN_EVENT_TOKEN_SECRET`   | (auto)  | HMAC signing secret for SSE event tokens. **Required when `AUTH_REQUIRED=1`**. Ephemeral random in dev mode. |

→ [Authentication overview](../auth/overview.md),
[API keys](../auth/api-keys.md), [SSE event tokens](../auth/event-tokens.md).

## Rate limiting

| Variable                            | Default | Description                                                              |
| ----------------------------------- | ------- | ------------------------------------------------------------------------ |
| `SECURESCAN_RATE_LIMIT_PER_MIN`     | `60`    | Sustained requests per minute on `POST /scans` (per principal / IP).     |
| `SECURESCAN_RATE_LIMIT_BURST`       | `10`    | Burst capacity above the sustained rate.                                 |
| `SECURESCAN_RATE_LIMIT_ENABLED`     | `true`  | Set to `false` to disable. Only do this if you have a smarter rate limiter in front. |

→ [Rate limits](../api/rate-limits.md).

## Logging

| Variable                            | Default                                  | Description                                                          |
| ----------------------------------- | ---------------------------------------- | -------------------------------------------------------------------- |
| `SECURESCAN_LOG_LEVEL`              | `INFO`                                   | `DEBUG` / `INFO` / `WARNING` / `ERROR`.                              |
| `SECURESCAN_LOG_FORMAT`             | `text` (or `json` if in container)       | `text` for dev TTY; `json` for container / aggregator-friendly.      |
| `SECURESCAN_IN_CONTAINER`           | `0`                                      | When `1`, default `LOG_FORMAT` flips to `json`.                      |

Each request emits one structured line on `securescan.request` with
`request_id`, `method`, `path`, `status`, `latency_ms`. Scan
lifecycle events go on `securescan.scan` with `event` + per-event
fields.

## CORS / network

| Variable                            | Default                                   | Description                                                          |
| ----------------------------------- | ----------------------------------------- | -------------------------------------------------------------------- |
| `SECURESCAN_CORS_ORIGINS`           | `localhost:3000,127.0.0.1:3000,localhost:3003,127.0.0.1:3003` | Comma-separated CORS origins.                  |

When the frontend and backend are on different hosts, set this to
the frontend's origin(s) so the browser doesn't get CORS-blocked.

## Frontend

| Variable                            | Default | Description                                                                |
| ----------------------------------- | ------- | -------------------------------------------------------------------------- |
| `NEXT_PUBLIC_SECURESCAN_API_KEY`    | (unset) | API key the dashboard injects on every request. Baked into the build.      |
| `NEXT_PUBLIC_SECURESCAN_API_URL`    | `http://localhost:8000` | Backend URL the dashboard talks to.                          |

Both are `NEXT_PUBLIC_*` (Next.js convention) so they end up in the
browser bundle. **Use a `read` scope key, not admin** — see
[Production checklist](./production-checklist.md).

## Scanner-specific

| Variable                            | Default                              | Description                                                                |
| ----------------------------------- | ------------------------------------ | -------------------------------------------------------------------------- |
| `SECURESCAN_ZAP_ADDRESS`            | `http://127.0.0.1:8090`              | URL of the ZAP daemon for the `zap` scanner.                               |
| `SECURESCAN_ZAP_API_KEY`            | (unset)                              | API key the ZAP daemon expects.                                            |
| `SECURESCAN_GROQ_API_KEY`           | (unset)                              | Groq API key for AI enrichment. AI is auto-disabled in CI (`CI=true`).     |

These can — and should — live in `~/.config/securescan/.env` rather
than the shell environment, so they persist across reboots. See
[Local config (.env)](./local-config.md).

## CI determinism

| Variable          | Default | Description                                                                                                |
| ----------------- | ------- | ---------------------------------------------------------------------------------------------------------- |
| `CI`              | (unset) | Set to `true` by GitHub Actions / GitLab CI / etc. SecureScan auto-disables AI enrichment when set.        |
| `SECURESCAN_FAKE_NOW` | (unset) | Pin the only time-derived field in output. Set in tests / CI replays for byte-identical output.        |

→ [How scans work → Determinism](../scanning/how-scans-work.md#determinism).

## Database

| Variable                            | Default                              | Description                                                                |
| ----------------------------------- | ------------------------------------ | -------------------------------------------------------------------------- |
| `SECURESCAN_DB_PATH`                | `~/.securescan/scans.db`             | SQLite DB file path. Persists scans, findings, triage state, keys, webhooks, notifications. |

In containers, mount a volume at this path. See [Docker](./docker.md).

## Examples

### Minimum production env

```bash
export SECURESCAN_AUTH_REQUIRED=1
export SECURESCAN_EVENT_TOKEN_SECRET="$(openssl rand -hex 32)"
export SECURESCAN_API_KEY="$(openssl rand -hex 32)"   # break-glass
export SECURESCAN_LOG_FORMAT=json
```

Then issue scoped DB keys for actual consumers (CI, dashboard) via
the API; reserve the env-var key for emergencies.

### Container env-file

```text
# /etc/securescan/env
SECURESCAN_AUTH_REQUIRED=1
SECURESCAN_EVENT_TOKEN_SECRET=replace-me-with-openssl-rand-hex-32
SECURESCAN_LOG_FORMAT=json
SECURESCAN_IN_CONTAINER=1
SECURESCAN_RATE_LIMIT_PER_MIN=120
SECURESCAN_RATE_LIMIT_BURST=20
SECURESCAN_CORS_ORIGINS=https://securescan.example.com
```

```bash
docker run --env-file /etc/securescan/env \
  -v securescan-data:/data \
  ghcr.io/metbcy/securescan:v0.11.0 \
  serve --host 0.0.0.0 --port 8000 --workers 1
```

### Tuning rate limits for a CI fleet

A team with 30 CI runners hitting the same key would saturate the
default 60/min. Bump it:

```bash
export SECURESCAN_RATE_LIMIT_PER_MIN=300
export SECURESCAN_RATE_LIMIT_BURST=30
```

Or — better — issue one DB key per runner so they have isolated
buckets.

## Source

- Most env vars resolve in
  [`backend/securescan/config.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/config.py).
- Auth-related: [`backend/securescan/auth.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/auth.py).
- Logging: [`backend/securescan/logging_config.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/logging_config.py).
- Local `.env` loader: [`backend/securescan/config_loader.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/config_loader.py).

## Next

- [Local config (.env)](./local-config.md) — the user-scoped env file.
- [Production checklist](./production-checklist.md) — how to use these together.
- [Authentication overview](../auth/overview.md).
