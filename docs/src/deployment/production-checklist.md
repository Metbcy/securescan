# Production checklist

A literal pre-flight before exposing SecureScan past `localhost`.
Every box is a real configuration step; skipping any of them has a
known consequence noted in the linked page.

<!-- toc -->

## Auth

- [ ] **Set `SECURESCAN_API_KEY`** *(or)* create at least one DB-backed
      admin key via `POST /api/v1/keys`. Without either, the backend
      runs in dev mode and serves every request unauthenticated.
      → [API keys](../auth/api-keys.md)
- [ ] **Set `SECURESCAN_AUTH_REQUIRED=1`.** Without this flag, an empty
      DB plus an unset env var silently falls back to dev mode. With
      it, the backend exits with code 2 at startup if no credentials
      exist — fail-closed.
      → [Authentication overview](../auth/overview.md)
- [ ] **Set `SECURESCAN_EVENT_TOKEN_SECRET`** (required when
      `AUTH_REQUIRED=1`). Without it, every backend restart picks a
      new ephemeral signing secret and any in-flight SSE token from
      the dashboard 401s — live progress goes blind.
      → [SSE event tokens](../auth/event-tokens.md)
- [ ] **Use scoped DB keys, not the env-var key, for every consumer.**
      The env var is full-trust by design. CI runners get
      `["read", "write"]`; monitoring gets `["read"]`. Reserve
      `admin` for one operator break-glass identity.
      → [Scopes](../auth/scopes.md)

## Rate limits

- [ ] **Set `SECURESCAN_RATE_LIMIT_PER_MIN`** and
      `SECURESCAN_RATE_LIMIT_BURST` if the defaults (60/min, burst 10)
      don't fit your scan cadence. Higher for a CI fleet sharing a
      key; lower for a multi-tenant proxy.
      → [Rate limits](../api/rate-limits.md)
- [ ] **Do not disable rate limiting** unless you have a smarter
      rate limiter in front of SecureScan (envoy / nginx). The
      bucket is the only thing standing between a curl loop and a
      forked-bombed orchestrator.

## Single-worker constraint

- [ ] **Confirm `--workers 1`** on the uvicorn invocation (the default).
      The event bus and webhook dispatcher are in-process; multi-worker
      uvicorn fragments them and SSE / webhooks break silently.
      → [Single-worker constraint](./single-worker.md)
- [ ] **Sticky sessions on `scan_id`** if you scale horizontally. Each
      scan's SSE subscribers must land on the same backend instance
      that runs the scan. Multi-process pubsub (Redis) is on the
      roadmap.

## Local config persistence

- [ ] **Persist `~/.config/securescan/.env`** (or
      `$XDG_CONFIG_HOME/securescan/.env`) across deploys / restarts.
      That is where ZAP credentials and other secrets live; without
      persistence you re-export them on every boot.
      → [Local config (.env)](./local-config.md)

## Signed artifacts

- [ ] **Verify the wheel signature** with sigstore-python before
      installing in a CI image:

      ```bash
      sigstore verify identity \
        --cert-identity 'https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/v0.11.0' \
        --cert-oidc-issuer 'https://token.actions.githubusercontent.com' \
        --bundle securescan-0.11.0-py3-none-any.whl.sigstore.json \
        securescan-0.11.0-py3-none-any.whl
      ```

- [ ] **Verify the container image** with cosign before pulling into a
      production registry:

      ```bash
      cosign verify ghcr.io/metbcy/securescan@<digest> \
        --certificate-identity 'https://github.com/Metbcy/securescan/.github/workflows/release.yml@refs/tags/v0.11.0' \
        --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
      ```

      → [Verifying signed artifacts](./verifying-artifacts.md)

## Health probes

- [ ] **Confirm `/health` and `/ready` are reachable from your
      load balancer.** Both are public regardless of API-key
      configuration. Sample Kubernetes fragment:

      ```yaml
      livenessProbe:
        httpGet: { path: /health, port: 8000 }
        initialDelaySeconds: 5
        periodSeconds: 10
      readinessProbe:
        httpGet: { path: /ready, port: 8000 }
        initialDelaySeconds: 2
        periodSeconds: 5
      ```

      `/health` returns 200 unless the process is crashing. `/ready`
      returns 200 with checks JSON when DB + scanner registry are
      OK; 503 with details otherwise.

## TLS / reverse proxy

- [ ] **Terminate TLS in front of SecureScan.** The bundled uvicorn
      serves plain HTTP. nginx, Traefik, AWS ALB, Caddy all work.
- [ ] **Forward `X-Request-ID`** through the proxy so client
      correlation works end-to-end. Clients can pin a request id;
      the server echoes it back on the response.
- [ ] **Set `SECURESCAN_CORS_ORIGINS`** to your dashboard origin(s)
      (comma-separated) if the frontend is on a different host than
      the backend. Defaults are localhost-only.

## Logging

- [ ] **Set `SECURESCAN_LOG_FORMAT=json`** in containers (auto-set
      when `SECURESCAN_IN_CONTAINER=1`). Each request emits one
      structured log line on `securescan.request` with `request_id`,
      `method`, `path`, `status`, `latency_ms`. Scan lifecycle
      events go on `securescan.scan`.
- [ ] **Aggregate logs centrally.** Filter by `logger:
      securescan.scan` to track scan-level events; by
      `logger: securescan.request` for HTTP traffic.

## Database

- [ ] **Persist the SQLite DB volume.** Default path is
      `~/.securescan/scans.db` (or under `/data` in the container).
      Loss of this DB loses scans, findings, triage state, API keys,
      webhooks, and notifications.
- [ ] **Back it up.** SQLite's `.backup` command works while the
      backend is running — use it on a cron schedule.

## Frontend

- [ ] **`NEXT_PUBLIC_SECURESCAN_API_KEY` is a `read`-scope key**, not
      `admin`. The value is baked into the build and shipped to the
      browser. Anyone hitting the dashboard automatically inherits
      that key's scopes.
- [ ] **The dashboard is not exposed publicly.** SecureScan does not
      ship its own SSO / OIDC integration. Put the dashboard behind
      your front-line auth (oauth2-proxy, Cloudflare Access, AWS ALB
      OIDC). The dashboard's API key becomes a service identity, not
      a user identity.

## Webhooks (optional, if you use them)

- [ ] **The receiver verifies HMAC and rejects stale timestamps**
      (>5 minutes old). At-least-once delivery is the contract;
      receivers must be idempotent.
      → [Webhooks](../dashboard/webhooks.md#signature-verification)
- [ ] **Slack / Discord URLs are treated as secrets.** Those receivers
      do not verify HMAC; the URL itself is the authorization. Don't
      share, rotate (delete + recreate) on suspicion of leak.

## Operational

- [ ] **Document the rotation procedure** for `SECURESCAN_API_KEY`,
      DB keys, `SECURESCAN_EVENT_TOKEN_SECRET`, and webhook secrets.
- [ ] **Alarm on spikes of 401 / 403** in the request log. Indicates
      key expired, brute-force attempt, or misconfigured caller.
- [ ] **Alarm on spikes of 5xx.** Crashes don't auto-recover; a
      restart loop in liveness deserves attention.
- [ ] **Periodically audit `GET /api/v1/keys`** for keys with no
      `last_used_at` in the last 90 days — candidates for
      revocation.

## Smoke test

After deploy, run these as a quick sanity check:

```bash
# 1. Liveness + readiness
$ curl -fs https://securescan.example.com/health
{"status":"ok"}
$ curl -fs https://securescan.example.com/ready
{"status":"ready","checks":{...}}

# 2. Auth is required (no key = 401)
$ curl -i -s https://securescan.example.com/api/v1/scans
HTTP/1.1 401 Unauthorized

# 3. Bogus key = 401 (does not fall through to dev mode)
$ curl -i -s -H "X-API-Key: nope" https://securescan.example.com/api/v1/scans
HTTP/1.1 401 Unauthorized

# 4. Read-only key cannot start a scan
$ curl -i -s -X POST -H "X-API-Key: $READ_KEY" \
    -d '{"target_path":"/tmp","scan_types":["code"]}' \
    https://securescan.example.com/api/v1/scans
HTTP/1.1 403 Forbidden

# 5. /docs renders
$ curl -fs https://securescan.example.com/openapi.json | jq '.info.title'
"SecureScan"
```

If those five are green, the deploy is safe to take traffic.

## Next

- [Configuration reference](./configuration.md) — every env var.
- [Auth production checklist](../auth/production-checklist.md) — narrower auth-only checklist.
- [Verifying signed artifacts](./verifying-artifacts.md) — full sigstore + cosign guide.
- [Single-worker constraint](./single-worker.md) — what fails on `--workers 2`.
