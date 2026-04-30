# Auth production checklist

A pre-flight specifically for the **authentication surface**. The
broader [Production checklist](../deployment/production-checklist.md)
includes this plus the rest (rate limits, single-worker, signed
artifacts, health probes).

<!-- toc -->

## Before exposing the API

- [ ] **At least one credential exists.** Either:
  - Set `SECURESCAN_API_KEY` to a strong random string (e.g.
    `openssl rand -hex 32`); OR
  - Create a DB-backed admin key via `POST /api/v1/keys` (see
    [API keys](./api-keys.md)).
- [ ] **`SECURESCAN_AUTH_REQUIRED=1` is set.** Without it, dev-mode
  fallback applies if all credentials are removed (silent
  unauthenticated state). With it, the backend exits with code 2 at
  startup if no credentials exist — fail-closed.
- [ ] **`SECURESCAN_EVENT_TOKEN_SECRET` is set** (required when
  `AUTH_REQUIRED=1`). Without it, every backend restart breaks
  in-flight SSE tokens. See [SSE event tokens](./event-tokens.md).

```bash
# Suggested env-var generation (Linux / macOS)
export SECURESCAN_AUTH_REQUIRED=1
export SECURESCAN_EVENT_TOKEN_SECRET="$(openssl rand -hex 32)"
# Either keep the legacy env-var key as a break-glass...
export SECURESCAN_API_KEY="$(openssl rand -hex 32)"
# ...or rely on DB keys exclusively (post-migration).
```

## DB key issuance

- [ ] **Issue at least one admin key** via the API or the dashboard
  before turning off `SECURESCAN_API_KEY`. Otherwise revoking the
  last admin key would lock you out — lockout protection catches the
  symmetric case but not "operator manually removed env var."
- [ ] **One admin key, scoped down per consumer.** A CI runner gets
  `["read", "write"]`. A monitoring dashboard gets `["read"]`. Only
  the operator's break-glass identity gets `admin`.
- [ ] **Save the secret to your secrets manager immediately.** The
  plaintext is returned exactly once.
- [ ] **Document key ownership.** Set `name` to something
  identifiable (`ci-runner`, `read-only-monitoring`, `breakglass-2026q2`).
  When you list keys later, you'll be able to tell which is which.

## Network exposure

- [ ] **Terminate TLS in front of SecureScan.** The bundled uvicorn
  serves plain HTTP. nginx, Traefik, AWS ALB, or Caddy are all
  reasonable.
- [ ] **Forward `X-Request-ID`** through the proxy so client
  correlation works end-to-end.
- [ ] **Restrict access to `/docs`, `/redoc`, `/openapi.json`** if
  your threat model includes "an unauthenticated actor learning the
  API surface." These describe every route — including admin — but
  expose no data. For most internal deployments, leaving them open
  to authenticated network paths is fine.

```admonish note
SecureScan does **not** ship its own SSO / OIDC integration. If you
need user-mapped auth, put it in front of SecureScan (oauth2-proxy,
Cloudflare Access, AWS ALB OIDC) and treat the backend as a service
that authenticates via API keys. The dashboard's
`NEXT_PUBLIC_SECURESCAN_API_KEY` is then a service identity for the
proxy, not a user identity.
```

## Frontend wiring

- [ ] **`NEXT_PUBLIC_SECURESCAN_API_KEY` is a `read`-scope key**, not
  admin. The value is baked into the build and shipped to the
  browser. Anyone who can hit the dashboard can read its key off the
  network tab. Only deploy the dashboard somewhere already protected
  by your front-line auth (SSO, mTLS).
- [ ] **The dashboard is not exposed publicly.** If it is, every
  visitor automatically has `read` (and any other scope you scoped
  it to) on the backend. That's a deliberately simple model — keep
  it inside your network perimeter.

## Operational

- [ ] **Rotation procedure documented.** Know in advance how to issue
  a new key and revoke an old one. See
  [API keys → Lifecycle: rotate a key](./api-keys.md#lifecycle-rotate-a-key).
- [ ] **Alarm on auth failures.** Tail the structured logs for
  `securescan.request` lines with `status: 401` and graph them. A
  spike past your normal noise floor means something has gone wrong
  (key expired, brute-force attempt, misconfigured caller).
- [ ] **Periodic key audit.** `GET /api/v1/keys` lists every key with
  `last_used_at`. Anything not used in 90 days is a candidate for
  revocation.

## SSE / real-time progress

- [ ] **`SECURESCAN_EVENT_TOKEN_SECRET` is set and stable** across
  restarts. Rotating this secret invalidates every outstanding event
  token; your dashboard's live progress will go blind for ~5 minutes
  while clients re-mint.
- [ ] **Run `--workers 1`.** The event bus is in-process; multi-worker
  uvicorn fragments the bus and SSE breaks silently. See
  [Single-worker constraint](../deployment/single-worker.md).
- [ ] **Sticky sessions on `scan_id`** if you scale horizontally.
  Each scan's SSE subscribers must land on the same backend instance
  that runs the scan.

## Incident response

- [ ] **Revoke a leaked key immediately.** `DELETE /api/v1/keys/{id}`
  takes effect on the next request. No cache, no propagation delay.
- [ ] **Rotate `SECURESCAN_EVENT_TOKEN_SECRET`** if an event token
  was specifically leaked. All outstanding tokens become invalid;
  legitimate clients re-mint within seconds.
- [ ] **`SECURESCAN_API_KEY` rotation requires a backend restart.**
  The env-var path reads on every request, but a hot rotation means
  the new value isn't picked up until the process restarts. To do a
  zero-downtime rotation, issue a DB key first, switch the consumer,
  then update / restart.

## Verifying a deployment is hardened

```bash
# 1. Auth is required:
$ curl -i http://127.0.0.1:8000/api/v1/scans
HTTP/1.1 401 Unauthorized
{"detail":"X-API-Key header required"}

# 2. Bogus key 401s (does not fall through to dev mode):
$ curl -i -H "X-API-Key: nope" http://127.0.0.1:8000/api/v1/scans
HTTP/1.1 401 Unauthorized
{"detail":"Invalid API key"}

# 3. Read-only key cannot create a scan:
$ curl -i -X POST -H "X-API-Key: $READ_KEY" \
    -d '{"target_path":"/tmp","scan_types":["code"]}' \
    http://127.0.0.1:8000/api/v1/scans
HTTP/1.1 403 Forbidden
{"detail":"Requires scope: write"}

# 4. Write key cannot list webhook subscriptions:
$ curl -i -H "X-API-Key: $WRITE_KEY" http://127.0.0.1:8000/api/v1/webhooks
HTTP/1.1 403 Forbidden
{"detail":"Requires scope: admin"}

# 5. /health and /ready are public:
$ curl -s http://127.0.0.1:8000/health
{"status":"ok"}

# 6. Lockout protection refuses removing the last admin key:
$ curl -i -X DELETE -H "X-API-Key: $ADMIN_KEY" \
    http://127.0.0.1:8000/api/v1/keys/$ONLY_ADMIN
HTTP/1.1 409 Conflict
{"detail":"Cannot revoke last admin key without an env-var fallback"}
```

If those six are green, the auth surface is correctly configured.

## Next

- [API keys](./api-keys.md) — issuance, rotation, lockout protection.
- [Scopes](./scopes.md) — what each scope grants, route by route.
- [SSE event tokens](./event-tokens.md) — auth on the live stream.
- [Production checklist](../deployment/production-checklist.md) — the broader pre-flight.
