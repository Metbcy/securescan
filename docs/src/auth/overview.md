# Authentication overview

SecureScan supports three credential types and one fallthrough mode:

| Source             | Format              | Scopes                  | Where it lives                                    |
| ------------------ | ------------------- | ----------------------- | ------------------------------------------------- |
| Env-var (legacy)   | Any string          | `read + write + admin`  | `SECURESCAN_API_KEY` env var                      |
| DB-issued key      | `ssk_<id>_<secret>` | Per-key (declared)      | `api_keys` table, salted-SHA-256 hashed           |
| SSE event token    | `base64url(...)`    | Inherits caller's       | `?event_token=...` on `/scans/{id}/events` only   |
| **Dev mode**       | (none)              | All — fail-open         | When neither of the first two is configured       |

The auth path is in
[`backend/securescan/auth.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/auth.py).

<!-- toc -->

## Decision tree

```mermaid
flowchart TD
  Req[Incoming request to /api/*] --> SSE{SSE route<br>and ?event_token=...?}
  SSE -->|yes| Tok[Validate HMAC, expiry,<br>scan_id binding,<br>rehydrate principal]
  SSE -->|no| Hdr{X-API-Key or<br>Authorization: Bearer set?}
  Hdr -->|yes| Match{Matches<br>env or DB?}
  Match -->|env match| EnvP[Principal: env, all scopes]
  Match -->|DB match, not revoked| DbP[Principal: db, row.scopes]
  Match -->|no match| F401[401 Invalid API key]
  Hdr -->|no| Has{any creds<br>configured?}
  Has -->|yes| F401b[401 X-API-Key required]
  Has -->|no| Required{AUTH_REQUIRED=1?}
  Required -->|yes| F503[503 unreachable in practice;<br>startup raised SystemExit]
  Required -->|no| Dev[None: dev mode passthrough]

  Tok --> Scope[require_scope]
  EnvP --> Scope
  DbP --> Scope
  Dev --> Scope
  Scope -->|scope OK| H[Route handler]
  Scope -->|missing| F403[403 Requires scope: ...]
```

## Three things to set in production

```admonish important
At minimum, a production deployment must:

1. **Configure credentials.** Either set `SECURESCAN_API_KEY` (legacy
   single-key) OR create at least one DB key with `admin` scope via
   `POST /api/v1/keys`. See [API keys](./api-keys.md).

2. **Set `SECURESCAN_AUTH_REQUIRED=1`.** Without it, an empty DB
   plus an unset env var silently falls back to dev mode (every
   request passes through). With it, the backend exits with status
   code 2 at startup if no credentials exist.

3. **Set `SECURESCAN_EVENT_TOKEN_SECRET`.** Required when
   `AUTH_REQUIRED=1`. Without it, every backend restart breaks any
   in-flight SSE tokens and the live-progress dashboard goes blind.
   See [SSE event tokens](./event-tokens.md).
```

The full pre-flight is on the [Production checklist](./production-checklist.md).

## Public endpoints

These never require auth — they are for Kubernetes / load-balancer
probes and the API discovery surface:

| Endpoint        | Purpose                                                              |
| --------------- | -------------------------------------------------------------------- |
| `GET /`         | API root: `{name, status, docs, health}`. No DB read.                |
| `GET /health`   | Liveness — process up. Always 200 unless crashing.                   |
| `GET /ready`    | Readiness — DB openable + scanner registry loaded. 200 or 503.       |
| `GET /docs`     | FastAPI Swagger UI (auto-generated from the route schemas).          |
| `GET /redoc`    | FastAPI ReDoc UI.                                                    |
| `GET /openapi.json` | OpenAPI document.                                                |

```admonish warning
`/docs`, `/redoc`, and `/openapi.json` describe **every** route on
the server, including admin-scope ones. They do not expose data, but
they do expose the surface. If your threat model includes that, put
the dashboard behind a TLS-terminating proxy with IP allowlisting —
SecureScan's auth model is intentionally simple and assumes the API
is not directly internet-facing. The legacy unprefixed `/api/*`
paths additionally carry deprecation headers, which leak nothing
sensitive but do tell a probe the version. See
[Production checklist](../deployment/production-checklist.md).
```

## Header formats

Every authenticated route accepts **either** of:

```http
X-API-Key: ssk_5a7c8f9e_abc123def...
```

```http
Authorization: Bearer ssk_5a7c8f9e_abc123def...
```

The Bearer form exists because some HTTP clients (curl with
`--user`, some load balancers) handle `Authorization` more
ergonomically than custom headers. They are equivalent.

For the SSE event-token path on `/scans/{id}/events`, neither header
is used — the token rides in the query string:

```http
GET /api/v1/scans/0f1a93cb/events?event_token=eyJzY2FuX2lkI...
```

This is the **only** route on which `event_token` is honored. Any
other URL with a query-string token gets 401.

## Dev mode

When **no env var** is set AND **no DB keys** exist AND
`AUTH_REQUIRED=0` (the default), the backend logs a startup banner:

```text
SECURESCAN_API_KEY not set; API is unauthenticated (dev mode).
```

Every `/api/*` request passes through. `request.state.principal` is
`None`; `require_scope(...)` fails open in this case so route-level
scope checks do not block local development.

This is **convenient for one-machine local development** and
**unacceptable for anything else**. The startup banner is a warning,
not a request-time block. See [Production checklist](./production-checklist.md).

## What happens to a revoked key

- An explicit-but-bogus key — even one that *was* valid yesterday —
  always returns 401. It does **not** fall through to dev mode just
  because no other DB keys remain.
- An SSE event token bound to a now-revoked DB key fails the
  rehydrate step at connect time and returns 401, even if the token
  HMAC and TTL are still valid. Revocation is immediate.
- The `last_used_at` touch only writes on a successful auth, so a
  rate of 401s does not pound the `api_keys` table.

The "explicit-but-bogus → always 401" path was a v0.8.0 bug fix:
without it, revoking your only key would silently flip the system
back to dev mode and the revoked key would keep working until at
least one other key was created. Regression test in
`test_revoked_db_key_rejected_when_no_env_var`.

## What's authenticated, what isn't

| Surface                                       | Auth required (when configured)?                                |
| --------------------------------------------- | --------------------------------------------------------------- |
| Every `/api/*` route                          | Yes, with explicit per-route scope                              |
| `/health`, `/ready`                           | No — public for probes                                          |
| `/docs`, `/redoc`, `/openapi.json`            | No — schema is the API surface, not data                        |
| Static dashboard assets (Next.js)             | Out of scope; deploy frontend behind your own auth              |
| Frontend → API requests                       | Yes — frontend injects the `NEXT_PUBLIC_SECURESCAN_API_KEY`     |
| SSE `/scans/{id}/events`                      | Yes, via short-lived event token (browsers can't send headers)  |

## Source

- `auth.py` — `Principal`, `require_api_key`, `require_scope`,
  `assert_auth_credentials_configured`.
- `api_keys.py` — key generation, salted-SHA-256 hashing, `parse_key_id`.
- `event_tokens.py` — SSE token mint/verify.
- `api/keys.py` — CRUD endpoints for DB keys.

## Next

- [API keys](./api-keys.md) — DB-issued keys, the v0.8.0 way.
- [Scopes](./scopes.md) — read / write / admin per route.
- [SSE event tokens](./event-tokens.md) — auth on EventSource.
- [Production checklist](./production-checklist.md) — the pre-flight.
