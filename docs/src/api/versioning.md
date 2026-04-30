# Versioning & deprecation

SecureScan v0.6.0 introduced an `/api/v1/...` mount that mirrors every
existing `/api/...` route. The legacy unprefixed paths continue to
work — the v0.5.0 CLIs, old GitHub Actions, and third-party scripts do
not break — but their responses now carry RFC 9745-style deprecation
headers so callers know where to migrate.

<!-- toc -->

## The two prefixes

| Prefix         | Status     | Notes                                                                        |
| -------------- | ---------- | ---------------------------------------------------------------------------- |
| `/api/v1/...`  | Current    | Use for all new code. No deprecation headers.                                |
| `/api/...`     | Deprecated | Identical handler. Adds `Deprecation: true`, `Link: ...`, `Sunset` headers.  |

Source:
[`backend/securescan/api/versioning.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/versioning.py).

## Deprecation headers

Every response under `/api/...` (but **not** `/api/v1/...`,
`/health`, `/ready`, `/docs`, `/openapi.json`, `/`) carries:

```http
Deprecation: true
Link: </api/v1/scans/abc>; rel="successor-version"
Sunset: Wed, 31 Dec 2026 23:59:59 GMT
```

The `Link` header points at the matching `/api/v1/` path so a smart
client can auto-migrate. The `Sunset` date is fixed: **Dec 31, 2026,
23:59:59 GMT**. That gives v0.5.0 callers roughly 18 months to migrate.

```admonish note
The `Sunset` date is *the upper bound for planning*, not a hard
EOL. The legacy paths will keep working past it; the date just
tells callers when SecureScan considers itself free to drop them.
We will revisit the date in a future release before any actual
removal.
```

## Why mount both

The handlers are **shared** between the two prefixes. `alias_router_at_v1`
walks the legacy router's routes and re-registers each on a fresh `/api/v1/`
router pointing at the same callable. So:

- A bug fix in `create_scan` affects `/api/scans` AND `/api/v1/scans`
  in the same release.
- The OpenAPI document lists each operation under both paths.
- There is no "version drift" possible — there is only one handler.

## Migrating from `/api/` to `/api/v1/`

Three patterns:

### 1. Hardcoded base URL

If your code does:

```python
BASE = "https://securescan.internal/api"
```

Change to:

```python
BASE = "https://securescan.internal/api/v1"
```

That's it. No request body changes; no auth changes.

### 2. Auto-follow `Link: rel="successor-version"`

A more robust client follows the deprecation hint:

```python
import requests

resp = requests.get("https://securescan.internal/api/scans",
                    headers={"X-API-Key": KEY})
if resp.headers.get("Deprecation") == "true":
    successor = resp.links.get("successor-version", {}).get("url")
    if successor:
        # Optional: log a warning, retry against the v1 path.
        ...
```

This is overkill for most callers, but useful in libraries that want
to be self-correcting.

### 3. The CLI / Action — already on v1

`securescan` (the CLI) and `Metbcy/securescan@v1` (the GitHub Action)
both already talk `/api/v1/`. No migration required if those are your
entry points.

## What does *not* change

- **Request bodies, headers, response shapes** — identical between
  the two prefixes.
- **Auth** — the same API keys / scopes apply on both.
- **Rate limits** — same per-key bucket regardless of which prefix.
- **Error responses** — same status codes, same `detail` shape.

## Detecting deprecation usage

Tail your structured request log for lines under `/api/...` that do
not start with `/api/v1/`:

```bash
journalctl -u securescan-backend --output=cat \
  | jq -c 'select(.path | startswith("/api/") and (startswith("/api/v1/") | not))'
```

A spike of legacy-prefix calls indicates an unmigrated caller. Fix
the caller, not the server.

## v1.x → v2.x policy

When a new major version of the API ships (v2.x), the v1 paths will
get the same deprecation treatment v0 got — `/api/v2/...` mounted
alongside `/api/v1/...`, with `Deprecation` / `Sunset` headers on
the v1 paths and a date at least 18 months out. Callers will get the
same migration window.

We do not ship breaking changes inside a major version — that is the
SemVer contract. New optional fields, new endpoints, new query
params: yes. Renamed fields, removed endpoints, changed shapes: only
in a major-version bump.

## Source

- `backend/securescan/api/versioning.py` — `alias_router_at_v1` and
  `DeprecationHeaderMiddleware`.
- The middleware is registered in
  [`backend/securescan/api/__init__.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/__init__.py).

## Next

- [API overview](./overview.md) — what's at `/api/v1`.
- [Endpoints](./endpoints.md) — the actual list.
- [Rate limits](./rate-limits.md) — applies regardless of prefix.
