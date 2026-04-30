# API overview

SecureScan exposes a single REST API. Every route is mounted at both
`/api/...` (legacy) and `/api/v1/...` (current); the legacy paths
return `Deprecation` / `Sunset` response headers. See
[Versioning & deprecation](./versioning.md).

This page is the entry point. For the **interactive** schema with
every parameter, look at the running server's `/docs` (FastAPI
Swagger UI) or `/redoc`.

<!-- toc -->

## Where each endpoint group lives

| Group         | Prefix                         | Source                                                                                                       |
| ------------- | ------------------------------ | ------------------------------------------------------------------------------------------------------------ |
| Scans         | `/api/v1/scans`                | [`backend/securescan/api/scans.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/scans.py)                 |
| Findings      | `/api/v1/scans/{id}/findings`  | (same file as Scans)                                                                                         |
| Triage        | `/api/v1/findings`             | [`backend/securescan/api/triage.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/triage.py)               |
| Keys          | `/api/v1/keys`                 | [`backend/securescan/api/keys.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/keys.py)                   |
| Webhooks      | `/api/v1/webhooks`             | [`backend/securescan/api/webhooks.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/webhooks.py)           |
| Notifications | `/api/v1/notifications`        | [`backend/securescan/api/notifications.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/notifications.py) |
| SBOM          | `/api/v1/scans/{id}/sbom`      | [`backend/securescan/api/sbom.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/sbom.py)                   |
| Compliance    | `/api/v1/compliance`           | [`backend/securescan/api/compliance.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/compliance.py)       |
| Dashboard     | `/api/v1/dashboard`            | [`backend/securescan/api/dashboard.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/dashboard.py)         |
| Health probes | `/health`, `/ready`            | [`backend/securescan/api/__init__.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/__init__.py)           |

## Auth

Every authenticated route accepts `X-API-Key: <key>` or
`Authorization: Bearer <key>`. Per-route scope (`read` / `write` /
`admin`) is declared via `Depends(require_scope(...))`. See
[Authentication overview](../auth/overview.md) and
[Scopes](../auth/scopes.md).

The SSE route additionally accepts `?event_token=...` because
browsers cannot send custom headers on `EventSource` — see
[SSE event tokens](../auth/event-tokens.md).

## Common request / response patterns

### Request ID correlation

Every request carries a request id end-to-end. If you don't pin one,
the server generates a UUID and echoes it back via the same header:

```bash
$ curl -i -H "X-Request-ID: my-trace-12345" \
    -H "X-API-Key: $K" \
    http://127.0.0.1:8000/api/v1/scans
HTTP/1.1 200 OK
X-Request-ID: my-trace-12345
...
```

In server logs, the same id appears on the `securescan.request`
structured log line:

```json
{"timestamp": "...", "logger": "securescan.request", "request_id": "my-trace-12345",
 "method": "GET", "path": "/api/v1/scans", "status": 200, "latency_ms": 4.13}
```

### Rate limit headers

`POST /api/v1/scans` is rate-limited per API key (or per IP in dev
mode). Successful responses include:

```http
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 47
X-RateLimit-Reset: 1730230885
```

Exceeded responses are 429 with `Retry-After` and a structured body.
See [Rate limits](./rate-limits.md).

### Error shape

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{"detail": "Scan not found"}
```

`detail` is a single string for most errors; on 422 (Pydantic
validation failure), it is a structured list:

```json
{
  "detail": [
    {"type": "value_error", "loc": ["body", "url"], "msg": "URL must be http(s)", "input": "..."}
  ]
}
```

## The most-used endpoints

These are documented in detail; the rest live in `/docs`.

### Start a scan

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scans \
  -H "X-API-Key: $K" \
  -H 'Content-Type: application/json' \
  -d '{
    "target_path": "/abs/path",
    "scan_types": ["code", "dependency"]
  }'
```

→ 200 with a `Scan` row (status starts as `pending`). Background
asyncio task starts immediately; subscribe to events to watch.
Requires `write` scope.

### Stream live progress

```bash
curl -N "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/events"
```

→ SSE stream of `scan.start`, `scanner.start`, `scanner.complete`,
etc. Terminal events close the stream. Requires `read` scope (or a
valid `?event_token=`).

See [Real-time scan progress](../dashboard/realtime.md) and
[SSE event tokens](../auth/event-tokens.md).

### Read findings

```bash
curl "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/findings" \
  -H "X-API-Key: $K"
```

→ Array of `FindingWithState`. Filter via query: `?severity=high`,
`?scan_type=code`, `?compliance=OWASP-A03`. Multiple filters are
AND-combined. Requires `read` scope.

### Set a triage verdict

```bash
curl -X PATCH "http://127.0.0.1:8000/api/v1/findings/$FP/state" \
  -H "X-API-Key: $K" \
  -H 'Content-Type: application/json' \
  -d '{"status": "false_positive", "note": "..."}'
```

→ The persisted state row. Requires `write` scope. See
[Triage workflow](../scanning/triage.md).

### Compare two scans

```bash
curl "http://127.0.0.1:8000/api/v1/scans/compare?scan_a=$BASE&scan_b=$HEAD" \
  -H "X-API-Key: $K"
```

→ `{new, fixed, unchanged}` arrays of findings. Requires `read`
scope.

### Issue an API key

```bash
curl -X POST http://127.0.0.1:8000/api/v1/keys \
  -H "X-API-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"name": "ci-runner", "scopes": ["read", "write"]}'
```

→ 201 with `ApiKeyCreated`, including the plaintext `key` field
**once**. Requires `admin` scope. See [API keys](../auth/api-keys.md).

### Create a webhook subscription

```bash
curl -X POST http://127.0.0.1:8000/api/v1/webhooks \
  -H "X-API-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "ops-pager",
    "url": "https://hooks.example.com/...",
    "event_filter": ["scan.complete", "scan.failed"]
  }'
```

→ 201 with `WebhookCreated`, including the plaintext `secret` field
**once**. Requires `admin` scope. See [Webhooks](../dashboard/webhooks.md)
and [Webhook payloads](./webhook-payloads.md).

## OpenAPI / Swagger

The full machine-readable schema is at:

| Path                | What it is                                                        |
| ------------------- | ----------------------------------------------------------------- |
| `/openapi.json`     | The OpenAPI 3.1 document. Feed it to your client generator.       |
| `/docs`             | FastAPI Swagger UI — try-it-now interactive tool.                 |
| `/redoc`            | FastAPI ReDoc — read-only schema documentation.                   |

Each operation has its own `description` (the handler docstring) and
declared response models. For the **complete** parameter list per
endpoint, the `/docs` UI is the source of truth.

## Versioning & stability

```admonish note title="What's stable"
- Route paths under `/api/v1/...`, the response shapes documented in
  this site, and the `Finding` / `Scan` / `ApiKey` Pydantic models
  are stable. Additions (new fields, new optional query params,
  new endpoints) happen in minor releases without breaking existing
  callers.

- Internal-only routes — anything not listed in [Endpoints](./endpoints.md)
  or [Scopes](../auth/scopes.md) — may change without notice.

- `/api/...` (legacy unprefixed) is **deprecated**. Migrate to
  `/api/v1/...` by Dec 31, 2026. See
  [Versioning & deprecation](./versioning.md).
```

## Next

- [Versioning & deprecation](./versioning.md) — the legacy / v1 split.
- [Rate limits](./rate-limits.md) — `POST /scans` rate limiting.
- [Endpoints](./endpoints.md) — complete list with grouping.
- [Webhook payloads](./webhook-payloads.md) — full schema for outbound events.
