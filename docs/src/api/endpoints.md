# Endpoints

A condensed listing of every public endpoint, its scope requirement,
and where it's documented. For the full request/response schema of
each, look at the running server's auto-generated **`/docs`** (FastAPI
Swagger UI) or **`/redoc`**.

This page is the **navigation**, not the complete reference.

<!-- toc -->

## Public

No auth required.

| Method | Path             | Purpose                                                    |
| ------ | ---------------- | ---------------------------------------------------------- |
| GET    | `/`              | API root info: `{name, status, docs, health}`              |
| GET    | `/health`        | Liveness — process up. Always 200 unless crashing.         |
| GET    | `/ready`         | Readiness — DB openable + scanner registry loaded.         |
| GET    | `/docs`          | Swagger UI                                                 |
| GET    | `/redoc`         | ReDoc                                                      |
| GET    | `/openapi.json`  | OpenAPI 3.1 document                                       |

## Scans

Prefix: `/api/v1/scans` (and `/api/scans` legacy).
Source: [`backend/securescan/api/scans.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/scans.py).

| Method | Path                          | Scope    | Purpose                                                                                |
| ------ | ----------------------------- | -------- | -------------------------------------------------------------------------------------- |
| POST   | `/`                           | `write`  | Start a scan. Rate-limited. See [How scans work](../scanning/how-scans-work.md).       |
| GET    | `/`                           | `read`   | List scans.                                                                            |
| GET    | `/{id}`                       | `read`   | Scan details.                                                                          |
| DELETE | `/{id}`                       | `write`  | Delete scan + cascade findings. 409 if running/pending.                                |
| POST   | `/{id}/cancel`                | `write`  | Cancel a running scan. 409 if already terminal.                                        |
| GET    | `/compare`                    | `read`   | `?scan_a=&scan_b=` → `{new, fixed, unchanged}`. See [Diff & compare](../dashboard/diff.md). |
| GET    | `/{id}/findings`              | `read`   | Findings + triage state. Filter `?severity=`, `?scan_type=`, `?compliance=`.           |
| GET    | `/{id}/summary`               | `read`   | Severity counts, risk score, scanners run / skipped, timing.                           |
| GET    | `/{id}/sbom`                  | `read`   | `?format=cyclonedx\|spdx`. See [SBOM](../dashboard/sbom.md).                           |
| GET    | `/{id}/report`                | `read`   | HTML / PDF report.                                                                     |
| GET    | `/{id}/events`                | `read`*  | SSE stream. Accepts `?event_token=`. See [Real-time scan progress](../dashboard/realtime.md). |
| POST   | `/{id}/event-token`           | `read`   | Mint short-lived SSE token. See [SSE event tokens](../auth/event-tokens.md).           |

`*` SSE route also accepts `?event_token=` from browsers; see
[Authentication overview](../auth/overview.md).

## Triage

Prefix: `/api/v1/findings`.
Source: [`backend/securescan/api/triage.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/triage.py).

| Method | Path                                       | Scope    | Purpose                                  |
| ------ | ------------------------------------------ | -------- | ---------------------------------------- |
| PATCH  | `/{fingerprint}/state`                     | `write`  | Set / replace triage verdict + note.     |
| GET    | `/{fingerprint}/comments`                  | `read`   | List comments, oldest first.             |
| POST   | `/{fingerprint}/comments`                  | `write`  | Add a comment.                           |
| DELETE | `/{fingerprint}/comments/{comment_id}`     | `write`  | Delete one comment by id.                |

See [Triage workflow](../scanning/triage.md).

## API keys

Prefix: `/api/v1/keys`.
Source: [`backend/securescan/api/keys.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/keys.py).

| Method | Path           | Scope    | Purpose                                                                          |
| ------ | -------------- | -------- | -------------------------------------------------------------------------------- |
| POST   | `/`            | `admin`  | Issue a key. **Returns plaintext secret once.**                                  |
| GET    | `/`            | `admin`  | List keys (no secret).                                                           |
| GET    | `/me`          | any DB key | Calling key's introspection.                                                  |
| DELETE | `/{id}`        | `admin`  | Revoke. Lockout-protected (409 if would zero admin credentials).                 |

See [API keys](../auth/api-keys.md).

## Webhooks

Prefix: `/api/v1/webhooks`.
Source: [`backend/securescan/api/webhooks.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/webhooks.py).

| Method | Path                          | Scope    | Purpose                                                                |
| ------ | ----------------------------- | -------- | ---------------------------------------------------------------------- |
| POST   | `/`                           | `admin`  | Create. **Returns secret once.**                                       |
| GET    | `/`                           | `admin`  | List.                                                                  |
| GET    | `/{id}`                       | `admin`  | Fetch one.                                                             |
| PATCH  | `/{id}`                       | `admin`  | Edit name / url / event_filter / enabled. **Cannot rotate secret.**    |
| DELETE | `/{id}`                       | `admin`  | Cascades deliveries.                                                   |
| GET    | `/{id}/deliveries`            | `admin`  | Last 100 delivery rows, newest first.                                  |
| POST   | `/{id}/test`                  | `admin`  | Enqueue a synthetic `webhook.test`. Returns 202 + delivery_id.         |

See [Webhooks](../dashboard/webhooks.md) and
[Webhook payloads](./webhook-payloads.md).

## Notifications

Prefix: `/api/v1/notifications`.
Source: [`backend/securescan/api/notifications.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/notifications.py).

| Method | Path                  | Scope    | Purpose                                                          |
| ------ | --------------------- | -------- | ---------------------------------------------------------------- |
| GET    | `/`                   | `read`   | List. `?unread_only=`, `?limit=` (capped at 200).                |
| GET    | `/unread-count`       | `read`   | `{count}` for the bell badge. Index-only query.                  |
| PATCH  | `/{id}/read`          | `write`  | Mark one read.                                                   |
| PATCH  | `/read-all`           | `write`  | Bulk mark read. Returns `{marked_read: N}`.                      |

See [Notifications](../dashboard/notifications.md).

## Dashboard

Prefix: `/api/v1/dashboard`.
Source: [`backend/securescan/api/dashboard.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/dashboard.py).

| Method | Path                       | Scope    | Purpose                                                  |
| ------ | -------------------------- | -------- | -------------------------------------------------------- |
| GET    | `/status`                  | `read`   | Per-scanner availability + version.                      |
| GET    | `/stats`                   | `read`   | Aggregate counts.                                        |
| GET    | `/trends`                  | `read`   | Risk / finding trends over time.                         |
| GET    | `/browse`                  | `read`   | Filesystem directory picker data (for the New Scan UI).  |
| POST   | `/install/{scanner}`       | `write`  | Install a supported scanner via the system package manager. |

## Compliance

Prefix: `/api/v1/compliance`.
Source: [`backend/securescan/api/compliance.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/compliance.py).

| Method | Path           | Scope    | Purpose                                                  |
| ------ | -------------- | -------- | -------------------------------------------------------- |
| GET    | `/coverage`    | `read`   | Per-framework coverage with `?scan_id=`.                 |

See [Compliance](../scanning/compliance.md).

## Quick examples

### Get all critical findings on a scan

```bash
curl -s -H "X-API-Key: $K" \
  "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/findings?severity=critical" | jq .
```

### List webhook delivery history

```bash
curl -s -H "X-API-Key: $ADMIN_KEY" \
  "http://127.0.0.1:8000/api/v1/webhooks/$WID/deliveries" | jq '.[].status'
```

### Mark every notification read

```bash
curl -s -X PATCH -H "X-API-Key: $K" \
  "http://127.0.0.1:8000/api/v1/notifications/read-all"
```

### Pin a request id (for log correlation)

```bash
curl -s -H "X-API-Key: $K" \
  -H "X-Request-ID: my-debug-trace-2026-04-29" \
  "http://127.0.0.1:8000/api/v1/dashboard/stats"
```

## Where to look for the parameters

For the full set of query parameters, request body fields, and
response schemas — including the ones we don't repeat on this site
because they're auto-derived from Pydantic models — open
**`http://<your-backend>/docs`** in a browser. The "Try it out"
panel of Swagger UI lets you exercise any endpoint with your API
key plugged in.

## Next

- [API overview](./overview.md) — auth and request/response patterns.
- [Versioning & deprecation](./versioning.md) — `/api/` vs `/api/v1/`.
- [Webhook payloads](./webhook-payloads.md) — outbound event schemas.
