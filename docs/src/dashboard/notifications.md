# Notifications

The dashboard's topbar **bell icon** (added in v0.9.0) shows an unread
badge and a popover of the most recent notifications. Clicking
through goes to `/notifications`, the full feed.

Notifications are a **durable** in-app record — the SSE stream
([Real-time scan progress](./realtime.md)) shows scans as they happen,
notifications stay around after the SSE has closed.

<!-- toc -->

## What gets a notification

Auto-created by the orchestrator on:

| Trigger event      | Condition                                  | Severity            |
| ------------------ | ------------------------------------------ | ------------------- |
| `scan.complete`    | only when `findings_count > 0`             | Critical / high / medium / low / info — derived from the highest-severity finding in the scan |
| `scan.failed`      | always                                     | high                |
| `scanner.failed`   | always                                     | medium              |

```admonish tip title="Why findings_count > 0 for scan.complete?"
Successful zero-finding scans don't spam the bell. If your CI runs
SecureScan on every push of a clean repo, you don't get 50
notifications a day saying "all clear." A failing scan still
notifies regardless — silent failure is the bug.
```

The filter logic lives in
[`backend/securescan/api/scans.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/scans.py)
under `_create_notification_for_event`.

## Bell icon

```text
  ┌──────────────────────────────────────┐
  │   ●3   Notifications                 │   <- bell with unread count badge
  └──────────────────────────────────────┘
        ↓ click
  ┌──────────────────────────────────────────────────────────┐
  │ Notifications                                  Mark all  │
  ├──────────────────────────────────────────────────────────┤
  │ ● critical  3 critical findings on /home/me/proj-a        │
  │             scan 0f1a93cb · 2 minutes ago                 │
  ├──────────────────────────────────────────────────────────┤
  │ ● high      Scan failed: nmap — connection timed out      │
  │             scan 0d2c... · 5 minutes ago                  │
  ├──────────────────────────────────────────────────────────┤
  │ ● medium    Scanner skipped: zap — install /usr/share/... │
  │             scan 0d2c... · 5 minutes ago                  │
  ├──────────────────────────────────────────────────────────┤
  │                  See all notifications →                  │
  └──────────────────────────────────────────────────────────┘
```

- Polled every 30s via `GET /api/v1/notifications/unread-count`.
- 360px popover, 10 most recent.
- Severity dot prefix per row.
- Click a row → marks read, navigates to the scan detail.

## Full feed (`/notifications`)

A page with the same rows, no truncation, plus filter chips:

- **All** — every notification.
- **Unread** — `read_at IS NULL`.
- **Read** — `read_at IS NOT NULL`.

Sorted newest-first. Shows the same severity / title / scan id /
timestamp. Bulk action: "Mark all as read".

## API

| Method   | Path                                         | Scope   | Notes                                                                              |
| -------- | -------------------------------------------- | :-----: | ---------------------------------------------------------------------------------- |
| `GET`    | `/api/v1/notifications`                      | `read`  | Newest first. Query: `unread_only=true`, `limit=50` (silently capped at 200).      |
| `GET`    | `/api/v1/notifications/unread-count`         | `read`  | Returns `{"count": N}`. Index-only query, cheap to poll.                           |
| `PATCH`  | `/api/v1/notifications/{id}/read`            | `write` | Returns the updated row. 404 if the id is unknown.                                 |
| `PATCH`  | `/api/v1/notifications/read-all`             | `write` | Returns `{"marked_read": N}`. Idempotent: a second call returns `{"marked_read": 0}`. |

Source:
[`backend/securescan/api/notifications.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/notifications.py).

## Notification shape

```json
{
  "id": "n-9d2f3a1b",
  "severity": "critical",
  "title": "3 critical findings on /home/me/proj-a",
  "body": "Scanners run: semgrep, bandit, trivy",
  "scan_id": "0f1a93cb-44c2-4c8e-9f92-0a7c5a2e1b51",
  "created_at": "2026-04-29T20:11:09.123456",
  "read_at": null
}
```

## Examples

### Poll for unread count

```bash
$ curl -s -H "X-API-Key: $K" \
    http://127.0.0.1:8000/api/v1/notifications/unread-count
{"count":3}
```

### List the latest 10 unread

```bash
$ curl -s -H "X-API-Key: $K" \
    "http://127.0.0.1:8000/api/v1/notifications?unread_only=true&limit=10" \
    | jq '.[].title'
"3 critical findings on /home/me/proj-a"
"Scan failed: nmap — connection timed out"
"Scanner skipped: zap — install /usr/share/zaproxy/zap.sh"
```

### Mark one read

```bash
$ curl -s -X PATCH \
    -H "X-API-Key: $K" \
    "http://127.0.0.1:8000/api/v1/notifications/n-9d2f3a1b/read" | jq .
{
  "id": "n-9d2f3a1b",
  "severity": "critical",
  "title": "3 critical findings on /home/me/proj-a",
  ...,
  "read_at": "2026-04-29T20:14:00.000000"
}
```

### Mark all read

```bash
$ curl -s -X PATCH -H "X-API-Key: $K" \
    http://127.0.0.1:8000/api/v1/notifications/read-all
{"marked_read":3}
```

A second call returns `{"marked_read": 0}` — idempotent.

## Retention

Read notifications older than **30 days** are pruned at backend
startup. Unread notifications are kept indefinitely. The pruning is
defensive — a long-running deployment that never restarts would
accumulate forever; the on-startup sweep is enough for the typical
operator-managed lifecycle.

If you need different retention, run periodic restarts or open an
issue to discuss a configurable knob.

## Multi-tenant note

v0.9.0 is **single-tenant**: every authenticated browser session sees
the same notifications. There is no per-user scoping. The schema and
endpoints are shaped so a `user_id` query param can be added later
without breaking existing callers, but the v0.9.0 contract is "one
queue per deployment."

If you have an internal-tooling stack with a single SecureScan
deployment serving a small team, single-tenant is the right shape. For
SaaS-style multi-tenancy, look at the v1.0 roadmap.

## How notifications relate to webhooks

| Trigger          | In-app bell | Webhook |
| ---------------- | :---------: | :-----: |
| `scan.complete`  | ✓ (when findings_count > 0)    | ✓      |
| `scan.failed`    | ✓                              | ✓      |
| `scanner.failed` | ✓                              | ✓      |
| `scan.start` / `scanner.start` / `scanner.complete` / `scanner.skipped` / `scan.cancelled` | — | — |

Both surfaces consume the same SSE event stream. Notifications are
"the operator's inbox"; webhooks are "external integrations." See
[Webhooks](./webhooks.md).

## Next

- [Webhooks](./webhooks.md) — external delivery of the same events.
- [Real-time scan progress](./realtime.md) — the live SSE stream.
- [Dashboard tour](./tour.md) — where the bell lives.
