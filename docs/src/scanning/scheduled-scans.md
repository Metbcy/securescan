# Scheduled scans

SecureScan can run scans automatically on a **cron schedule**. Each schedule ties
a target path and set of scan types to a standard 5-field cron expression. The
background scheduler fires the scan at the configured time, records a run row,
and updates the schedule's `last_run` timestamp.

## Creating a schedule

### Via the UI

Navigate to **Settings > Schedules** and click **New schedule**. Fill in:

| Field | Description |
|---|---|
| **Name** | Human-readable label (e.g. "Nightly SAST") |
| **Target path** | Absolute path to the directory or file to scan |
| **Scan types** | One or more of `code`, `dependency`, `iac`, `baseline`, `dast`, `network` |
| **Cron expression** | Standard 5-field cron (`minute hour dom month dow`) |

Example cron expressions:

| Expression | Meaning |
|---|---|
| `0 2 * * *` | Every day at 02:00 |
| `0 */6 * * *` | Every 6 hours |
| `30 8 * * 1` | Every Monday at 08:30 |
| `0 0 1 * *` | First day of each month at midnight |

### Via the API

```http
POST /api/v1/schedules
Authorization: X-API-Key <your-admin-key>
Content-Type: application/json

{
  "name": "Nightly SAST",
  "target_path": "/home/ci/repo",
  "scan_types": ["code", "dependency"],
  "cron_expression": "0 2 * * *"
}
```

The response includes the full `Schedule` object. Schedules are enabled by default.

## Managing schedules

All endpoints require the `admin` API-key scope.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/schedules` | Create a schedule |
| `GET` | `/api/v1/schedules` | List all schedules |
| `GET` | `/api/v1/schedules/{id}` | Fetch one schedule |
| `PATCH` | `/api/v1/schedules/{id}` | Edit name, path, types, cron, or enabled flag |
| `DELETE` | `/api/v1/schedules/{id}` | Delete schedule and all run history |
| `GET` | `/api/v1/schedules/{id}/runs` | Last 50 run records (newest first) |

### Disabling a schedule without deleting it

```http
PATCH /api/v1/schedules/{id}
Content-Type: application/json

{"enabled": false}
```

The in-memory APScheduler job is removed immediately; setting `enabled: true`
re-registers it.

## Run history

Each time a schedule fires, a `schedule_run` row is created with:

- `triggered_at` - UTC timestamp when the cron fired
- `scan_id` - UUID of the resulting scan (link to `/scan/{scan_id}` in the UI)

View the last 50 runs from **Settings > Schedules > History** (row menu) or via
`GET /api/v1/schedules/{id}/runs`.

## Multi-worker safety

When `SECURESCAN_REDIS_URL` is set, the scheduler uses a short-lived Redis lock
(`SET NX EX 30`) so that two workers whose cron fires at the same second do not
double-fire the same schedule. The second worker detects the lock and skips
without creating a run row.

Without Redis the application runs in single-process mode and an in-process
lock is used automatically.

## Scheduling in the background

The scheduler starts automatically with the FastAPI application via the
`startup` lifespan event and shuts down cleanly on `shutdown`. No extra
configuration is required beyond setting `SECURESCAN_REDIS_URL` when running
multiple workers.
