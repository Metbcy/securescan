# Quick start: your first scan

This walks through running SecureScan against the
`~/Documents/securescan` repo itself — backend + frontend up, an
end-to-end scan, and reading the result on the dashboard.

It assumes you have:

- Python 3.12+
- Node.js 20+
- The repo cloned at `~/Documents/securescan`

<!-- toc -->

## 1. Bring up the backend

```bash
cd ~/Documents/securescan/backend
python3 -m venv venv && source venv/bin/activate
pip install -e .
pip install semgrep bandit safety pip-licenses checkov
securescan serve --host 127.0.0.1 --port 8000
```

You should see something like:

```text
INFO     SECURESCAN_API_KEY not set; API is unauthenticated (dev mode).
INFO     Started server process [12345]
INFO     Waiting for application startup.
INFO     Application startup complete.
INFO     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

Confirm liveness and readiness:

```bash
$ curl -s http://127.0.0.1:8000/health
{"status":"ok"}

$ curl -s http://127.0.0.1:8000/ready | jq .
{
  "status": "ready",
  "checks": {
    "database": "ok",
    "scanner_registry": "ok"
  }
}
```

```admonish note
Dev mode means **no authentication required**. The startup banner
warns you. For anything past `localhost`, set `SECURESCAN_API_KEY`
or create DB-backed keys — see [API keys](./auth/api-keys.md) and
[Production checklist](./deployment/production-checklist.md).
```

## 2. Bring up the frontend

In a second shell:

```bash
cd ~/Documents/securescan/frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The topbar API
status indicator should be green: the dashboard is talking to the
backend at `http://localhost:8000`.

## 3. Kick off a scan via the API

You can use the dashboard, but the API path is the easiest to show
in a guide. Request a `code` + `dependency` scan of the SecureScan
repo itself:

```bash
curl -s -X POST http://127.0.0.1:8000/api/v1/scans \
  -H 'Content-Type: application/json' \
  -d '{
    "target_path": "/home/you/Documents/securescan",
    "scan_types": ["code", "dependency"]
  }' | jq .
```

Response:

```json
{
  "id": "0f1a93cb-44c2-4c8e-9f92-0a7c5a2e1b51",
  "target_path": "/home/you/Documents/securescan",
  "scan_types": ["code", "dependency"],
  "status": "pending",
  "started_at": "2026-04-29T20:11:05.123456",
  "completed_at": null,
  "scanners_run": [],
  "scanners_skipped": []
}
```

The backend immediately starts running the requested scanners as a
background asyncio task. Save the `id` — call it `$SCAN_ID`.

## 4. Watch progress live

Open the dashboard at
`http://localhost:3000/scan/<SCAN_ID>`. Above the StatLine you will
see `<ScanProgressPanel>` with one row per scanner, each going
`queued → running → complete` as the orchestrator drives them. This is
the v0.7.0 SSE stream; on the wire it looks like:

```bash
curl -N "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/events"
```

```text
event: scan.start
data: {"scan_types":["code","dependency"]}

event: scanner.start
data: {"name":"semgrep"}

event: scanner.complete
data: {"name":"semgrep","duration_s":4.31,"findings_count":7}

event: scanner.start
data: {"name":"bandit"}
...
event: scan.complete
data: {"findings_count":12,"risk_score":34.2}
```

```admonish tip
In an authenticated deployment, browsers cannot send `X-API-Key` on an
EventSource. The dashboard exchanges the API key for a short-lived
signed event token via `POST /api/v1/scans/{id}/event-token`.
See [SSE event tokens](./auth/event-tokens.md).
```

## 5. Read the results

Once `status` flips to `completed`, the scan-detail page shows:

- A **PageHeader** with the target path, scan id, and total finding count.
- A **StatLine** with risk score, severity counts, scanners run, and
  total duration.
- A **scanner-chip strip** showing which scanners ran, which were
  skipped, and the install hint for skipped ones.
- A **findings table** with columns:
  | Column     | What it shows                                                                   |
  | ---------- | ------------------------------------------------------------------------------- |
  | Severity   | `critical` / `high` / `medium` / `low` / `info` with a colored dot prefix.      |
  | Title      | One-line finding summary from the scanner.                                      |
  | File:line  | Mono-spaced; click to expand the row for the matched line and AI explanation.   |
  | Rule       | Scanner-specific rule id (`B106`, `python.lang.security.audit.eval-detected`).  |
  | Scanner    | Origin scanner (`semgrep`, `bandit`, `trivy`, …).                               |
  | Compliance | Tag chips: `OWASP-A03`, `PCI-DSS-6.5.1`, `SOC2-CC7.1`, etc. ([Compliance](./scanning/compliance.md)) |
  | Status     | Triage verdict pill — `new` (default), `triaged`, `false_positive`, `accepted_risk`, `fixed`, `wont_fix`. ([Triage](./scanning/triage.md)) |

The same data is available over the API:

```bash
curl -s "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/findings" | jq '.[0]'
```

```json
{
  "id": "f-2c1...",
  "scanner": "semgrep",
  "scan_type": "code",
  "severity": "high",
  "title": "Use of eval()",
  "description": "...",
  "file_path": "backend/securescan/cli.py",
  "line": 142,
  "rule_id": "python.lang.security.audit.eval-detected",
  "fingerprint": "9d2f...",
  "compliance_tags": ["OWASP-A03"],
  "state": null,
  "metadata": { "suppressed_by": null }
}
```

`state` is `null` until you set a triage verdict — see
[Triage workflow](./scanning/triage.md).

## 6. Triage one finding

Suppose row 1 is a false positive in test code. Set the verdict:

```bash
FP=$(curl -s "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/findings" \
  | jq -r '.[0].fingerprint')

curl -s -X PATCH \
  "http://127.0.0.1:8000/api/v1/findings/$FP/state" \
  -H 'Content-Type: application/json' \
  -d '{"status":"false_positive","note":"intentional in test fixture","updated_by":"alice"}'
```

Response:

```json
{
  "fingerprint": "9d2f...",
  "status": "false_positive",
  "note": "intentional in test fixture",
  "updated_at": "2026-04-29T20:14:22.000000",
  "updated_by": "alice"
}
```

The default findings filter hides `false_positive` (along with
`accepted_risk` and `wont_fix`); the row disappears on next reload.
This verdict survives every later scan of the same target —
fingerprints are cross-scan stable.

## 7. Clean up

```bash
curl -X DELETE "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID"
# 204 — scan + findings rows cascade-deleted.
# Triage verdicts persist (keyed on fingerprint, not scan id).
```

## What you just touched

- The **scan engine** — see [How scans work](./scanning/how-scans-work.md).
- The **API** — see [API overview](./api/overview.md).
- The **SSE stream** — see [Real-time scan progress](./dashboard/realtime.md).
- The **triage workflow** — see [Triage](./scanning/triage.md).

## Where to next

- Run a CI scan: [GitHub Action](./cli/github-action.md).
- Deploy past `localhost`: [Production checklist](./deployment/production-checklist.md).
- Hook another tool to scan completion: [Webhooks](./dashboard/webhooks.md).
