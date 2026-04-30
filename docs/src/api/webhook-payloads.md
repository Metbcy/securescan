# Webhook payloads

Full schemas for every event SecureScan delivers to outbound webhooks.
The headers, signature contract, and retry policy are documented in
[Webhooks](../dashboard/webhooks.md); this page is the **payload**
reference.

<!-- toc -->

## Envelope

Every event is wrapped in a stable envelope:

```json
{
  "event": "<event-type>",
  "data": { /* per-event payload */ },
  "delivered_at": "2026-04-29T20:11:09.123456Z"
}
```

The literal bytes on the wire come from
`json.dumps(payload, separators=(",", ":"))` — whitespace-free,
key-order preserved. **Sign these literal bytes**, not a re-parsed
JSON object. See [Webhooks → signature verification](../dashboard/webhooks.md#signature-verification).

For Slack and Discord URLs, the envelope is replaced with the
provider-specific shape — see [Slack shape](#slack-shape) and
[Discord shape](#discord-shape).

## Headers

Every delivery, every event, same set:

```http
POST <your-url>
Content-Type: application/json
User-Agent: SecureScan-Webhook/0.9
X-SecureScan-Event: <event-type>
X-SecureScan-Webhook-Id: <subscription-id>
X-SecureScan-Signature: t=<unix-ts>,v1=<hex-hmac-sha256>
```

## `scan.complete`

Fires when a scan completes successfully (`status` flipped to
`completed`).

```json
{
  "event": "scan.complete",
  "data": {
    "scan_id": "0f1a93cb-44c2-4c8e-9f92-0a7c5a2e1b51",
    "target_path": "/home/me/proj-a",
    "scan_types": ["code", "dependency"],
    "scanners_run": ["semgrep", "bandit", "trivy", "safety"],
    "scanners_skipped": [
      {"name": "checkov", "reason": "binary not on PATH", "install_hint": "pip install checkov"}
    ],
    "findings_count": 12,
    "severity_counts": {
      "critical": 1,
      "high": 3,
      "medium": 5,
      "low": 2,
      "info": 1
    },
    "risk_score": 34.2,
    "duration_s": 81.3,
    "started_at": "2026-04-29T20:09:48.123456Z",
    "completed_at": "2026-04-29T20:11:09.456789Z"
  },
  "delivered_at": "2026-04-29T20:11:10.001234Z"
}
```

## `scan.failed`

Fires when the orchestrator fails the scan before reaching `completed`
(database write failure, target validation, internal error).

```json
{
  "event": "scan.failed",
  "data": {
    "scan_id": "0d2c3a8f-4f1c-86e9-2b4b4ab0a8e0",
    "target_path": "/home/me/missing",
    "scan_types": ["code"],
    "error": "ValueError: target_path does not exist",
    "scanners_run": [],
    "scanners_skipped": [],
    "started_at": "2026-04-29T20:00:00.000000Z",
    "completed_at": "2026-04-29T20:00:00.250000Z"
  },
  "delivered_at": "2026-04-29T20:00:00.500000Z"
}
```

The `error` field is a single-line description, truncated for safety
(stack traces are kept in the backend log, not pushed to webhooks).

## `scanner.failed`

Fires when an individual scanner crashed mid-scan. The scan itself
may still complete successfully via the other scanners; the failed
scanner's failure is recorded on the scan row.

```json
{
  "event": "scanner.failed",
  "data": {
    "scan_id": "0f1a93cb-44c2-4c8e-9f92-0a7c5a2e1b51",
    "scanner": "nmap",
    "scan_type": "network",
    "error": "subprocess timed out after 600s",
    "duration_s": 600.0
  },
  "delivered_at": "2026-04-29T20:10:00.123456Z"
}
```

`error` is truncated to 200 chars (the constant `_SCAN_ERROR_TRUNCATE`
in `backend/securescan/api/scans.py`) so a multi-MB stack trace
doesn't blow up your receiver.

## `webhook.test`

Fires only when an operator clicks "Test" in the dashboard or calls
`POST /api/v1/webhooks/{id}/test`. The synthetic event flows through
the **identical** dispatcher path as a real one — same retry, same
signature contract — so a green test proves end-to-end wiring.

```json
{
  "event": "webhook.test",
  "data": {
    "message": "Test from SecureScan",
    "timestamp": "2026-04-29T20:00:00.000000Z"
  },
  "delivered_at": "2026-04-29T20:00:00.000000Z"
}
```

## What is *not* in the payload

Deliberately small so the public webhook contract stays stable and
small:

- **Findings.** The full finding list is not delivered — it can be
  thousands of rows. To get findings, hit
  `GET /api/v1/scans/{id}/findings` with the `scan_id` from the
  webhook payload.
- **Per-scanner lifecycle events.** `scanner.start`,
  `scanner.complete`, `scanner.skipped`, `scan.start`,
  `scan.cancelled` are NOT delivered to webhooks. They stay on the
  internal SSE event bus only — too noisy for outbound delivery,
  and the public webhook contract should be small and stable. The
  allowlist is `WEBHOOK_RELEVANT_EVENTS` in
  [`backend/securescan/api/scans.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/scans.py).
- **Triage state.** Webhooks fire on scan/scanner lifecycle. Triage
  state changes are dashboard actions, not lifecycle events.
- **API key / webhook secret values.** Never delivered. Plaintext
  credentials are returned exactly once on creation and never travel
  through any other surface.

## Slack shape

For URLs matching `https://hooks.slack.com/services/...`, the body is
reshaped to Slack's expected format. The reshaper is
[`backend/securescan/webhook_formatters.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/webhook_formatters.py).

For `scan.complete`:

```json
{
  "blocks": [
    {
      "type": "header",
      "text": {"type": "plain_text", "text": ":shield: Scan complete: /home/me/proj-a"}
    },
    {
      "type": "section",
      "fields": [
        {"type": "mrkdwn", "text": "*Findings:*\n12 (●1 critical, ●3 high)"},
        {"type": "mrkdwn", "text": "*Risk score:*\n34.2"},
        {"type": "mrkdwn", "text": "*Duration:*\n1m 21s"},
        {"type": "mrkdwn", "text": "*Scanners:*\nsemgrep, bandit, trivy, safety"}
      ]
    },
    {
      "type": "context",
      "elements": [{"type": "mrkdwn", "text": "Scan ID `0f1a93cb-...`"}]
    }
  ]
}
```

For `scan.failed`:

```json
{
  "blocks": [
    {
      "type": "header",
      "text": {"type": "plain_text", "text": ":warning: Scan failed: /home/me/missing"}
    },
    {
      "type": "section",
      "text": {"type": "mrkdwn", "text": "*Error:* `ValueError: target_path does not exist`"}
    }
  ]
}
```

`scanner.failed` and `webhook.test` get analogous Slack-shape blocks.

## Discord shape

For URLs matching `https://discord.com/api/webhooks/...`:

```json
{
  "embeds": [
    {
      "title": "Scan complete: /home/me/proj-a",
      "color": 7654321,
      "fields": [
        {"name": "Findings", "value": "12 (●1 critical, ●3 high)", "inline": true},
        {"name": "Risk score", "value": "34.2", "inline": true},
        {"name": "Duration", "value": "1m 21s", "inline": true}
      ],
      "footer": {"text": "Scan 0f1a93cb-..."},
      "timestamp": "2026-04-29T20:11:09.456789Z"
    }
  ]
}
```

Embed color is set per severity:

| Severity bucket | Color decimal |
| --------------- | ------------- |
| critical        | red-ish       |
| high            | orange-ish    |
| medium          | yellow-ish    |
| low / info      | blue-ish      |

```admonish important title="Slack and Discord don't verify HMAC"
Both Slack and Discord webhook URLs are *unauthenticated* — anyone
with the URL can post. The HMAC headers are still sent (so you could
route through a proxy and verify there), but the receivers don't.
Treat the URL itself as the secret. Don't share it; rotate it
(create a new one at the provider, update SecureScan's
subscription) if it leaks.
```

## Versioning of the payload schema

The shapes above are stable for v0.9.x. New optional fields may be
added in minor releases. Receivers should:

- Treat unknown top-level fields as additive (don't crash on new
  keys).
- Pin to `User-Agent: SecureScan-Webhook/0.9` if you want to
  detect a major-version transition.
- Use `event` (not URL pattern) to dispatch.

When the major version of the payload changes, the `User-Agent`
will increment and the prior shape will continue working for at
least one minor cycle alongside the new one.

## Source

- Payload construction: `_log_scan_event` and helpers in
  [`backend/securescan/api/scans.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/scans.py).
- Slack/Discord shaper:
  [`backend/securescan/webhook_formatters.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/webhook_formatters.py).
- Dispatch + signing:
  [`backend/securescan/webhook_dispatcher.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/webhook_dispatcher.py).

## Next

- [Webhooks](../dashboard/webhooks.md) — verification, retry, FIFO ordering.
- [API endpoints](./endpoints.md) — full route list including the webhook CRUD.
- [Real-time scan progress](../dashboard/realtime.md) — internal SSE events not delivered to webhooks.
