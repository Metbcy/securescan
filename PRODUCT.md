# SecureScan — Product Brief

## What this is

SecureScan is a self-hosted security-scanning orchestrator that runs Semgrep, Bandit, Trivy, Checkov, Safety, Gitleaks, nmap, ZAP, and a baseline scanner against a project, normalizes the output, and surfaces it through a CLI, GitHub Action, and web dashboard. It ships as a Python package + container image with signed releases.

Single-binary install, single-tenant API key, structured JSON output. Runs as a sidecar to a real codebase.

## Who uses it

**Primary user — the AppSec / Platform engineer.** They own the security pipeline for a small-to-mid engineering org. They've used Snyk, GitHub Code Scanning, Trivy directly. They don't want a SaaS dashboard. They want a single tool that wraps the scanners they already trust, gives them a deterministic SARIF stream, and stays out of their way. They live in PRs and the CLI; the web UI is a place they go when they need to triage backlog or show somebody else.

**Secondary user — the on-call dev triaging a PR comment.** Got a SecureScan inline review comment on their PR. Clicks the link. Wants to: see the finding in context, decide if it's a true positive, suppress it or fix it, and move on. They've been in the dashboard for less than 60 seconds total in their career. The first scan-result page they ever see has to teach them the model.

**Tertiary user — the engineering lead at quarterly review.** Wants risk trends, scan cadence, what was suppressed. Won't dig past the overview page.

## Brand tone

Calm, precise, deterministic. The opposite of an enterprise security suite. Closer in spirit to a Linear, a Stripe Dashboard, or a `git` man page — a tool that respects your time and assumes you know what you're doing. Plain language. No fear-marketing. No "AI-powered." No "actionable insights."

When SecureScan finds a critical: the row goes coral, the count is in the page header, the user can act in two clicks. When SecureScan finds nothing: the empty state teaches what scanners *would have caught*, so the user trusts the silence.

## Anti-references

- **Snyk** — corporate blue, marketing-driven, opaque. We are not that.
- **Generic dark-blue-on-black observability dashboards** — Datadog, the typical AI-generated SaaS template. We are not that.
- **Glassmorphism / gradient-text / hero-metric-card SaaS template** — we explicitly reject.
- **Splunk-style information overload.** Density is good. Visual noise is not.

## Design references (reach for)

- **Linear** — density, opinionated, refined neutrals, command palette as a primary affordance.
- **Stripe Dashboard** — predictable grids, semantic color used sparingly, tables that respect the reader.
- **GitHub Code Scanning** — table-first listing of findings, severity icons inline, suppress/fix as the primary actions.
- **Vercel Dashboard** — black/white plus single accent, refined dark theme, no neon.

## Strategic principles

1. **Earned familiarity over invention.** Standard nav patterns. Familiar affordances. The user should feel like the tool was built by people who've been using Linear and Stripe for years, not like the tool was generated.
2. **Density is a feature.** Security analysts read lots of findings. Tables, not card grids. More rows per screen. Tighter type scale.
3. **The CLI is the source of truth.** The web UI mirrors the CLI's data model — same fingerprints, same severity, same suppression vocabulary. No web-only concepts.
4. **Determinism in the surface.** Same finding looks the same every render. Same sort order. Stable URLs by fingerprint. No surprises.
5. **The tool disappears into the task.** When the user is triaging, the chrome gets out of the way.

## Register

**Product.** SecureScan is a tool. Design serves the product. Defaults to Restrained color, familiar patterns, system-ish fonts, predictable grids. Earned-familiarity bar.

## Outbound webhooks (v0.9.0)

SecureScan can fan out scan-lifecycle events to HTTP receivers (your incident-response server, Slack, Discord, an internal queue). Subscriptions are managed under `/api/v1/webhooks` with the `admin` scope.

### Events

- `scan.complete` — emitted when a scan finishes successfully.
- `scan.failed` — emitted when the orchestrator fails a scan.
- `scanner.failed` — emitted when an individual scanner crashes.
- `webhook.test` — only emitted by `POST /webhooks/{id}/test`; useful for verifying receiver configuration without running a real scan.

### Delivery contract

Each webhook gets the literal bytes:

```
POST <your-url>
Content-Type: application/json
User-Agent: SecureScan-Webhook/0.9
X-SecureScan-Event: scan.complete
X-SecureScan-Webhook-Id: <subscription-id>
X-SecureScan-Signature: t=<unix-seconds>,v1=<hex-hmac-sha256>

{"event":"scan.complete","data":{...},"delivered_at":"2025-..."}
```

For `hooks.slack.com` and `discord.com/api/webhooks` URLs the body is reshaped to the receiver's expected format (Slack blocks, Discord embed). For everything else the generic `{event, data, delivered_at}` shape is used.

### Verifying signatures

The `v1` signature is `hmac_sha256(secret, f"{t}.{raw_body}".encode("utf-8"))`. **Sign the literal request body bytes, not parsed JSON** — the dispatcher uses `json.dumps(payload, separators=(",", ":"))` so the body is whitespace-free; any re-serialization breaks the signature. Reject requests where `t` is more than 5 minutes old to defeat replays.

Python receiver-side example:

```python
import hmac, hashlib

def verify(secret: str, header: str, raw_body: bytes) -> bool:
    parts = dict(p.split("=", 1) for p in header.split(","))
    expected = hmac.new(
        secret.encode(),
        f"{parts['t']}.".encode() + raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, parts["v1"])
```

### Durability and retry

Every outbound delivery is persisted to the SQLite `webhook_deliveries` table BEFORE the HTTP call. A backend restart resumes any in-flight retries on startup. Retry policy: full-jitter exponential backoff capped at 5 minutes between attempts, max delivery age 30 minutes. Past max age the delivery is marked `failed`.

Receivers must be idempotent — at-least-once delivery is the contract. Use the `(t, v1)` pair plus the event-specific `data` (e.g. `scan_id`) to dedupe.
