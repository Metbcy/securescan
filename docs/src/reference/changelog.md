# Changelog

This is a mirror of the project's
[`CHANGELOG.md`](https://github.com/Metbcy/securescan/blob/main/CHANGELOG.md)
for the post-v0.5.0 entries that the rest of this site references.
For the canonical list back to v0.1.0, follow the link above.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- toc -->

## [0.10.0] - 2026-04-30

A non-feature minor release: full product documentation website,
Apache 2.0 relicensing, and a NOTICE file crediting the third-party
scanners SecureScan orchestrates.

### Added

- **Documentation website** at <https://metbcy.github.io/securescan/>.
  41 pages covering install, all features (v0.6.0 → v0.9.0), API
  reference, deployment, security, and CLI usage. Built with mdBook,
  auto-deployed on every push to `main` that touches `docs/**` via a
  new `.github/workflows/docs.yml` workflow.
- `LICENSE` file (Apache 2.0, full text) and `NOTICE` file crediting
  the third-party scanners which are invoked as subprocesses, not
  redistributed.

### Changed

- Project relicensed to **Apache 2.0**. Previously declared MIT in
  `README.md` and `backend/pyproject.toml` but no `LICENSE` file
  existed in the repo. Apache 2.0 fits a security-tooling project
  better — explicit patent grant, NOTICE convention.

### No code changes

This release ships zero changes to the API, database schema,
scanner behavior, or dashboard UX. v0.9.0 callers can upgrade safely.

## [0.9.0] - 2026-04-29

A workflow / observability release: dashboards now have a
**notification bell**, operators can issue **outbound webhooks** to
Slack, Discord, or any HTTP receiver with HMAC-signed deliveries and
a durable retry queue, and the v0.7.0 SSE live-progress stream now
works in **authenticated deployments** via short-lived signed event
tokens (the v0.8.0 deferral is closed).

### Added

- **SSE event tokens.** New `POST /api/v1/scans/{id}/event-token`
  (read scope) returns a 5-minute HMAC-signed token bound to
  `scan_id` + the caller's `key_id`. The SSE endpoint
  `GET /api/v1/scans/{id}/events` now accepts `?event_token=…` as
  an alternative to `X-API-Key` so EventSource can authenticate.
  Token verification rehydrates the principal at connect time so a
  revoked DB key invalidates outstanding tokens immediately. Frontend
  rotates tokens at half-life with a single re-mint on error before
  falling back to polling. Signing secret from
  `SECURESCAN_EVENT_TOKEN_SECRET`; required when
  `SECURESCAN_AUTH_REQUIRED=1`. → [SSE event tokens](../auth/event-tokens.md).
- **Outbound webhooks.** `POST /api/v1/webhooks` (admin) creates
  durable subscriptions to scan lifecycle events. Each delivery is
  persisted in `webhook_deliveries` BEFORE the HTTP call, so a
  backend restart resumes any pending retries. Retry policy: full-
  jitter exponential backoff capped at 5 minutes, max delivery age
  30 minutes. Payloads are HMAC-SHA256 signed via
  `X-SecureScan-Signature: t=<unix-ts>,v1=<hex-hmac>` over
  `f"{t}.{raw_body}"` (Stripe-style). FIFO ordering per webhook
  (different webhooks dispatch concurrently). Slack and Discord URLs
  auto-detected and reshaped; generic JSON otherwise. New
  `/settings/webhooks` page lists webhooks with a delivery log
  drawer that auto-refreshes every 5s. `POST /webhooks/{id}/test`
  fires a synthetic event through the exact dispatcher path so users
  can verify receivers end-to-end. → [Webhooks](../dashboard/webhooks.md).
- **In-app notifications.** New `notifications` table; bell icon in
  the topbar with unread count badge (poll every 30s); 360px popover
  showing 10 most recent with severity dots. Notifications are
  auto-created on `scan.complete` (only when `findings_count > 0` —
  successful zero-finding scans don't spam the bell), `scan.failed`,
  `scanner.failed`. New `/notifications` page lists everything with
  All / Unread / Read filter chips. Read notifications older than
  30 days are pruned at backend startup. → [Notifications](../dashboard/notifications.md).

### Changed

- `_log_scan_event` now triggers three side-effects per emission:
  the v0.6.1 logger line, the v0.7.0 ScanEventBus publish, and (new)
  two side-effect hooks for webhook enqueue + notification create.
  Hooks run via `asyncio.create_task` and swallow DB errors so a
  failed side-effect can't break a live scan.
- `require_api_key` now accepts `?event_token=` for the SSE route
  specifically. The path-match check makes a leaked token only
  usable on `/scans/{id}/events`; any other route falls through to
  strict `X-API-Key` validation.

### Bug fixed during integration

- Dev-mode SSE event tokens were being minted with `key_id="env"`,
  then verification rejected them because no env-var was actually
  configured. Tokens minted in dev mode now use a `"dev"` sentinel
  that's accepted only while the system remains in dev mode; if
  credentials are added later, dev-mode tokens are invalidated.
  Regression tests in `test_sse.py::test_dev_mode_token_round_trips`
  and `test_dev_mode_token_invalidated_when_auth_enabled`.

### Tests

- 790 → 863 (+73): 9 event-token unit + 12 SSE token integration
  (including 2 dev-mode regression), 31 webhooks, 21 notifications.

### Deployment notes

- The webhook dispatcher runs as an asyncio task on the same uvicorn
  worker as the API. Single-worker constraint from v0.7.0 still
  applies (multi-worker pubsub backplane is a future feature).
  → [Single-worker constraint](../deployment/single-worker.md).

## [0.8.0] - 2026-04-29

A production-readiness release: API authentication is no longer a
single shared env-var key. Operators can now issue, scope, and revoke
**hashed API keys** through the dashboard or the API, and the
existing endpoints are gated behind explicit read / write / admin
scopes. The legacy `SECURESCAN_API_KEY` env var still works as a
break-glass / dev-mode fallback.

### Added

- **DB-backed API keys with scopes.** New `api_keys` table stores
  salted-sha256 hashes — plaintext keys are returned exactly once at
  creation. Key format: `ssk_<10-char id>_<32-char secret>` (~250
  bits of entropy). Three scopes: `read`, `write`, `admin`. Default
  new-key scopes are `["read", "write"]`; `admin` must be explicitly
  granted. → [API keys](../auth/api-keys.md).
  - `POST /api/v1/keys` (admin) — `{name, scopes}` → 201
    `ApiKeyCreated` (the only response that includes the full secret)
  - `GET /api/v1/keys` (admin) → `ApiKeyView[]` (no secret)
  - `GET /api/v1/keys/me` (any authenticated DB key) → caller's own
    key info
  - `DELETE /api/v1/keys/{id}` (admin) → 204; 409 if revoking the
    target would leave the system with zero admin credentials and
    `SECURESCAN_AUTH_REQUIRED=1` is set (lockout protection)
- **Per-route scope enforcement.** Every `/api/*` route now declares
  a required scope via `Depends(require_scope(...))`. A new
  regression-guard test (`test_all_routes_have_explicit_scope`)
  enumerates `app.routes` and fails if any non-public route is
  missing a scope — preventing future scope-coverage holes.
  → [Scopes](../auth/scopes.md).
- **`SECURESCAN_AUTH_REQUIRED=1` startup safety.** When set with no
  configured credentials, the backend logs CRITICAL and exits with
  code 2. Catches misconfigured deploys before they accept their
  first request unauthenticated.
- **Lockout protection.** Revoking the last admin DB key when
  `AUTH_REQUIRED=1` and no env-var key is set returns 409 with a
  human-readable message. Operators can still delete admin keys
  freely when an env-var fallback exists.
- **`/settings/keys` dashboard page.** Lists keys (name, prefix,
  scopes, created, last used, status), with a "New key" modal that
  enforces the one-shot secret reveal contract.

### Changed

- `auth.py` was rewritten to support both the legacy env-var path
  and DB keys. **Bug fix:** an explicit-but-bogus key now always
  fails with 401 — even when no DB keys remain unrevoked. The
  previous logic would fall back to dev mode in that scenario,
  letting a revoked key keep working until at least one other key
  was created. Caught during integration; regression test in
  `test_revoked_db_key_rejected_when_no_env_var`.
- The `Principal` resolved by `require_api_key` is stashed on
  `request.state.principal`, so per-route scope checks don't
  re-trigger DB writes.

### Tests

- 738 → 790 (+52).

### Backward compatibility

- `SECURESCAN_API_KEY` env var still works exactly as before; treated
  as a synthetic principal with all scopes.
- Dev mode (no env, no DB keys) is unchanged: every request passes
  through and scope checks fail-open.

## [0.7.0] - 2026-04-29

A workflow + observability release: the dashboard now lets you
**triage individual findings** (status + comments) with verdicts that
survive across scans, and replaces 2-second polling with a **live
event stream** so a running scan shows real-time per-scanner progress
instead of a frozen "running" badge.

### Added

- **Findings triage workflow.** Each finding now has an optional
  triage state (`new`, `triaged`, `false_positive`,
  `accepted_risk`, `fixed`, `wont_fix`) and a per-finding comments
  thread. State is keyed on the stable `fingerprint` so a "false
  positive" verdict on a finding survives subsequent rescans of the
  same target — and even survives `DELETE /scans/{id}`. New API:
  - `PATCH /api/v1/findings/{fingerprint}/state`
  - `GET /api/v1/findings/{fingerprint}/comments`
  - `POST /api/v1/findings/{fingerprint}/comments`
  - `DELETE /api/v1/findings/{fingerprint}/comments/{comment_id}`
  → [Triage workflow](../scanning/triage.md).
- **Triage UI.** New compact "Status" column in the findings table.
  Default-hide set is `{false_positive, accepted_risk, wont_fix}`.
  `fixed` is intentionally NOT default-hidden so a "fixed" finding
  reappearing in a later scan stays visible.
- **Real-time scan progress (SSE).**
  `GET /api/v1/scans/{scan_id}/events` streams scan + per-scanner
  lifecycle events. Late subscribers get a 200-event replay buffer.
  Terminal events are never dropped on subscriber backpressure.
  → [Real-time scan progress](../dashboard/realtime.md).
- **Scan-detail page goes live.** New `<ScanProgressPanel>` above
  the StatLine while a scan is `running`/`pending`. `EventSource`
  replaces the 2-second poll, with a polling fallback when an API
  key is configured (the v0.9.0 SSE-with-auth path closes that gap).

### Changed

- `GET /api/v1/scans/{id}/findings` now returns
  `FindingWithState` objects — every existing field, plus an
  optional `state` payload. The bare `Finding` model is unchanged,
  so SARIF / JSON / baseline / CLI exporters keep their existing
  contract.

### Deployment notes

- The SSE event bus is a module-level singleton. SecureScan now
  requires `--workers 1` for `/api/v1/scans/{id}/events` to work
  correctly. → [Single-worker constraint](../deployment/single-worker.md).

### Tests

- 709 → 738 (+29).

## [0.6.1] - 2026-04-29

A polish release focused on production readiness on real (large)
scans. The 20k-finding scan that shipped during v0.6.0 testing
exposed three issues — a stale-running UI badge, a janky search box,
and a missing delete-scan endpoint — all fixed here. We also added
structured scan lifecycle logs, a user-scoped `.env` loader so
credentials persist across restarts, and a smarter ZAP install hint.

### Added

- `DELETE /api/v1/scans/{id}` removes a scan and cascades its
  findings. Returns 204 on success, 409 if the scan is
  `running`/`pending` (cancel first), 404 otherwise.
- Structured INFO logging for the scan lifecycle on the
  `securescan.scan` logger: `scan.start`, `scanner.start`,
  `scanner.complete` (with `duration_s` and `findings_count`),
  `scanner.skipped`, `scanner.failed`, `scan.complete`, `scan.failed`,
  `scan.cancelled`. Tail `/tmp/securescan-backend.log` to debug a
  scan in flight.
- `~/.config/securescan/.env` (or `$XDG_CONFIG_HOME/securescan/.env`)
  is auto-loaded at backend startup. → [Local config (.env)](../deployment/local-config.md).

### Changed

- `frontend/src/app/scan/[id]/page.tsx` polling no longer refetches
  the entire findings array every 2 seconds. While a scan is
  running, only the lightweight scan-status record is polled;
  findings and summary load once on mount and once when status
  flips to `completed`.
- `FindingsTable` is responsive again on 20k-finding scans. Search
  input uses React 19's `useDeferredValue`; a single memoized
  projection replaces per-keystroke string normalization.

### Tests

- 690 → 709 (+19).

## [0.6.0] - 2026-04-29

This release pairs an end-to-end frontend redesign with two backend
durability features. The dashboard moves off neon traffic-light
colors and ad-hoc card grids onto an OKLCH design system with a
single-hue severity ramp, dense data-table layouts, a new app shell
(sidebar + sticky topbar + ⌘K command palette), and a brand-new
`/diff` page for PR-style scan comparison. On the API side, all
routes are now mounted under `/api/v1/...` (legacy `/api/...` paths
still work, with `Deprecation` / `Sunset` response headers), and
`POST /scans` is protected by an in-memory per-key token-bucket rate
limiter.

### Added

- `/api/v1` versioning prefix; legacy `/api/*` paths return
  `Deprecation`, `Link`, and `Sunset` (Dec 31 2026) response headers.
  → [Versioning & deprecation](../api/versioning.md).
- In-memory rate limiting on `POST /api/scans` and
  `POST /api/v1/scans`; per-API-key token-bucket, configurable via
  `SECURESCAN_RATE_LIMIT_PER_MIN` / `_BURST` / `_ENABLED`.
  → [Rate limits](../api/rate-limits.md).
- New `/diff` dashboard page — PR-style scan-vs-scan diff with
  base/head pickers, summary chips, and tabbed findings.
  → [Diff & compare](../dashboard/diff.md).
- Command palette (⌘K) for navigation, recent scans, and quick
  actions.
- Theme toggle and `next-themes` integration; dark default with
  light theme support.

### Changed

- Frontend redesigned end-to-end. New OKLCH design tokens, single-hue
  severity ramp (replaces neon traffic-light coloring), Geist
  Sans/Mono typography, restrained color strategy per the new
  [`DESIGN.md`](https://github.com/Metbcy/securescan/blob/main/DESIGN.md).
  → [Dashboard tour](../dashboard/tour.md).

## Earlier releases

For v0.5.0, v0.4.0, v0.3.0, v0.2.0, and v0.1.0, see
[`CHANGELOG.md`](https://github.com/Metbcy/securescan/blob/main/CHANGELOG.md)
on GitHub. Highlights:

- **0.5.0** — API key auth, structured JSON logging, request-ID
  correlation, `/ready` distinct from `/health`, `Scan.scanners_run`
  / `scanners_skipped` persisted.
- **0.4.0** — `pr-mode: inline` GitHub Action mode with one inline
  comment per finding, `\`\`\`suggestion` blocks, idempotent re-runs
  via fingerprint markers.
- **0.3.0** — `.securescan.yml` config, inline `# securescan: ignore`
  comments, baselines, `securescan compare`, `severity_overrides`,
  `--show-suppressed` / `--no-suppress`, `--ai` / `--no-ai`.
- **0.2.0** — `securescan diff`, deterministic SARIF output, GitHub
  Action, container image, signed releases (cosign + sigstore-python),
  per-finding fingerprints.
- **0.1.0** — Initial public release. 14 scanners, FastAPI backend,
  Next.js dashboard, SBOM (CycloneDX + SPDX), AI enrichment, OWASP /
  CIS / PCI-DSS / SOC 2 compliance mapping.

[Unreleased]: https://github.com/Metbcy/securescan/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/Metbcy/securescan/releases/tag/v0.9.0
[0.8.0]: https://github.com/Metbcy/securescan/releases/tag/v0.8.0
[0.7.0]: https://github.com/Metbcy/securescan/releases/tag/v0.7.0
[0.6.1]: https://github.com/Metbcy/securescan/releases/tag/v0.6.1
[0.6.0]: https://github.com/Metbcy/securescan/releases/tag/v0.6.0
