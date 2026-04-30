# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- New features land here on each PR. -->

## [0.10.2] - 2026-04-30

UX polish on the scan-detail page while a scan is running.

### Changed

- The running-state surface no longer renders the redundant
  "Scanners X/Y done" `<StatLine>` row or the
  `<ScannerChipStrip>` of scan types. Both duplicated information
  already visible in the live progress panel — for example the
  panel header reads "Live progress · 4/14 scanners" while the
  StatLine simultaneously read "Scanners 0/4 done", which was
  confusing on first look.
- The `<ScanProgressPanel>` is now self-contained for the running
  state: header shows elapsed wall-clock duration alongside the
  "streaming events" indicator; footer shows partial-finding count
  + severity pill strip when findings have already arrived. One
  panel, all the answers.
- The completed / failed / cancelled views are unchanged — they
  still use `<StatLine>` + `<ScannerChipStrip>` because there's
  no live panel competing for the same information.

## [0.10.1] - 2026-04-30

A scanner-detection bug fix. Tools installed via `pip install` into
the same Python venv that runs the SecureScan backend (e.g.
`./venv/bin/bandit`) were being shown as "Not installed" on the
Scanners page and silently skipped during scans, even though the
binary was right next to `./venv/bin/python` — because
`shutil.which()` only searches the system `PATH`, which doesn't
include the venv's `bin/`.

### Fixed

- New `securescan.scanners.discovery.find_tool()` helper resolves
  binaries via PATH first, then falls back to the directory
  containing `sys.executable` (i.e. the running Python's `bin/`).
  All scanners (`bandit`, `semgrep`, `safety`, `checkov`, `trivy`,
  `nmap`, `npm-audit`, `license-checker`) now use this helper for
  both `is_available()` and the actual subprocess invocation, so
  tools installed in the backend venv are auto-discovered.
- Bug regression test: `find_tool` deliberately does NOT
  `Path.resolve()` `sys.executable`, because doing so would walk the
  symlink chain `venv/bin/python` → `python3` → `/usr/bin/python3`
  and miss the venv's own `bin/`. Pinned by
  `test_find_tool_does_not_resolve_symlinks`.

### Added

- `GET /api/v1/dashboard/status` now returns a `checked_at` timestamp
  alongside the scanner list. The Scanners page surfaces this next to
  the "Refresh status" button as `· Xs ago` so users can confirm their
  manual refresh actually did fresh work. The button label flips to
  `Checking…` while the request is in flight.

### Tests

- 790 → 870 (+80 since v0.10.0): 7 new for `find_tool` /
  `tool_command_or_module`, and the existing scanner test suites all
  still pass after migrating off `shutil.which`.

## [0.10.0] - 2026-04-30

A non-feature minor release: full product documentation website,
Apache 2.0 relicensing, and a NOTICE file crediting the third-party
scanners SecureScan orchestrates.

### Added

- **Documentation website** at <https://metbcy.github.io/securescan/>.
  41 pages covering install, all features (v0.6.0 → v0.9.0), API
  reference, deployment, security, and CLI usage. Built with mdBook,
  auto-deployed on every push to `main` that touches `docs/**` via a
  new `.github/workflows/docs.yml` workflow. Includes mermaid
  architecture diagrams (scan lifecycle, SSE token rotation, webhook
  delivery state machine) and full HMAC verification examples for
  Python / Node / Go.
- `LICENSE` file (Apache 2.0, full text) and `NOTICE` file crediting
  the third-party scanners (bandit, semgrep, trivy, checkov, safety,
  OWASP ZAP, nmap, npm-audit, license-checker) which are invoked as
  subprocesses, not redistributed.
- README link to the new documentation site.

### Changed

- Project relicensed to **Apache 2.0**. Previously declared MIT in
  `README.md` and `backend/pyproject.toml` but no `LICENSE` file
  existed in the repo. Apache 2.0 fits a security-tooling project
  better — explicit patent grant, NOTICE convention. `frontend/
  package.json` `license` field added (was unset).

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
  `SECURESCAN_AUTH_REQUIRED=1`.
- **Outbound webhooks.** `POST /api/v1/webhooks` (admin) creates
  durable subscriptions to scan lifecycle events. Each delivery is
  persisted in `webhook_deliveries` BEFORE the HTTP call, so a
  backend restart resumes any pending retries. Retry policy: full-
  jitter exponential backoff capped at 5 minutes, max delivery age
  30 minutes. Payloads are HMAC-SHA256 signed via
  `X-SecureScan-Signature: t=<unix-ts>,v1=<hex-hmac>` over
  `f"{t}.{raw_body}"` (Stripe-style; documented in PRODUCT.md).
  FIFO ordering per webhook (different webhooks dispatch
  concurrently). Slack and Discord URLs auto-detected and reshaped;
  generic JSON otherwise. New `/settings/webhooks` page lists
  webhooks with a delivery log drawer that auto-refreshes every 5s.
  `POST /webhooks/{id}/test` fires a synthetic event through the
  exact dispatcher path so users can verify receivers end-to-end.
- **In-app notifications.** New `notifications` table; bell icon in
  the topbar with unread count badge (poll every 30s); 360px popover
  showing 10 most recent with severity dots. Notifications are
  auto-created on `scan.complete` (only when `findings_count > 0` —
  successful zero-finding scans don't spam the bell), `scan.failed`,
  `scanner.failed`. New `/notifications` page lists everything with
  All / Unread / Read filter chips. Read notifications older than
  30 days are pruned at backend startup.

### Changed

- `_log_scan_event` now triggers three side-effects per emission: the
  v0.6.1 logger line, the v0.7.0 ScanEventBus publish, and (new) two
  side-effect hooks for webhook enqueue + notification create. Hooks
  run via `asyncio.create_task` and swallow DB errors so a failed
  side-effect can't break a live scan.
- `require_api_key` now accepts `?event_token=` for the SSE route
  specifically. The path-match check makes a leaked token only usable
  on `/scans/{id}/events`; any other route falls through to strict
  `X-API-Key` validation.

### Bug fixed during integration

- Dev-mode SSE event tokens were being minted with `key_id="env"`,
  then verification rejected them because no env-var was actually
  configured. Tokens minted in dev mode now use a `"dev"` sentinel
  that's accepted only while the system remains in dev mode; if
  credentials are added later, dev-mode tokens are invalidated.
  Regression test in `test_sse.py::test_dev_mode_token_round_trips`
  and `test_dev_mode_token_invalidated_when_auth_enabled`.

### Tests

- 790 → 863 (+73): 9 event-token unit + 12 SSE token integration
  (including 2 dev-mode regression), 31 webhooks, 21 notifications.

### Deployment notes

- The webhook dispatcher runs as an asyncio task on the same uvicorn
  worker as the API. Single-worker constraint from v0.7.0 still
  applies (multi-worker pubsub backplane is a future feature).
- HMAC verification reference (Python):
  ```python
  import hmac, hashlib
  ts, _, sig = request.headers["X-SecureScan-Signature"].partition("v1=")
  ts = ts.split("=")[1].rstrip(",")
  expected = hmac.new(
      secret.encode(), f"{ts}.".encode() + body, hashlib.sha256
  ).hexdigest()
  assert hmac.compare_digest(expected, sig)
  ```

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
  granted.
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
  enforces the one-shot secret reveal contract: the close button
  is disabled for 1 second after the secret appears, and an Esc /
  outside-click triggers a "discard without saving the key?" confirm
  dialog. Sidebar now has a Settings group.

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
  re-trigger DB writes (`last_used_at` touch).

### Tests

- 738 → 790 (+52): 30 for the keys API + auth flow, 11 for scopes
  including the route-coverage regression guard, plus the revoked-
  key-no-env-var fix and a rate-limit test update.

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
  - `PATCH /api/v1/findings/{fingerprint}/state` —
    `{status, note?, updated_by?}` → `FindingState`
  - `GET /api/v1/findings/{fingerprint}/comments` →
    `FindingComment[]`
  - `POST /api/v1/findings/{fingerprint}/comments` —
    `{text, author?}` → `FindingComment` (201)
  - `DELETE /api/v1/findings/{fingerprint}/comments/{comment_id}` →
    204
  Schema additions (idempotent migrations): `finding_states`,
  `finding_comments`, plus a previously-missing
  `idx_findings_scan_id` index that the existing `get_findings`
  query needed as scan history grew.
- **Triage UI.** New compact "Status" column in the findings table
  with status pill (color-coded; `fixed` adds strikethrough +
  accent-green pill so a regression is loud). Status filter chip
  strip in the sticky filter bar. Expanded row gets a Triage panel
  (status dropdown + note textarea) and a Comments panel (lazy
  loaded; add / delete inline). Triage filter and the existing
  suppression filter are independent and AND-combined. Default-hide
  set is `{false_positive, accepted_risk, wont_fix}`. `fixed` is
  intentionally NOT default-hidden so a "fixed" finding reappearing
  in a later scan stays visible — the regression signal would
  otherwise vanish.
- **Real-time scan progress (SSE).**
  `GET /api/v1/scans/{scan_id}/events` streams the same lifecycle
  events the v0.6.1 logger emits (`scan.start`, `scanner.start`,
  `scanner.complete`, `scanner.skipped`, `scanner.failed`,
  `scan.complete`, `scan.failed`, `scan.cancelled`).
  `Content-Type: text/event-stream` with 15-second keepalive
  comments. Late subscribers get a 200-event replay buffer so a tab
  refresh mid-scan still rebuilds the full state; the buffer is
  retained 30 seconds after a terminal event. Terminal events are
  never dropped on subscriber backpressure (oldest non-terminal
  event is evicted instead).
- **Scan-detail page goes live.** New `<ScanProgressPanel>` above
  the StatLine while a scan is `running`/`pending`, showing
  per-scanner state dots (queued / running / complete / failed /
  skipped) with findings counts and durations as they update.
  `EventSource` replaces the 2-second poll. On `EventSource`
  error or when an API key is configured (EventSource can't send
  custom auth headers), the page falls back to the v0.6.1
  status-only poll path — `EventSource` is closed first so the
  browser's auto-reconnect doesn't run alongside the fallback.

### Changed

- `GET /api/v1/scans/{id}/findings` now returns
  `FindingWithState` objects — every existing field, plus an
  optional `state` payload. The bare `Finding` model is unchanged,
  so SARIF / JSON / baseline / CLI exporters keep their existing
  contract.

### Deployment notes

- The SSE event bus is a module-level singleton. SecureScan now
  requires `--workers 1` for `/api/v1/scans/{id}/events` to work
  correctly. Multi-process pubsub (Redis backplane) is on the
  v0.7.x roadmap. Documented in `README.md`.
- SSE is unauthenticated when `SECURESCAN_API_KEY` is set, because
  browsers can't attach custom headers to `EventSource`. The
  frontend silently falls back to polling in that case. Cookie
  auth / signed-token auth for SSE is on the v0.7.x roadmap.

### Tests

- 709 → 738 (+29): 15 for triage API, 14 for SSE bus + endpoint.

## [0.6.1] - 2026-04-29

A polish release focused on production readiness on real (large) scans.
The 20k-finding scan that shipped during v0.6.0 testing exposed three
issues — a stale-running UI badge, a janky search box, and a missing
delete-scan endpoint — all fixed here. We also added structured scan
lifecycle logs, a user-scoped `.env` loader so credentials persist
across restarts, and a smarter ZAP install hint.

### Added

- `DELETE /api/v1/scans/{id}` removes a scan and cascades its findings.
  Returns 204 on success, 409 if the scan is `running`/`pending`
  (cancel first), 404 otherwise. The History page Delete action is now
  enabled and wired up with a confirm prompt.
- Structured INFO logging for the scan lifecycle on the
  `securescan.scan` logger: `scan.start`, `scanner.start`,
  `scanner.complete` (with `duration_s` and `findings_count`),
  `scanner.skipped`, `scanner.failed`, `scan.complete`, `scan.failed`,
  `scan.cancelled`. Tail `/tmp/securescan-backend.log` to debug a scan
  in flight.
- `~/.config/securescan/.env` (or `$XDG_CONFIG_HOME/securescan/.env`)
  is auto-loaded at backend startup. Persist `SECURESCAN_ZAP_ADDRESS`,
  `SECURESCAN_ZAP_API_KEY`, etc. across reboots without re-exporting.
  Shell environment still wins over the file. Documented in `README.md`.

### Changed

- `frontend/src/app/scan/[id]/page.tsx` polling no longer refetches
  the entire findings array every 2 seconds. While a scan is running,
  only the lightweight scan-status record is polled; findings and
  summary load once on mount and once when status flips to
  `completed`. Fixes the "scan stays running forever" UI bug on
  large-result scans.
- `FindingsTable` is responsive again on 20k-finding scans. Search
  input uses React 19's `useDeferredValue`; a single memoized
  projection (`severityNorm`, `suppressed`, `haystack`) replaces
  per-keystroke string normalization across filter, sort, severity
  counts, and scanner options. Measured: 9.6 ms avg keystroke handling
  (was hundreds of ms).
- `ZapScanner.install_hint` now detects Arch Linux's
  `/usr/share/zaproxy/zap.sh` launcher, recommends port `8090` (8080
  is commonly busy), and points users at the new `.env` file for
  credential persistence.

### Tests

- 690 → 709 (+19): 11 for the DELETE endpoint, 4 for the lifecycle
  logger, 4 for the env-file loader.

## [0.6.0] - 2026-04-29

This release pairs an end-to-end frontend redesign with two backend
durability features. The dashboard moves off neon traffic-light colors
and ad-hoc card grids onto an OKLCH design system with a single-hue
severity ramp, dense data-table layouts, a new app shell (sidebar +
sticky topbar + ⌘K command palette), and a brand-new `/diff` page for
PR-style scan comparison. On the API side, all routes are now mounted
under `/api/v1/...` (legacy `/api/...` paths still work, with
`Deprecation` / `Sunset` response headers), and `POST /scans` is
protected by an in-memory per-key token-bucket rate limiter.

### Added

- `/api/v1` versioning prefix; legacy `/api/*` paths return
  `Deprecation`, `Link`, and `Sunset` (Dec 31 2026) response headers
  (FEAT2).
- In-memory rate limiting on `POST /api/scans` and
  `POST /api/v1/scans`; per-API-key token-bucket, configurable via
  `SECURESCAN_RATE_LIMIT_PER_MIN` / `_BURST` / `_ENABLED`, 429
  responses with `Retry-After` and `X-RateLimit-*` headers (FEAT3).
- New `/diff` dashboard page — PR-style scan-vs-scan diff with
  base/head pickers, summary chips (new / resolved / unchanged + risk
  delta), and tabbed findings (FEAT1).
- Command palette (⌘K) for navigation, recent scans, and quick
  actions (DSH2).
- Theme toggle and `next-themes` integration; dark default with light
  theme support (DSH1).

### Changed

- Frontend redesigned end-to-end. New OKLCH design tokens, single-hue
  severity ramp (replaces neon traffic-light coloring), Geist
  Sans/Mono typography, Restrained color strategy per the new
  `DESIGN.md` (DSH1).
- New 220px sidebar + 56px sticky topbar with breadcrumb-style page
  label and live API health indicator (DSH2).
- Overview page replaces 3-card hero metric grid with `PageHeader` +
  `StatLine`; latest-scan two-column section, recent-scans compact
  table, tokenized compliance cards (DSH3).
- New Scan page is now a two-column wizard with sticky preview panel,
  per-scanner row layout, quick presets, recently-scanned chips, and
  severity-threshold option (DSH4).
- Scan Detail page rewritten: `PageHeader`, `StatLine` (risk score /
  finding counts / scanners / duration), sticky filter bar with
  severity chips, compact findings table with severity-tinted left
  edges, expand-row interactions, scanner-chip strip showing ran /
  skipped scanners with skip reasons (DSH5).
- History page replaces 24-card grid with sortable, filterable,
  paginated data table; status icons, mono target paths, scanner
  chip strip with overflow, kebab action menu, URL-persisted sort /
  page-size (DSH6).
- Scanners page categorizes scanners into Code analysis /
  Dependencies / Containers & IaC / Secrets / Network / Web / Other;
  sticky status legend + search; bulk "Install all available";
  tokenized install hints (DSH7).
- SBOM and Compare pages redesigned with `PageHeader` + segmented
  format toggle (CycloneDX / SPDX) + scan picker cards + tokenized
  diff coloring (DSH8).
- Frontend dependencies updated: `geist`, `next-themes`, `cmdk`.

### Removed

- `StatCard` component (replaced by `StatLine`).
- `ScanCard` component (replaced by `HistoryTable`).
- Hardcoded hex colors throughout the dashboard (replaced by OKLCH
  design tokens).

### Documentation

- New `PRODUCT.md` captures product brief, users, brand tone,
  anti-references, design references, strategic principles, and
  register declaration.
- New `DESIGN.md` captures the canonical design system: OKLCH tokens,
  severity ramp, typography, spacing, layout, component vocabulary,
  page-level bans, and validation checklist.
- README updated with v0.6.0 highlights.

### Migration

Existing v0.5.0 callers (CLIs, GitHub Actions, third-party scripts)
continue working against `/api/*` and will see a `Deprecation: true`
response header indicating the new `/api/v1/*` path. No code changes
required; migrate at your pace before Dec 31, 2026.

## [0.5.0] - 2026-04-28

<!-- PG8 finalizes the date and version bump. -->

This release is about prod-readiness ground truth. v0.4.0 made the
GitHub Action useful for adoption; v0.5.0 makes the FastAPI server
deployable beyond the developer's laptop and closes the silent-skip
UX gaps that were burning trust on the dashboard.

### Added

- Optional API key authentication via `SECURESCAN_API_KEY` env var.
  When set, every `/api/*` endpoint requires `X-API-Key` (or
  `Authorization: Bearer`); when unset, dev mode preserves v0.4
  behavior with a startup warning. `secrets.compare_digest` for
  timing-safe comparison.
- Structured JSON logging via stdlib (no new deps). Defaults to JSON
  in containers (`SECURESCAN_IN_CONTAINER=1`), text in dev. Configure
  with `SECURESCAN_LOG_LEVEL`, `SECURESCAN_LOG_FORMAT`. Each request
  emits one structured log line with `request_id`, `method`, `path`,
  `status`, and `latency_ms`.
- Request-ID correlation: each response carries `X-Request-ID`. Client
  can pin via the same header on the request; otherwise server
  generates a uuid4.
- `GET /ready` endpoint distinct from `/health`. Returns 200 when
  the database is openable AND the scanner registry loads; returns
  503 with per-check details when not. Both `/health` and `/ready`
  remain public regardless of API-key configuration.
- `Scan.scanners_run` and `Scan.scanners_skipped` fields persisted
  per scan. Skipped entries include `name`, `reason`, and
  `install_hint` so the dashboard renders actionable text without
  re-fetching scanner availability.
- `metadata["baseline_scope"] = "host" | "target"` stamp on every
  baseline finding so the audit trail records which scope produced
  each finding.
- CLI flag `--baseline-host-probes` on `scan`, `diff`, `compare`
  for power users who want host-scope alongside target-scope scans.
- Dashboard `/scan` page reads `/api/dashboard/status` on mount and
  disables categories whose scanners are all unavailable, with
  inline install hints. Default selection adapts to availability.
- Dashboard `FindingsTable` renders `[SUPPRESSED:inline]` /
  `[SUPPRESSED:config]` / `[SUPPRESSED:baseline]` badges and shows
  `severity (was: original)` annotations when `.securescan.yml`
  overrode severity. Optional "Show suppressed findings" toggle.
- Dashboard scan-result page surfaces `Scanners run: ...` and a
  collapsible `Skipped (N)` section with install hints.

### Changed

- Baseline scanner now respects `target_path`. When target is `/`
  or empty, host-wide probes run (v0.4 behavior). Otherwise the
  scanner probes `<target>/etc/ssh/sshd_config`,
  `<target>/etc/passwd`, `<target>/etc/shadow` and skips
  `~/.ssh` perm checks (those are host-scope only). When a target
  has no host-config files, the scanner emits ONE info-severity
  finding pointing the user to `--baseline-host-probes`. Backward
  compat: `target_path = "/"` still runs host-wide probes.
- Scan results now record `scanners_run` and `scanners_skipped`
  on both COMPLETED and FAILED scans (no more silent skips).
- The frontend API client (`frontend/src/lib/api.ts`) injects
  `X-API-Key` from `NEXT_PUBLIC_SECURESCAN_API_KEY` on every
  request when the env var is set at build time.

### Documentation

- README "Production deployment" section: API key, log format,
  health/readiness probes, reverse-proxy notes.

## [0.4.0] - 2026-04-28

<!-- IR9 finalizes the date and version bump. -->

This release adds **inline PR review comments**: when `pr-mode: inline`
is set on the `Metbcy/securescan@v1` Action, each finding becomes a
GitHub review comment anchored to the affected line — letting
reviewers resolve findings individually instead of treating the
summary block as a single yes/no toggle.

### Added

- `pr-mode: inline | summary | both` action input. Default `summary`
  preserves v0.2.0/v0.3.0 behavior; `inline` switches to GitHub Reviews
  API; `both` posts both surfaces.
- `review-event: COMMENT | REQUEST_CHANGES | APPROVE` action input.
  Default `COMMENT` so the action does not silently block merges via
  branch protection.
- `inline-suggestions: true | false` action input. When true (default),
  inline comments include suggestion blocks for mechanical fixes
  (e.g., `# securescan: ignore RULE-ID` one-click commit).
- `securescan diff --output github-review` and
  `securescan compare --output github-review` CLI flags. Emit the
  GitHub Reviews API JSON payload (commit_id, event, body, comments).
  Useful both for the action's `post-review.sh` and for local
  inspection.
- `--repo`, `--sha`, `--base-sha`, `--review-event`, `--no-suggestions`
  CLI flags on `diff` and `compare` for the github-review output path.
  All `GITHUB_*` env vars are honored as fallbacks.
- `<!-- securescan:fp:<12-char-prefix> -->` fingerprint marker
  embedded in each inline comment body so re-runs can PATCH existing
  comments by fingerprint instead of posting duplicates.
- `<!-- securescan:diff-review -->` and
  `<!-- securescan:compare-review -->` body markers on the review's
  overall body, distinct from the existing `securescan:diff` /
  `securescan:compare` markers used by `pr-mode: summary`.
- Suggestion blocks for two mechanical fixes:
  - **Inline ignore**: a `\`\`\`suggestion` block adding the
    `# securescan: ignore RULE-ID` comment one line above the finding
    (one-click commit).
  - **Severity pin**: a YAML reference for `.securescan.yml`'s
    `severity_overrides:` map (copy-paste only — the file lives outside
    the comment's anchor scope).
- Resolved-finding marking: when a finding disappears from a re-run,
  its inline comment is PATCHed to prepend
  `**Resolved in <commit-sha-prefix>** — finding no longer present`
  with the original body strikethrough'd. Manual reviewer resolution
  is preserved (we do NOT call GraphQL `resolveReviewThread`).

### Changed

- `securescan` CLI requires `--repo`, `--sha`, and `--base-sha` (or the
  `GITHUB_REPOSITORY` / `GITHUB_SHA` env fallbacks) when
  `--output github-review` is selected. Other output formats are
  unchanged.
- The action's `entrypoint.sh` dispatches to the appropriate poster
  based on `pr-mode`. Backward-compatible: omitting the input behaves
  exactly as v0.3.0.

### Documentation

- README "Inline PR review comments" section with action snippet,
  permissions, local-dev workflow, and a comparison table against
  the existing `pr-mode: summary`.
- `examples/github-action.yml` shows both default and inline variants.

## [0.3.0] - 2026-04-28

<!-- TS12 finalizes the date and version bump. -->

This release is about signal quality. v0.2.0 made SecureScan a useful
CI/CD tool; v0.3.0 makes it tunable enough to *stay on* across months
of CI runs without becoming PR-comment noise.

### Added

- `.securescan.yml` configuration file (auto-detected, walks up from
  the scan target). Covers `scan_types`, `severity_overrides`,
  `ignored_rules`, `semgrep_rules` (custom rule packs),
  `fail_on_severity`, and `ai`.
- Inline ignore comments in source: `# securescan: ignore RULE-ID`,
  `// securescan: ignore-next-line RULE-A, RULE-B`, etc. Recognized in
  `#`, `//`, and `--` comment styles. `*` wildcard supported.
- Per-rule severity overrides applied post-scan; original severity
  preserved on `metadata.original_severity` for audit.
- Custom Semgrep rule packs via `semgrep_rules:` in config. When set,
  replaces `--config auto` with one `--config <path>` per entry.
- `securescan compare <baseline.json>` subcommand: classifies the
  current scan against a baseline JSON into NEW / DISAPPEARED /
  STILL_PRESENT. Marker: `<!-- securescan:compare -->` for PR-comment
  upsert.
- `securescan baseline` subcommand: writes a canonicalized,
  byte-deterministic baseline JSON (default `.securescan/baseline.json`)
  with no timestamps and a relative `target_path` so it's git-friendly.
- `securescan config validate` subcommand: lints `.securescan.yml` for
  typos, bad severity values, missing rule-pack paths, and
  `ignored_rules` ↔ `severity_overrides` collisions.
- `--show-suppressed` and `--no-suppress` flags on `scan`, `diff`, and
  `compare`. By default, suppressed findings are hidden in CI but shown
  on a TTY with a `[SUPPRESSED:<reason>]` prefix for audit visibility.
- `--ai` / `--no-ai` flags on every relevant subcommand, with a
  three-tier precedence: CLI flag > `.securescan.yml`'s `ai:` key > CI
  environment auto-detection.
- `metadata.suppressed_by` finding stamp records the suppression reason
  (`"inline"` | `"config"` | `"baseline"`) so SARIF / JSON / CSV
  consumers can audit which mechanism applied.
- New CSV column `suppressed` (when `--show-suppressed`); JUnit
  `<system-out>SUPPRESSED:<reason></system-out>` annotations; SARIF
  `properties.suppressed_by` per result.

### Changed

- `securescan diff` and `securescan compare` now apply
  `.securescan.yml` to BOTH sides of the comparison (config rules apply
  uniformly across base and head). Backward-compatible when no config
  file is present.
- The PR comment summary table includes a "Suppressed: N (inline=I,
  config=C, baseline=B)" row when `--show-suppressed` is set so
  reviewers can audit the breakdown without rerunning.
- `--fail-on-severity` counts only the `kept` findings (not suppressed
  ones), matching the v0.2.0 invariant that fail-on-severity respects
  diff filtering.

### Documentation

- README rewrite with new "Configuration", "Suppressing findings", and
  "Subcommands" sections; full `.securescan.yml` schema example with
  every key documented.

## [0.2.0] - 2026-04-28

This release reframes SecureScan around CI/CD adoption: diff-aware scans,
deterministic output, a first-class GitHub Action, and signed distribution
artifacts. The dashboard and all 14 scanners from v0.1.0 continue to work
unchanged; the new surfaces are opt-in.

### Added

- `securescan diff <base-ref> <head-ref>` subcommand for change-aware scans
  that report only NEW findings introduced between two refs.
- `--baseline <file>` CLI flag to suppress findings present in a saved
  snapshot, and `--no-ai` / `--ai` flags to explicitly toggle AI enrichment
  for fully-deterministic CI runs.
- `github-pr-comment` output format optimized for GitHub PR comments,
  including a `<!-- securescan:diff -->` upsert marker so CI systems can
  update a single comment in place rather than appending on every run.
- Deterministic SARIF output with stable rule ordering, canonical finding
  sort, and `partialFingerprints` for cleaner re-uploads to GitHub's
  Security tab without false-new-alert noise.
- `Metbcy/securescan@v1` GitHub Action (composite, wheel-first with
  container fallback) that wraps `securescan diff`, posts the PR comment,
  and uploads SARIF.
- Multi-arch container image published to `ghcr.io/Metbcy/securescan` with
  all 14 scanners pre-installed and pinned for reproducible CI runs.
- PyPI distribution: `pip install securescan` and `pipx install securescan`
  for runners that already have scanner binaries on PATH.
- cosign-signed container images and sigstore-python-signed wheels on every
  tagged release, with verification examples in the README.
- Per-finding stable fingerprints
  (`sha256(scanner|rule_id|file_path|normalized_line_context|cwe)`) so the
  same finding keeps the same identity across runs and trivial code shifts.

### Changed

- AI enrichment is now auto-disabled when the `CI=true` environment
  variable is set, ensuring deterministic output in CI without requiring
  callers to remember `--no-ai` on every invocation.
- All CLI output renderers (Markdown, SARIF, JSON, terminal) sort findings
  canonically by severity (descending), then `file_path`, then `line`, then
  `rule_id`, then `title`, and exclude wall-clock timestamps from
  byte-identity-sensitive sections so identical inputs produce
  byte-identical output.

### Fixed

- `--fail-on-severity` now respects `--diff` mode and counts only the NEW
  findings introduced by the change rather than every finding present in
  the codebase. Previously, a clean PR against a noisy baseline would still
  fail the build.

### Documentation

- README rewrite leading with the GitHub Action / PR-comment use case
  rather than the dashboard.
- Signature verification examples for both the wheel (sigstore) and the
  container image (cosign).

## [0.1.0] - 2026-04-05

Initial public release. SecureScan ships as a self-hosted, AI-augmented
security orchestrator: a FastAPI backend coordinating 14 scanners across
code, dependencies, IaC, containers, secrets, DAST, and network targets,
fronted by a Next.js dashboard.

### Added

- 14 scanners across categories:
  - Static analysis: `semgrep`, `bandit`
  - Container / IaC: `trivy`, `checkov`, `dockerfile`
  - Baseline / built-in heuristics: `baseline`
  - Secrets: `secrets`, `gitleaks`
  - Dependencies: `safety`, `npm-audit`, `license-checker`
  - DAST: `dast-builtin` (header / cookie / info-disclosure checks),
    OWASP `zap`
  - Network: `nmap`
- FastAPI backend with SQLite-backed scan storage, run history, and a
  cancellation-aware job queue.
- Next.js dashboard with scan launcher, directory browser, per-scanner
  descriptions and install buttons, scan comparison, and trend charts.
- AI enrichment of findings via Groq / Llama for human-readable
  explanations and remediation hints.
- SBOM generation in CycloneDX and SPDX formats with an API endpoint and
  a dashboard view that renders the component table and ecosystem stats.
- PDF and HTML report generation with compliance coverage summaries and
  a Jinja2-based report template.
- Compliance mapping engine covering OWASP Top 10, CIS, PCI-DSS, and
  SOC 2, with CWE / `rule_id` / keyword matching, framework data files,
  coverage API endpoints, and dashboard compliance badges.
- Export formats: SARIF, CSV, and JUnit, plus the new HTML and PDF
  report renderers.
- CI/CD gating via process exit code and an example workflow.
- Cross-platform setup notes (including Windows) and per-scanner
  install guidance.

[Unreleased]: https://github.com/Metbcy/securescan/compare/v0.10.2...HEAD
[0.10.2]: https://github.com/Metbcy/securescan/releases/tag/v0.10.2
[0.10.1]: https://github.com/Metbcy/securescan/releases/tag/v0.10.1
[0.10.0]: https://github.com/Metbcy/securescan/releases/tag/v0.10.0
[0.9.0]: https://github.com/Metbcy/securescan/releases/tag/v0.9.0
[0.8.0]: https://github.com/Metbcy/securescan/releases/tag/v0.8.0
[0.7.0]: https://github.com/Metbcy/securescan/releases/tag/v0.7.0
[0.6.1]: https://github.com/Metbcy/securescan/releases/tag/v0.6.1
[0.6.0]: https://github.com/Metbcy/securescan/releases/tag/v0.6.0
[0.5.0]: https://github.com/Metbcy/securescan/releases/tag/v0.5.0
[0.4.0]: https://github.com/Metbcy/securescan/releases/tag/v0.4.0
[0.3.0]: https://github.com/Metbcy/securescan/releases/tag/v0.3.0
[0.2.0]: https://github.com/Metbcy/securescan/releases/tag/v0.2.0
[0.1.0]: https://github.com/Metbcy/securescan/releases/tag/v0.1.0
