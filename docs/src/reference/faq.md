# FAQ

Common questions, with links into the rest of the documentation for
the long-form answers.

<!-- toc -->

## General

### Is SecureScan a SaaS?

No. It is a self-hosted Python package + container image. Run it on
your laptop, your CI runner, your internal server, your Kubernetes
cluster. There is no cloud-hosted instance to point a browser at.
See [Install](../install.md).

### What scanners are included?

14 across `code`, `dependency`, `iac`, `baseline`, `dast`, `network`.
Semgrep, Bandit, Trivy, Checkov, Safety, Gitleaks, nmap, ZAP, plus
built-ins for secrets / DAST / Dockerfile / baseline / git-hygiene /
licenses / npm-audit. Full list in
[Supported scanners](../scanning/supported-scanners.md).

### Does SecureScan have its own vulnerability database?

No. It orchestrates the open-source scanners you already trust.
Trivy and Safety bring their own DBs; SecureScan does not maintain
or duplicate them. This is a deliberate non-goal — see the README's
"Non-goals" section.

### Does it work in CI?

Yes — that's the primary use case. The `Metbcy/securescan@v1` GitHub
Action wraps `securescan diff`, posts an upserted PR comment of NEW
findings only, and uploads SARIF. See [GitHub Action](../cli/github-action.md).

For non-GitHub CI (GitLab, Jenkins, CircleCI), use `securescan diff`
directly with `--output github-pr-comment` or `--output sarif`.

## Determinism

### Why is AI enrichment off in CI?

Because it is non-deterministic, and the v0.2.0 contract (single
upserted PR comment, deduped SARIF) depends on byte-identical output
for the same inputs. AI explanations vary run-to-run, so they would
break the upsert.

`CI=true` (set automatically by GitHub Actions, GitLab CI, etc.)
flips AI off. Pass `--ai` to force it on; `--no-ai` to be explicit.

### How do I get reproducible CI output?

- Don't enable AI (`CI=true` handles this).
- Pin the SecureScan version (`Metbcy/securescan@v0.10.3`, not `@v1`).
- Pin scanner versions inside your runner (use the container —
  `prefer-image: true`).
- Use snapshot-mode diff: `securescan scan ... --output json` on
  each side, then `securescan diff ... --base-snapshot ... --head-snapshot ...`.

See [How scans work → Determinism](../scanning/how-scans-work.md#determinism).

### A trivial reformat made every finding "new". Why?

Almost certainly something changed in the
`normalized_line_context` of the matched line — e.g. you renamed a
variable used on that line, or moved the line to a different file.
The fingerprint hash includes those, so the identity changes.

If the change should NOT have re-opened the finding, file an issue
with a reproducer; we tune the normalization to handle real-world
reformats.

## Auth

### Do I need API keys for local dev?

No. With `SECURESCAN_API_KEY` unset and `SECURESCAN_AUTH_REQUIRED=0`
(both defaults), the backend runs in dev mode — every request passes
through. The startup banner warns you. See
[Authentication overview](../auth/overview.md#dev-mode).

### Can I rotate the env-var key without downtime?

Not exactly. The env-var key is read on every request, but a hot
rotation means the new value isn't picked up until the process
restarts.

For zero-downtime rotation, **issue a DB key first**, switch your
consumer, then update / restart at your leisure. See
[API keys → Lifecycle](../auth/api-keys.md#lifecycle-rotate-a-key).

### Why salted SHA-256 and not bcrypt / argon2?

Because the keys are 192-bit random secrets — brute-forcing the hash
is already infeasible without a memory-hard KDF. Adding bcrypt buys
nothing except a hard dependency and per-request CPU cost on the
auth path. See [API keys → Why salted SHA-256](../auth/api-keys.md#why-salted-sha-256-not-bcrypt--argon2).

If you have a different threat model — e.g. you let users pick weak
keys — use longer keys, not a slower KDF.

### How do I lock out a leaked key immediately?

```bash
curl -X DELETE -H "X-API-Key: $ADMIN_KEY" \
  http://your-backend/api/v1/keys/<id>
```

The next request with that key returns 401. No cache, no propagation
delay. SSE event tokens bound to the now-revoked key also fail at
the rehydrate step at connect time, even if the token's HMAC and
TTL are still valid. See [SSE event tokens](../auth/event-tokens.md).

### Why doesn't the API have OAuth / SSO?

Because SecureScan is intentionally an internal-tools / SRE shape.
Adding OIDC / SSO inside the backend would force every operator
through a much heavier integration than they need. Instead:
**terminate authentication in front of SecureScan** with
oauth2-proxy / Cloudflare Access / AWS ALB OIDC, and treat
SecureScan's API keys as service identities behind the proxy.

## Scaling

### Can I run multiple uvicorn workers?

No. The event bus and webhook dispatcher are in-process singletons.
`--workers 2+` silently breaks SSE and breaks webhook FIFO ordering.
See [Single-worker constraint](../deployment/single-worker.md).

### How do I scale horizontally?

Run multiple separate backend deployments behind a sticky-session
load balancer keyed on `scan_id`. Each deployment is single-worker;
all of one scan's lifecycle happens on the same instance.

A Redis pubsub backplane is on the roadmap to remove this constraint.

### My SSE connections drop after 60s. Why?

Some load balancers / reverse proxies close idle HTTP connections
after a default idle timeout. SecureScan emits a 15-second keepalive
comment on the SSE stream specifically to defeat this — but if your
proxy aggressively closes HTTP/1.1 streams regardless, raise its
idle timeout to at least 60s.

## Webhooks

### Why is at-least-once the contract?

Because some receivers accept the request, succeed at their internal
work, and then crash before responding 2xx. SecureScan retries
because it cannot tell the difference between "you didn't receive
it" and "you received it but failed to ack it." Receivers must be
idempotent — see [Webhooks → at-least-once](../dashboard/webhooks.md#retry--state-machine).

### Why retry 4xx?

A misconfigured receiver that returns 401 for a few seconds while
it loads its keys should not lose deliveries within the 30-minute
window. The cost (a few extra HTTP calls during a transient
misconfig) is far smaller than the cost (lost notifications) of
giving up immediately. See [Webhooks](../dashboard/webhooks.md).

### Can I rotate a webhook secret?

Not in place. To rotate: delete + recreate the webhook subscription.
The secret is returned only on creation; there is no
"reveal current secret" or "PATCH secret" endpoint by design.

If you need rotation without lost deliveries, create a new
subscription pointing at the same URL, switch your receiver to
accept both the old and new secret for a transition window, then
delete the old subscription.

### Slack/Discord don't verify HMAC. Is that a problem?

It's a property of those receivers, not SecureScan. Both Slack and
Discord webhook URLs are unauthenticated — anyone with the URL can
post. **Treat the URL itself as the secret.** Don't share it; rotate
it (regenerate at the provider, recreate the SecureScan
subscription) on suspicion of leak.

If you need cryptographic verification end-to-end, route through a
proxy you control that verifies HMAC and forwards into Slack /
Discord with their URL.

## Data

### How do I back up my SecureScan data?

The SQLite DB at `~/.securescan/scans.db` (or whatever
`SECURESCAN_DB_PATH` points at) holds everything: scans, findings,
triage state, API keys, webhooks, notifications. Use SQLite's
`.backup` command on a cron — it works while the backend is
running.

Don't forget `~/.config/securescan/.env` for the ZAP credentials
and any other persisted env vars.

### Can I delete old scans?

Yes:

```bash
curl -X DELETE -H "X-API-Key: $K" http://your-backend/api/v1/scans/$SCAN_ID
```

Findings are cascade-deleted. Triage verdicts and per-finding
comments **persist** because they're keyed on cross-scan
fingerprint, not scan id. They reactivate when the same finding
reappears in a later scan. See
[Triage workflow](../scanning/triage.md).

### Can I bulk-export findings?

Yes:

- `securescan scan ... --output csv` — one row per finding.
- `securescan scan ... --output json` — full record set.
- `securescan scan ... --output sarif` — SARIF v2.1.0.

Or query the API: `GET /api/v1/scans/{id}/findings` returns the
JSON shape directly.

## Behavior

### Why doesn't `DELETE /scans/{id}` clear my triage verdicts?

Because triage state is keyed on the cross-scan **fingerprint**, not
the scan id. The whole point of fingerprinted triage is that "this
finding is a false positive" outlives the scan that produced the
original instance. See [Triage workflow](../scanning/triage.md).

If you want to clear a verdict explicitly, set the status back to
`new` (PATCH the state with `{"status": "new"}`).

### Why isn't every scan emitting a notification?

`scan.complete` only creates a notification when `findings_count > 0`.
This is on purpose: zero-finding scans are the common case in a
healthy CI pipeline, and we don't want to spam the bell with 50
"all clear" notifications a day. `scan.failed` and `scanner.failed`
notify regardless. See [Notifications](../dashboard/notifications.md).

### My CI run is slow because Trivy is downloading its DB. What do I do?

The first Trivy run on a fresh runner downloads the vulnerability DB
(~30 seconds). Speed it up by:

- Caching `~/.cache/trivy` between runs (the GitHub Action can use
  `actions/cache`).
- Using the SecureScan container image (`prefer-image: true`) — the
  pre-built image ships with a recent DB baked in.

### Can I customize the severity ramp colors?

Yes, but it's a frontend change. Edit the `--sev-*` OKLCH custom
properties in
[`frontend/src/app/globals.css`](https://github.com/Metbcy/securescan/blob/main/frontend/src/app/globals.css).
The dashboard tokenizes its severity rendering, so changing the
tokens is enough — no per-component override.

The deliberate constraint is that severity is a **single tonal ramp,
not a traffic light**. Going back to neon red/yellow/green is
discouraged; see
[`DESIGN.md`](https://github.com/Metbcy/securescan/blob/main/DESIGN.md).

## Roadmap

### When will multi-process pubsub land?

After v0.9.x. The plan is a Redis backplane behind a feature flag,
followed by leader election for the webhook dispatcher (so FIFO
ordering survives the multi-instance world). No firm date.

### Will there be SaaS hosting?

No plans. SecureScan is positioned as an internal/SRE tool with the
opposite shape of a SaaS — single-tenant, opinionated, deployed
inside your perimeter. If a hosted offering ever ships it will be
under a different name.

### Can I get a feature added?

Open an issue with the use case. The
[`PRODUCT.md`](https://github.com/Metbcy/securescan/blob/main/PRODUCT.md)
captures the strategic principles that govern what goes in;
features that align (deterministic, density-favoring, CLI-as-source-of-truth)
are easier to land.

## Next

- [Glossary](./glossary.md) — precise definitions for terms used here.
- [Changelog](./changelog.md) — what changed in each release.
- [Contributing](../contributing.md) — how to ship a fix.
