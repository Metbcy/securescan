# Scopes

Three scopes, declared per-route, intersected (OR semantics) by the
`require_scope` dependency. Introduced in v0.8.0; every `/api/*` route
declares its required scope explicitly, and a regression-guard test
fails CI if a new route ships without one.

<!-- toc -->

## The scopes

| Scope    | Grants                                                                      | Typical caller                               |
| -------- | --------------------------------------------------------------------------- | -------------------------------------------- |
| `read`   | Read scans, findings, summaries, SBOMs, notifications, compliance.          | Read-only dashboard, monitoring tooling.     |
| `write`  | Create / cancel / delete scans. Set triage state. Add comments. Mark notifications read. | CI runners, the dashboard.   |
| `admin`  | All of the above + manage API keys, manage webhooks.                        | Operator-only (one admin key per deployment).|

Default new-key scopes are `["read", "write"]`. `admin` must be
explicitly requested. See [API keys](./api-keys.md).

## Per-route mapping

The source of truth is the regression-guard test:
**[`backend/tests/test_scopes.py::test_all_routes_have_explicit_scope`](https://github.com/Metbcy/securescan/blob/main/backend/tests/test_scopes.py)**.

That test enumerates `app.routes` and asserts every non-public route
declares a scope via `Depends(require_scope(...))`. A new route
without a scope fails CI.

The mapping below is the v0.9.0 surface, condensed:

### Read scope

| Method | Path                                                | Notes                                       |
| ------ | --------------------------------------------------- | ------------------------------------------- |
| GET    | `/api/v1/scans`                                     | List scans                                  |
| GET    | `/api/v1/scans/{id}`                                | Scan details                                |
| GET    | `/api/v1/scans/{id}/findings`                       | Findings + triage state                     |
| GET    | `/api/v1/scans/{id}/summary`                        | Severity counts + risk score                |
| GET    | `/api/v1/scans/{id}/sbom`                           | CycloneDX or SPDX                           |
| GET    | `/api/v1/scans/{id}/report`                         | HTML / PDF report                           |
| GET    | `/api/v1/scans/{id}/events`                         | SSE — accepts event token; see [event tokens](./event-tokens.md) |
| GET    | `/api/v1/scans/compare`                             | Scan-vs-scan diff                           |
| GET    | `/api/v1/findings/{fp}/comments`                    | List comments on a fingerprint              |
| GET    | `/api/v1/dashboard/status`                          | Scanner availability                        |
| GET    | `/api/v1/dashboard/stats`                           | Aggregate statistics                        |
| GET    | `/api/v1/dashboard/trends`                          | Risk / finding trend data                   |
| GET    | `/api/v1/compliance/coverage`                       | Per-framework coverage                      |
| GET    | `/api/v1/notifications`                             | List notifications                          |
| GET    | `/api/v1/notifications/unread-count`                | Unread count                                |
| POST   | `/api/v1/scans/{id}/event-token`                    | Mint SSE token (read-only operation)        |

### Write scope

| Method | Path                                                | Notes                                       |
| ------ | --------------------------------------------------- | ------------------------------------------- |
| POST   | `/api/v1/scans`                                     | Start a new scan (rate-limited)             |
| DELETE | `/api/v1/scans/{id}`                                | Delete a scan + cascade findings            |
| POST   | `/api/v1/scans/{id}/cancel`                         | Cancel a running scan                       |
| PATCH  | `/api/v1/findings/{fp}/state`                       | Set / replace triage verdict                |
| POST   | `/api/v1/findings/{fp}/comments`                    | Add a comment                               |
| DELETE | `/api/v1/findings/{fp}/comments/{id}`               | Delete a comment                            |
| PATCH  | `/api/v1/notifications/{id}/read`                   | Mark one notification read                  |
| PATCH  | `/api/v1/notifications/read-all`                    | Bulk mark notifications read                |
| POST   | `/api/v1/dashboard/install/{scanner}`               | Install a supported scanner                 |

### Admin scope

| Method | Path                                                | Notes                                       |
| ------ | --------------------------------------------------- | ------------------------------------------- |
| POST   | `/api/v1/keys`                                      | Issue a new API key                         |
| GET    | `/api/v1/keys`                                      | List all keys                               |
| DELETE | `/api/v1/keys/{id}`                                 | Revoke a key (lockout-protected)            |
| POST   | `/api/v1/webhooks`                                  | Create a webhook subscription               |
| GET    | `/api/v1/webhooks`                                  | List webhooks                               |
| GET    | `/api/v1/webhooks/{id}`                             | Fetch one webhook                           |
| PATCH  | `/api/v1/webhooks/{id}`                             | Edit a webhook (cannot rotate secret)       |
| DELETE | `/api/v1/webhooks/{id}`                             | Delete a webhook + cascade deliveries       |
| GET    | `/api/v1/webhooks/{id}/deliveries`                  | Last 100 delivery rows                      |
| POST   | `/api/v1/webhooks/{id}/test`                        | Fire a synthetic webhook.test               |

```admonish warning title="Webhooks are admin-only on read too"
There is **no read-scope view** of webhooks in v0.9.0. An attacker
with `read` cannot see webhook URLs or delivery history; an
attacker with `write` cannot redirect events to a sink they
control. Only `admin` does. The `/settings/webhooks` dashboard page
is the only intended consumer.
```

## Special cases

### `GET /api/v1/keys/me`

Carries no `require_scope` dependency — any authenticated DB key can
introspect itself. The handler returns the calling key's metadata
(no secret, just the prefix + scopes + timestamps).

### `GET /api/v1/scans/{id}/events`

Declared with `Depends(require_scope("read"))`, but the auth path
also accepts `?event_token=...` because browsers can't send
`X-API-Key` on `EventSource`. The token is bound to the caller's
`key_id`; the rehydrated principal carries that key's scopes. See
[SSE event tokens](./event-tokens.md).

## OR semantics

`Depends(require_scope("read", "admin"))` accepts a key with **either**
`read` or `admin`. If you need AND semantics (key must have both),
declare two separate dependencies — but the v0.9.0 surface does not
use AND anywhere.

## Scope check failure

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{"detail": "Requires scope: admin"}
```

403 (not 401) because the caller is authenticated; they just don't
have the right permissions. Returns `Requires scope: <scope>` so
operators can quickly diagnose missing-scope issues.

## Dev mode behavior

When the system has no env-var key AND no DB keys, every request
arrives with `request.state.principal = None`. `require_scope(...)`
**fails open** in this case — local development is not blocked by
scope checks.

`require_api_key` has already enforced the
"`AUTH_REQUIRED=1` with no creds" case as 503; so when
`require_scope` sees `principal is None` it knows the system is
genuinely in dev mode, not in a misconfigured production state.

## Changing scopes on an existing key

Not supported. Scopes are set at issuance. To change scopes:

1. Issue a new key with the right scopes.
2. Update the consumer to use the new key.
3. Revoke the old one.

This is on purpose. A "PATCH key scopes" endpoint would be a fast
privilege-escalation if an admin key was ever leaked and a
reasonable-looking write-scope-only key carried the leak by quietly
elevating in-place.

## Source

- `auth.py::require_scope` — dependency factory + the
  `__securescan_scope__` marker that the regression test uses.
- `tests/test_scopes.py::test_all_routes_have_explicit_scope` — the
  enforcement.

## Next

- [API keys](./api-keys.md) — issuing, revoking, scoping at issuance.
- [Production checklist](./production-checklist.md).
