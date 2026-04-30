# SecureScan

> Self-hosted security-scanning orchestrator: 14 scanners across code,
> dependencies, IaC, containers, secrets, DAST, and network targets,
> normalized into a single deterministic finding stream — fronted by a
> CLI, a GitHub Action, and a web dashboard.

This is the operator + developer reference for SecureScan
**v0.9.0**. If you have not used SecureScan before,
[**Quick start: your first scan**](./quick-start.md) is the place to begin.

## What you can do with SecureScan

- **Run diff-aware scans on every PR.** The `Metbcy/securescan@v1`
  GitHub Action wraps `securescan diff`, posts a single upserted PR
  comment of NEW findings, and uploads SARIF to GitHub's Security tab.
  See [GitHub Action](./cli/github-action.md).
- **Triage findings across rescans.** Each finding has a stable
  fingerprint, so verdicts (`false_positive`, `accepted_risk`, `fixed`,
  …) and per-finding comments survive `DELETE /scans/{id}` and reappear
  on every later scan of the same target. See
  [Triage workflow](./scanning/triage.md).
- **Watch scans in real time.** The dashboard's scan-detail page
  streams live per-scanner progress over Server-Sent Events. See
  [Real-time scan progress](./dashboard/realtime.md).
- **Fan out events to your tools.** Outbound webhooks deliver
  HMAC-signed `scan.complete` / `scan.failed` / `scanner.failed`
  events to Slack, Discord, or any HTTP receiver, with a durable
  retry queue. See [Webhooks](./dashboard/webhooks.md).
- **Issue scoped, hashed API keys.** v0.8.0 replaces the single shared
  env-var key with DB-backed keys carrying explicit `read` / `write` /
  `admin` scopes per route. See [API keys](./auth/api-keys.md).

## Audience

This documentation is for three readers, in roughly that order:

| Reader              | What they need                                                                                                        | Start here                                                                                |
| ------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| **Operator**        | Install, configure, harden, deploy, and maintain SecureScan in their org. Health probes, env vars, signed artifacts.  | [Install](./install.md) → [Production checklist](./deployment/production-checklist.md)    |
| **Developer**       | Talk to the API. Ship a PR scan. Verify webhook signatures.                                                           | [API overview](./api/overview.md) → [Webhook payloads](./api/webhook-payloads.md)         |
| **Security team**   | Understand what SecureScan covers, what it deliberately does not, and how findings are scored / suppressed / triaged. | [Scan types](./scanning/scan-types.md) → [Supported scanners](./scanning/supported-scanners.md) |

## What this is not

SecureScan is intentionally **not** a SaaS, not an SBOM database, and
not a vulnerability database in its own right. It orchestrates the
open-source scanners you already trust (Semgrep, Bandit, Trivy,
Checkov, ZAP, nmap, …), normalizes their output into a single shape,
and adds diff-awareness, signed artifacts, and a deterministic
serialization contract on top. See
[Architecture overview](./architecture.md) for the full picture.

## Project links

- Source: [github.com/Metbcy/securescan](https://github.com/Metbcy/securescan)
- Container image: `ghcr.io/metbcy/securescan`
- PyPI: [`pip install securescan`](https://pypi.org/project/securescan/)
- Changelog: [reference/changelog](./reference/changelog.md)
- Release process: [reference/release-process](./reference/release-process.md)

```admonish tip title="Auto-generated API docs"
This site documents the **stable** public API surface and the
operational behavior. For the full request/response schema of every
endpoint — including the schemas you will not find here — point your
browser at the running server's `/docs` (FastAPI Swagger UI) or
`/redoc`. See [API endpoints](./api/endpoints.md) for the entry point.
```
