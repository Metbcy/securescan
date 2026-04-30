# Glossary

Terms used across the SecureScan documentation, codebase, and PRs.

<!-- toc -->

## A — D

**Admin scope.** The highest of the three [scope](../auth/scopes.md)
levels. Grants API-key management and webhook management in addition
to read+write. Reserve for one operator break-glass identity.

**Audit trail.** The structured record of who did what to a finding —
`metadata.suppressed_by` for suppression, `finding_states.updated_by`
for triage verdicts, comments thread for discussion. SecureScan does
not delete this record on rescan or on `DELETE /scans/{id}`.

**Backplane.** The hypothetical multi-process pubsub layer (Redis or
similar) that would let SecureScan run multiple uvicorn workers /
instances without losing SSE or webhook FIFO ordering. Roadmap;
v0.9.0 is in-process only. See
[Single-worker constraint](../deployment/single-worker.md).

**Baseline.** A canonicalized, byte-deterministic JSON snapshot of a
scan's findings, used to suppress legacy findings on later runs. See
[Suppression → baseline](../scanning/suppression.md#3-baseline-legacy-findings).
Distinct from the **baseline scanner**, the host-config audit family.

**Compliance tag.** A string like `OWASP-A03`, `PCI-DSS-6.5.1`,
`SOC2-CC7.1` attached to a finding. Computed by the compliance mapper
from CWE / rule_id / keywords. See [Compliance](../scanning/compliance.md).

**DAST.** Dynamic Application Security Testing. Runs against a
**live URL**. SecureScan ships `builtin_dast` (header / cookie /
info-disclosure) and `zap` (full ZAP active+passive). Contrast with
SAST, which runs against source code.

**Determinism contract.** SecureScan's promise that every renderer
produces byte-identical output for the same inputs. Foundational for
the PR-comment upsert and SARIF Security-tab dedup. See
[Architecture: determinism contract](../architecture.md#determinism-contract).

**Dev mode.** Backend mode when no env-var key AND no DB keys are
configured AND `SECURESCAN_AUTH_REQUIRED=0`. Every request passes
through; scope checks fail-open. Convenient for local dev,
unacceptable for anything else. See
[Authentication overview](../auth/overview.md#dev-mode).

## E — H

**Event bus.** The in-process pub/sub powering SSE live progress.
Module-level singleton; one per uvicorn worker. Source:
`backend/securescan/events.py`. See
[Real-time scan progress](../dashboard/realtime.md).

**Event token.** A short-lived (5-minute) HMAC-signed token that
authorizes one specific scan's SSE stream. Exists because browsers
cannot send custom headers on `EventSource`. See
[SSE event tokens](../auth/event-tokens.md).

**Fingerprint.** A SHA-256 over
`(scanner | rule_id | file_path | normalized_line_context | cwe)`,
stable across scans of the same target. The cross-scan identity for
findings; what triage state, comments, and SARIF
`partialFingerprints` are keyed on. See
[Findings & severity](../scanning/findings-severity.md#fingerprints--cross-scan-identity).

**FIFO ordering (per webhook).** SecureScan's promise that two
deliveries to the same webhook subscription are processed in
`created_at` order. Different webhooks dispatch concurrently. See
[Webhooks](../dashboard/webhooks.md#retry--state-machine).

**Health probe.** `/health` (liveness — process up) and `/ready`
(readiness — DB + scanners loaded). Both public regardless of auth.

## I — L

**IaC.** Infrastructure as Code. SecureScan's `iac` scan type covers
Terraform, Kubernetes, Helm, CloudFormation, and Dockerfiles via
`checkov` and `dockerfile` scanners.

**Inline ignore.** A `# securescan: ignore RULE-ID` (or `// securescan: ignore-next-line ...`)
comment on the line a finding fires for, suppressing it. The most
local of the three suppression mechanisms. See
[Suppression](../scanning/suppression.md#1-inline-ignore-comments).

**Inline review mode.** The `pr-mode: inline` GitHub Action setting
that posts findings as inline review comments anchored on the
affected lines, instead of a single summary comment. See
[GitHub Action](../cli/github-action.md#pr-mode-summary-inline-both).

**Lockout protection.** The 409 response from `DELETE /api/v1/keys/{id}`
when revoking would zero out admin credentials and the env-var
fallback is unset. Prevents the operator from locking themselves out.

## M — P

**OKLCH.** The OKLab cylindrical color space used for SecureScan's
design tokens. The `--accent`, `--bg`, severity-ramp colors are all
expressed in OKLCH for predictable contrast. See
[`DESIGN.md`](https://github.com/Metbcy/securescan/blob/main/DESIGN.md).

**Orchestrator.** The asyncio task started by `POST /api/v1/scans`
that drives scanner subprocesses, captures their output, persists
findings, and emits lifecycle events. Source: `_run_scan` in
`backend/securescan/api/scans.py`.

**Principal.** The authenticated caller's identity. A dataclass with
`(id, scopes, source)` where `source` is `"env"`, `"db"`, or `"dev"`.
Stashed on `request.state.principal` for downstream use. See
`backend/securescan/auth.py`.

## R — S

**Read scope.** The lowest of the three scopes. Lets the caller list
scans, read findings, view SBOM, see notifications. Cannot start a
scan or set triage. See [Scopes](../auth/scopes.md).

**Replay buffer.** A 200-event buffer per scan that lets a late SSE
subscriber (tab refresh mid-scan) reconstruct full state. Retained
30s after a terminal event. See
[Real-time scan progress → replay buffer](../dashboard/realtime.md#replay-buffer).

**SAST.** Static Application Security Testing. Runs against source
files (no execution). SecureScan's `code` scan type — semgrep,
bandit, secrets, git-hygiene.

**SBOM.** Software Bill of Materials. SecureScan generates CycloneDX
1.5 and SPDX 2.3. See [SBOM](../dashboard/sbom.md).

**Scope.** A capability declaration on an API key — `read`, `write`,
or `admin`. Each route declares which scopes it accepts. See
[Scopes](../auth/scopes.md).

**SSE.** Server-Sent Events. SecureScan's mechanism for streaming
live scan progress to the dashboard. One-way server-to-client;
compatible with the browser's `EventSource` API.

**Sticky session.** A load-balancer pattern that hashes a request
attribute (e.g. `scan_id`) to consistently route to one backend
instance. Required when scaling SecureScan horizontally because the
event bus is per-instance.

**Suppression.** Filtering a finding out of CI output. Three
mechanisms with fixed precedence: inline > config > baseline. See
[Suppression](../scanning/suppression.md). Distinct from
**triage**, which records a verdict.

## T — Z

**Triage.** Recording a human verdict on a finding (`new`,
`triaged`, `false_positive`, `accepted_risk`, `fixed`, `wont_fix`).
Per-fingerprint, durable across rescans. See
[Triage workflow](../scanning/triage.md).

**Upsert marker.** An HTML comment in a PR comment body
(`<!-- securescan:diff -->`) that lets the action find and update
its existing comment instead of posting a new one each push. See
[GitHub Action](../cli/github-action.md).

**Webhook.** An outbound HMAC-signed HTTP delivery of a scan
lifecycle event. v0.9.0 feature. See
[Webhooks](../dashboard/webhooks.md).

**Webhook delivery.** A row in `webhook_deliveries`. Persisted
*before* the HTTP call so retries survive backend restarts.

**Write scope.** The middle scope. Adds: start / cancel / delete
scans, set triage state, mark notifications read. The default for a
new key alongside `read`. See [Scopes](../auth/scopes.md).

**ZAP.** OWASP Zed Attack Proxy. SecureScan's `zap` scanner connects
to a separately-running ZAP daemon. Not bundled in the container
because of size; install on the host or run as a sidecar.

## Acronyms

| Acronym  | Stands for                                                |
| -------- | --------------------------------------------------------- |
| CWE      | Common Weakness Enumeration                               |
| CVE      | Common Vulnerabilities and Exposures                      |
| DAST     | Dynamic Application Security Testing                      |
| HMAC     | Hash-based Message Authentication Code                    |
| IaC      | Infrastructure as Code                                    |
| OIDC     | OpenID Connect                                            |
| OKLCH    | OKLab cylindrical color space                             |
| PCI-DSS  | Payment Card Industry Data Security Standard              |
| OWASP    | Open Worldwide Application Security Project               |
| SARIF    | Static Analysis Results Interchange Format                |
| SAST     | Static Application Security Testing                       |
| SBOM     | Software Bill of Materials                                |
| SOC 2    | Service Organization Control 2                            |
| SSE      | Server-Sent Events                                        |
| TLS      | Transport Layer Security                                  |

## Next

- [FAQ](./faq.md) — frequently asked questions.
- [Changelog](./changelog.md) — the term-introducing-release record.
