# vs Trivy

## TL;DR

SecureScan *wraps* [Trivy](https://trivy.dev/). If you already use Trivy
and just want a unified PR loop on top of it, SecureScan is the right
next step. If you only need Trivy's coverage (SCA, IaC, container,
secrets), use Trivy alone — it's a single binary and it's excellent at
what it does.

## What Trivy does

Trivy is the de-facto open-source scanner for software composition
analysis (SCA), infrastructure-as-code (IaC), container images,
filesystem scans, and basic secrets detection. It ships as a single Go
binary, has a large vulnerability database, and is fast. For many teams
whose only need is "scan our containers and lockfiles", Trivy alone is
enough.

## What SecureScan adds

SecureScan runs Trivy as one of 14 scanners. Around it, SecureScan adds
code SAST (Semgrep, Bandit), dedicated secrets detection,
infrastructure-as-code policies (Checkov), DAST against live web apps
(OWASP ZAP), network discovery (nmap), and others. On top of that
layer, SecureScan adds a diff-aware PR loop: every finding is
classified `NEW` / `FIXED` / `UNCHANGED` against the PR's base, and a
single PR comment is upserted (not appended) on every push. Findings
have stable fingerprints (v0.6.0+) so triage state survives rescans
(v0.7.0+), and SARIF output is byte-deterministic for CI use.

## Capability matrix

| Capability                                  | Trivy alone   | SecureScan (wraps Trivy)           |
| ------------------------------------------- | ------------- | ---------------------------------- |
| SCA / IaC / container scan                  | ✅            | ✅ (via Trivy)                     |
| Code SAST (Python, JS, Go, …)               | ❌            | ✅ (via Semgrep, Bandit)           |
| Secrets detection                           | ✅ basic      | ✅ (Trivy + dedicated scanner)     |
| DAST (live web app)                         | ❌            | ✅ (via OWASP ZAP)                 |
| Network scan                                | ❌            | ✅ (via nmap)                      |
| Diff-aware PR comment                       | ❌            | ✅                                 |
| Single upserted PR comment                  | ❌            | ✅                                 |
| Web dashboard                               | ❌            | ✅                                 |
| Triage state + comments                     | ❌            | ✅ (v0.7.0+)                       |
| Determinism (sorted, stable fingerprints)   | partial       | ✅                                 |
| OSS license                                 | Apache-2.0    | Apache-2.0                         |

## When to pick Trivy alone

Pick Trivy alone if your CI surface is intentionally minimal, you only
need SCA/IaC/container/secrets coverage, you don't want to host a
dashboard, you prefer a single static binary, and you don't need
diff-aware classification on PRs. Trivy is a sharp tool that does its
job well; adding SecureScan to that picture is overhead you don't need.

## When to pick SecureScan

Pick SecureScan if you want diff-aware PR comments that show only what
the change introduced, code SAST in addition to SCA, a dashboard for
triage and history, and a triage workflow that survives rescans. The
trade-off is operating one more service.

## Using both intentionally

Nothing wrong with running both. A common split: Trivy inside the
container image build as a hard gate on the final artifact, SecureScan
at PR-time across the whole repo for developer feedback. Different
cadences, different audiences, no real overlap.
