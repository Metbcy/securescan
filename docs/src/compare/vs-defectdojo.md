# vs DefectDojo

## TL;DR

DefectDojo and SecureScan solve different problems. [DefectDojo](https://www.defectdojo.org/)
is a vulnerability-management hub that ingests findings from many tools.
SecureScan is a PR-loop scanner that runs the tools and posts a
diff-aware PR comment. Many teams use both.

## What each tool is

**DefectDojo** is a *vulnerability management* platform. Its job starts
once findings already exist: import them from 150+ scanners, deduplicate,
assign owners, track remediation SLAs, and report across products and
engagements. It does not run scanners itself in any first-class way; it
consumes their output.

**SecureScan** is a *scan orchestration with PR feedback* tool. Its job
is to run 14 scanners (Semgrep, Bandit, Trivy, Checkov, ZAP, nmap, and
others) against a target, classify the resulting findings as
`NEW` / `FIXED` / `UNCHANGED` against the PR's base ref, and upsert a
single GitHub PR comment so the developer who opened the PR sees only
what their change introduced.

## Where they overlap

Both surface findings, both have a web UI, both speak SARIF, and both
support a triage workflow with status and comments
(SecureScan's triage shipped in v0.7.0). The overlap is shallow: they
sit at different points in the security lifecycle.

## Where they don't

| Capability                                  | DefectDojo            | SecureScan                |
| ------------------------------------------- | --------------------- | ------------------------- |
| Aggregate findings from external tools      | ✅ first-class        | ❌ runs scanners directly |
| Diff-aware NEW/FIXED/UNCHANGED on PRs       | ❌                    | ✅                        |
| Single upserted PR comment                  | ❌                    | ✅                        |
| Triage workflow (status + comments)         | ✅ mature             | ✅ v0.7.0+                |
| User/role management                        | ✅ first-class        | ❌ single-tenant + API keys |
| Stable across-runs fingerprints             | ❌                    | ✅                        |
| OSS license                                 | BSD-3                 | Apache-2.0                |

## Using both

The two tools compose cleanly. SecureScan emits deterministic SARIF on
every scan; DefectDojo has a SARIF importer. A common arrangement: the
GitHub Action runs SecureScan on every PR (developer-facing PR loop),
and a nightly job re-imports the latest scan's SARIF into DefectDojo for
portfolio-level tracking, SLA reporting, and cross-product views. The PR
loop stays fast and local; the long-term ledger lives in DefectDojo.

## When to pick which

- **Just SecureScan**: small or mid-size engineering org, dev-first PR
  feedback is the priority, no existing central vuln-management
  practice yet, single team or single product.
- **Just DefectDojo**: large engineering org with established scanners
  already wired into CI, a security team that owns triage centrally,
  and an existing PR-comment story that the team is happy with.
- **Both**: SecureScan owns the dev-time PR loop (NEW/FIXED on every
  push), DefectDojo owns the long-term portfolio view (SLAs,
  engagements, cross-product reporting).

The choice is not adversarial. SecureScan does not aim to replace
DefectDojo, and DefectDojo does not aim to replace the PR-loop. Pick
the one that fits the gap you actually have today.
