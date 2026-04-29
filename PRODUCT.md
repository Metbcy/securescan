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
