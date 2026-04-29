# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

<!-- New features land here on each PR. -->

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

[Unreleased]: https://github.com/Metbcy/securescan/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Metbcy/securescan/releases/tag/v0.4.0
[0.3.0]: https://github.com/Metbcy/securescan/releases/tag/v0.3.0
[0.2.0]: https://github.com/Metbcy/securescan/releases/tag/v0.2.0
[0.1.0]: https://github.com/Metbcy/securescan/releases/tag/v0.1.0
