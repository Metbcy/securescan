# GitHub Action

The `Metbcy/securescan@v1` composite action wraps `securescan diff`,
posts the upserted PR comment, and uploads SARIF to GitHub's Security
tab. It tries the wheel first and falls back to the pinned container
image when scanner binaries are not on `PATH`.

Action source:
[`action/`](https://github.com/Metbcy/securescan/tree/main/action).

<!-- toc -->

## Minimum example

```yaml
# .github/workflows/securescan.yml
on: pull_request

permissions:
  contents: read
  pull-requests: write    # required for the upserted PR comment
  security-events: write  # required for SARIF upload to the Security tab

jobs:
  securescan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # diff needs both base and head commits
      - uses: Metbcy/securescan@v1
        with:
          scan-types: code,dependency
          fail-on-severity: high
```

That's the full integration. The action:

1. Checks out both refs (base + head).
2. Runs `securescan diff` against them.
3. Posts a PR comment with NEW findings (upserted via the
   `<!-- securescan:diff -->` marker — one comment per PR, updated
   in place).
4. Uploads SARIF to the Security tab.
5. Exits non-zero if NEW findings exist at `>= fail-on-severity`.

## Inputs

| Input                  | Default     | Description                                                                                                  |
| ---------------------- | ----------- | ------------------------------------------------------------------------------------------------------------ |
| `base-ref`             | PR base sha | Git ref to diff from. Auto-resolved from the PR event payload.                                               |
| `head-ref`             | PR head sha | Git ref to diff to. Auto-resolved from the PR event payload.                                                 |
| `scan-types`           | `code`      | Comma-separated: `code,dependency,iac,baseline,dast,network`.                                                |
| `fail-on-severity`     | `none`      | Exit non-zero if NEW findings >= this severity. `none\|critical\|high\|medium\|low`.                          |
| `comment-on-pr`        | `true`      | Post the diff as a PR comment.                                                                               |
| `upload-sarif`         | `true`      | Upload SARIF to the Security tab.                                                                            |
| `image-tag`            | `latest`    | Tag of `ghcr.io/metbcy/securescan` to use when falling back to the container.                                |
| `prefer-image`         | `false`     | Skip the wheel install path; always run the container.                                                       |
| `baseline`             | (none)      | Path to a baseline JSON to suppress legacy findings.                                                         |
| `github-token`         | `GITHUB_TOKEN` | Token used for PR comment upsert.                                                                         |
| `pr-mode`              | `summary`   | `summary` (one PR comment) / `inline` (inline-anchored review) / `both`.                                     |
| `review-event`         | `COMMENT`   | When `pr-mode` includes inline: `COMMENT` / `REQUEST_CHANGES` / `APPROVE`.                                   |
| `inline-suggestions`   | `true`      | Include `\`\`\`suggestion` blocks for one-click inline-ignore / severity-pin.                               |

The full `inputs:` declaration is in
[`action/action.yml`](https://github.com/Metbcy/securescan/blob/main/action/action.yml).

## PR mode: summary, inline, both

```admonish tip title="Pick one based on how reviewers triage"
**`summary`** (default) is one upserted PR comment listing every
NEW finding. Best for: dashboards, single-reviewer PRs, finding
counts that fit in one comment.

**`inline`** posts a GitHub Review with one inline comment anchored
on each affected line. Best for: many reviewers triaging
independently, larger PRs where individual resolution matters,
teams that already use GitHub Review threads.

**`both`** posts both surfaces. The summary lives in the
conversation tab; inline comments live in files-changed. Use this
when you want the "what's the headline finding count" surface AND
per-finding resolution.
```

### Inline mode example

```yaml
- uses: Metbcy/securescan@v1
  with:
    pr-mode: inline
    review-event: COMMENT          # COMMENT | REQUEST_CHANGES | APPROVE
    inline-suggestions: true       # one-click ignore / severity-pin
```

How inline mode behaves:

1. **Diff resolution.** SecureScan reads `git diff <base>..<head>` to
   compute each finding's *position* — GitHub's offset-into-the-PR-diff
   coordinate, not the source line number.
2. **Findings outside the diff fall back to the review body** so
   they're not silently dropped.
3. **Suggestion blocks** (when `inline-suggestions: true`):
   - For findings the reviewer can suppress, SecureScan offers a
     one-click `\`\`\`suggestion` block adding
     `# securescan: ignore <rule_id>` above the line.
   - For findings whose severity is wrong for this codebase,
     SecureScan shows a copy-paste `severity_overrides:` snippet for
     `.securescan.yml`.
4. **Idempotent re-runs.** Each comment carries a hidden
   `<!-- securescan:fp:<prefix> -->` marker. On re-runs, SecureScan
   PATCHes existing comments instead of posting duplicates —
   reviewer reply threads survive.
5. **Resolved findings are marked, not deleted.** When a finding
   disappears from a re-run, its comment is patched to
   `**Resolved in <sha7>** — finding no longer present` with the
   original body strikethrough'd. Manual resolution by the reviewer
   is honored — we do NOT call GraphQL `resolveReviewThread`.

### Summary vs inline at a glance

|                                     | summary                | inline                                | both              |
| ----------------------------------- | ---------------------- | ------------------------------------- | ----------------- |
| Comment count                       | 1 (upserted)           | 1 review with N inline comments       | summary + inline  |
| Reviewer can resolve per-finding    | No                     | Yes                                   | Yes (inline)      |
| Findings on touched code only       | All                    | Only lines in PR's diff               | summary covers all|
| Findings outside touched code       | In the comment         | Review body fallback                  | covered both ways |
| Suggestion blocks                   | No                     | Yes (when enabled)                    | Yes (inline only) |

## Permissions

The action's permissions are controlled by the workflow YAML — set
the right ones at the workflow level:

```yaml
permissions:
  contents: read
  pull-requests: write   # both summary comment AND inline review submission
  security-events: write # for SARIF upload (if upload-sarif is true)
```

`pull-requests: write` is required for both `summary` and `inline`
modes. Without it, the action will fail at the comment / review POST
step.

## Pinning

`Metbcy/securescan@v1` is the **floating major-version tag** —
auto-tracks the latest `v1.x.y` stable release. Recommended for most
users.

`Metbcy/securescan@v0.10.3` (or any specific `vX.Y.Z`) is the
**immutable per-release pin** — use it when you want reproducible
CI behavior and explicit upgrades:

```yaml
- uses: Metbcy/securescan@v0.10.3   # pinned; you control upgrades
```

## Examples

### Multi-type scan with custom baseline

```yaml
- uses: Metbcy/securescan@v1
  with:
    scan-types: code,dependency,iac
    fail-on-severity: high
    baseline: .securescan/baseline.json
```

### Inline mode, request-changes on critical

```yaml
- uses: Metbcy/securescan@v1
  with:
    pr-mode: inline
    review-event: REQUEST_CHANGES   # blocks merge if branch protection requires reviews
    fail-on-severity: critical
```

### Force the container path (slower; reproducible)

```yaml
- uses: Metbcy/securescan@v1
  with:
    prefer-image: true
    image-tag: v0.9.0
```

### Summary + inline together

```yaml
- uses: Metbcy/securescan@v1
  with:
    pr-mode: both
    inline-suggestions: true
```

## Local development of the inline-review path

To inspect what would be posted without running CI:

```bash
securescan diff . --base-ref main --head-ref HEAD \
  --output github-review --repo Metbcy/securescan \
  --output-file review.json
cat review.json | jq .
```

The CLI requires `--repo`, `--sha`, and `--base-sha` (auto-resolved
from `--base-ref`/`--head-ref` in a git working tree). It does NOT
post to GitHub on its own — that's the action's job.

## Source

- Action: [`action/action.yml`](https://github.com/Metbcy/securescan/blob/main/action/action.yml).
- Entry point script: [`action/entrypoint.sh`](https://github.com/Metbcy/securescan/blob/main/action/entrypoint.sh).
- Summary poster: [`action/post-pr-comment.sh`](https://github.com/Metbcy/securescan/blob/main/action/post-pr-comment.sh).
- Inline review poster: [`action/post-review.sh`](https://github.com/Metbcy/securescan/blob/main/action/post-review.sh).
- Examples: [`examples/github-action.yml`](https://github.com/Metbcy/securescan/blob/main/examples/github-action.yml).

## Next

- [Commands](./commands.md) — what `securescan diff` does on the wire.
- [Diff & compare](../dashboard/diff.md) — the model behind the action.
- [Findings & severity](../scanning/findings-severity.md#fingerprints--cross-scan-identity) — fingerprints stabilize comment threads.
