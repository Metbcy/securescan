# SecureScan GitHub Action

Diff-aware security scan for pull requests. Wraps `securescan diff`,
posts a single upserted PR comment, and uploads SARIF to the GitHub
Security tab.

## What you get from one `uses:` block

- A PR comment listing only the **new** findings introduced by the PR
  (no spam from pre-existing legacy issues).
- The same comment **upserted** on every push to the PR branch -- the
  marker `<!-- securescan:diff -->` keeps it a single comment instead
  of accumulating one per push.
- SARIF upload to the **Security** tab, even when the action exits
  non-zero because of `fail-on-severity`.
- Wheel-first, container-fallback execution. The action tries
  `pip install securescan` into an isolated venv first; if that fails
  (or if `prefer-image: true`), it falls back to running
  `ghcr.io/metbcy/securescan:<image-tag>`.

## Quick start

```yaml
on: pull_request

permissions:
  contents: read
  pull-requests: write    # required for the upserted PR comment
  security-events: write  # required for SARIF upload

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

## Inputs

| Input              | Default          | Description                                                                                       |
| ------------------ | ---------------- | ------------------------------------------------------------------------------------------------- |
| `base-ref`         | PR `base.sha`    | Git ref for the "before" side. On `pull_request` defaults to the PR base sha.                     |
| `head-ref`         | PR `head.sha`    | Git ref for the "after" side. On `pull_request` defaults to the PR head sha (immutable).          |
| `scan-types`       | `code`           | Comma-separated scanners: `code,dependency,iac,baseline,dast,network`.                            |
| `fail-on-severity` | `none`           | Exit non-zero if any **new** finding is at or above this severity (`critical|high|medium|low`).   |
| `comment-on-pr`    | `true`           | Post the diff as a PR comment (upserted via marker). Auto-skipped on non-`pull_request` events.   |
| `upload-sarif`     | `true`           | Upload SARIF to the GitHub Security tab. Runs even when the diff exits non-zero.                  |
| `image-tag`        | `latest`         | Tag of `ghcr.io/metbcy/securescan` to use when falling back to the container.                     |
| `prefer-image`     | `false`          | Skip the wheel install path and always run the container image.                                   |
| `baseline`         | (none)           | Path (relative to repo root) of a baseline JSON file to suppress legacy findings on **both** sides. |
| `github-token`     | `${{ github.token }}` | Token used for PR comment upsert.                                                            |
| `pr-mode`          | `summary`        | Where to post the diff: `summary` (single PR comment, the v0.2.0 default), `inline` (one GitHub Review with one comment per finding anchored at the offending line), or `both`. Inline modes require a `pull_request` event. |
| `review-event`     | `COMMENT`        | GitHub Reviews API event when `pr-mode` includes inline submission: `COMMENT`, `REQUEST_CHANGES`, or `APPROVE`. `COMMENT` is the default to avoid silently blocking merges via branch protection. |
| `inline-suggestions` | `true`         | Include suggestion blocks (one-click apply) in inline review comments where SecureScan can construct a mechanical fix. Set to `false` for compact comment bodies. |

## Outputs

The action writes two artefacts to `${GITHUB_WORKSPACE}/.securescan/`:

- `diff.md` -- the rendered PR comment body (also posted by the action).
- `diff.sarif` -- the SARIF document uploaded to the Security tab.

When `pr-mode` is `inline` or `both`, the action additionally writes:

- `review.json` -- the GitHub Reviews API payload (the body submitted by
  the action; useful to inspect or diff between runs).

You can `actions/upload-artifact` either of these if you want to keep
them around longer than the run.

## PR comment modes

`pr-mode` selects where SecureScan posts the diff. The default `summary`
preserves v0.2.0/v0.3.0 single-comment behaviour for every existing
caller; opt into the new modes by setting the input explicitly.

- **`summary`** (default) -- one PR comment summarising every new
  finding, upserted on each push via the `<!-- securescan:diff -->`
  marker. Backward-compatible with v0.2.0 callers.
- **`inline`** -- a single GitHub Review with one inline comment per
  finding anchored at the offending line. Findings whose line is outside
  the PR's diff fall back into the review body. Each comment carries a
  hidden fingerprint trailer so re-runs edit the existing comment instead
  of duplicating it.
- **`both`** -- posts the summary comment AND the inline review. Useful
  for repos that want a high-level overview in `Conversation` plus
  per-line context in the `Files changed` tab.

```yaml
- uses: Metbcy/securescan@v1
  with:
    pr-mode: inline
    review-event: COMMENT          # or REQUEST_CHANGES to block merge
    inline-suggestions: 'true'     # one-click apply for mechanical fixes
```

`pr-mode: inline` and `pr-mode: both` require a `pull_request` event
payload (the inline anchors need the PR's diff). On any other event
SecureScan logs a warning and skips the inline submission rather than
failing the workflow; the summary path (when `pr-mode` is `summary` or
`both`) continues to follow the existing `pull_request`-only gate.

`review-event: COMMENT` is the default. `REQUEST_CHANGES` blocks merging
when the repo has branch protection requiring approving reviews, which
is great for some workflows and hostile in others -- pick it
deliberately.

## Pinning

For production, pin to a specific image tag rather than relying on the
default `latest`:

```yaml
- uses: Metbcy/securescan@v1
  with:
    image-tag: v0.2.0
```

## How it works

1. **Resolve refs** -- if `base-ref`/`head-ref` are blank, fill them
   from `pull_request.base.sha` / `pull_request.head.sha`.
2. **Pick runtime** -- try `pip install securescan` into a venv. If
   that succeeds, use the wheel; otherwise fall back to
   `ghcr.io/metbcy/securescan:<image-tag>` via `docker run`.
3. **Run `securescan diff` twice** -- once with
   `--output github-pr-comment` (writes `diff.md`), once with
   `--output sarif` (writes `diff.sarif`). Two passes mean a
   `--fail-on-severity` non-zero exit on the comment pass does not
   skip the SARIF artefact.
4. **Upsert the PR comment** -- look up existing comments on the PR
   that start with `<!-- securescan:diff -->`; PATCH if found, POST
   otherwise. Uses raw `curl` against the REST API so the action
   works on minimal self-hosted runners that do not have the `gh`
   CLI installed.
5. **Upload SARIF** -- delegates to `github/codeql-action/upload-sarif@v3`,
   guarded by `if: always() && inputs.upload-sarif == 'true'` so the
   upload happens even on a non-zero diff exit.

## Permissions

| Permission               | Why                                |
| ------------------------ | ---------------------------------- |
| `contents: read`         | Checkout + diff against base.      |
| `pull-requests: write`   | Create / update the PR comment AND submit inline reviews (the GitHub Reviews API uses the same scope as issue comments -- no extra permission needed for `pr-mode: inline` or `both`). |
| `security-events: write` | Upload SARIF to the Security tab.  |

## Local self-test

`action/test-resolve.sh` exercises `entrypoint-resolve.sh` against
synthetic event payloads. `action/test-pr-mode.sh` exercises
`entrypoint.sh`'s `pr-mode` dispatch (summary / inline / both, plus the
non-PR-event guard). Run them from the repo root:

```bash
bash action/test-resolve.sh
bash action/test-pr-mode.sh
```
