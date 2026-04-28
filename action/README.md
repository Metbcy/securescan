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

## Outputs

The action writes two artefacts to `${GITHUB_WORKSPACE}/.securescan/`:

- `diff.md` -- the rendered PR comment body (also posted by the action).
- `diff.sarif` -- the SARIF document uploaded to the Security tab.

You can `actions/upload-artifact` either of these if you want to keep
them around longer than the run.

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
| `pull-requests: write`   | Create / update the PR comment.    |
| `security-events: write` | Upload SARIF to the Security tab.  |

## Local self-test

`action/test-resolve.sh` exercises `entrypoint-resolve.sh` against
synthetic event payloads. Run it from the repo root:

```bash
bash action/test-resolve.sh
```
