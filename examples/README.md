# SecureScan examples

Copy-pasteable starting points for adopting SecureScan v0.2.0 in your CI
or local workflow. Pick the file that matches your trust model and
deployment constraints.

| File | Use when |
| --- | --- |
| [`github-action.yml`](./github-action.yml) | Recommended `Metbcy/securescan@v1` path -- the no-friction wrapper that posts an upserted PR comment and uploads SARIF. |
| [`github-action-docker.yml`](./github-action-docker.yml) | Explicit container path (no third-party action). For teams that can't run non-trusted actions and want to invoke `ghcr.io/metbcy/securescan` directly. |
| [`local-snapshot-diff.sh`](./local-snapshot-diff.sh) | Local two-branch diff outside CI -- snapshot two branches with `securescan scan`, then classify with `securescan diff`. |

## Version pinning

- The two workflow examples target `Metbcy/securescan@v1` (mutable major
  tag) and `ghcr.io/metbcy/securescan:v0.2.0` (immutable release tag).
- Use the immutable tag when reproducibility matters; use `:latest` or
  `@v1` to track new releases automatically.

## Required permissions

All workflow examples request:

- `contents: read` -- checkout
- `pull-requests: write` -- upserted PR comment
- `security-events: write` -- SARIF upload to the Security tab

And use `actions/checkout@v4` with `fetch-depth: 0`, since the diff
classifier needs the base ref's history.
