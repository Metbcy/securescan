# pre-commit hook

SecureScan ships a [pre-commit](https://pre-commit.com/) hook for the
fast pre-commit feedback loop. Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Metbcy/securescan
    rev: v0.11.0
    hooks:
      - id: securescan
```

Then `pre-commit install` and `pre-commit run --all-files`. From here
on, every `git commit` will run SecureScan on the staged changes.

## What it scans

Only files in `git diff --cached --name-only`. The full repo is NOT
re-scanned on every commit; for that, run `securescan scan .` directly
or use the GitHub Action.

## Performance

The hook is amd64-only Python and skips heavyweight scanners when no
staged file matches their target type. Typical run is sub-3s on small
projects. If yours runs slow, narrow scan-types in your `.securescan.yml`.

## Suppression

Triage state, inline `securescan: ignore` comments, and the baseline
file all apply to the hook the same way they apply to `securescan
scan`. See [Suppression](../scanning/suppression.md).
