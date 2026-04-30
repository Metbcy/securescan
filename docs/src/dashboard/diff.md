# Diff & compare

Two related surfaces, both built on the cross-scan
[fingerprint](../scanning/findings-severity.md#fingerprints--cross-scan-identity)
identity:

- **`securescan diff`** — what's NEW between two git refs (or two
  pre-scanned snapshots). The CI workhorse.
- **`securescan compare`** — what's drifted since a saved baseline.
  An auditing / triage surface.

The dashboard renders both at `/diff` and `/compare`.

<!-- toc -->

## diff (CLI)

```bash
# Ref mode — refs must exist in the local clone
securescan diff . --base-ref main --head-ref HEAD

# Snapshot mode — recommended for CI; no second checkout required
securescan diff . \
  --base-snapshot before.json \
  --head-snapshot after.json \
  --output github-pr-comment
```

The classifier produces three buckets keyed on fingerprint:

- **NEW** — present in head, absent from base.
- **FIXED** — present in base, absent from head.
- **UNCHANGED** — fingerprint in both.

Only NEW is reported by default in the github-pr-comment output —
that is the diff-aware-PR-comment property.

```admonish tip title="Snapshot mode is the right CI shape"
Each side of the diff runs `securescan scan ... --output json`
independently — possibly on different runners — and a single
classification step does the diff without re-checking-out the tree.
This decouples the heavy work from the diff logic and lets you cache
each side's snapshot.
```

See [CLI commands](../cli/commands.md#diff).

## diff (dashboard)

`/diff`: a PR-style scan-vs-scan comparison.

```text
PageHeader: Diff

Base:  [ scan picker ▾ ]   ↔   Head: [ scan picker ▾ ]
       0d2c... · 2026-04-29              0f1a... · 2026-04-29

Summary chips
  ▲ 3 new   ▼ 2 resolved   = 14 unchanged   Risk Δ +12.4

[ New (3) ] [ Resolved (2) ] [ Unchanged (14) ]   <- tabs

Findings table (severity-tinted, expandable rows)
  ● critical  Use of eval()                  backend/api.py:42       semgrep   ⌃
  ● high      SQL injection via str.format   backend/db.py:12        bandit    ⌃
  ● medium    Missing X-Frame-Options        (https://...)           dast      ⌃
```

Source: `frontend/src/app/diff/page.tsx` (FEAT1 from v0.6.0).

## compare (CLI)

```bash
# What disappeared since the last baseline?
securescan compare .securescan/baseline.json
```

`compare` classifies findings into:

- **NEW** — in current scan, not in baseline.
- **DISAPPEARED** — in baseline, not in current scan.
- **STILL_PRESENT** — in both.

The PR-comment marker is `<!-- securescan:compare -->` so a comment
upserter can keep this on a separate thread from the
`<!-- securescan:diff -->` PR-diff comment.

## compare (dashboard)

`/compare`: same shape as `/diff`, framed for "current scan vs saved
baseline" rather than "scan A vs scan B". Useful at end-of-sprint to
confirm legacy findings were actually remediated.

## API: scan-vs-scan compare

```bash
curl -H "X-API-Key: $K" \
  "http://127.0.0.1:8000/api/v1/scans/compare?scan_a=$BASE&scan_b=$HEAD" \
  | jq .
```

Response:

```json
{
  "scan_a": "0d2c...",
  "scan_b": "0f1a...",
  "new": [ /* findings present in scan_b only */ ],
  "fixed": [ /* findings present in scan_a only */ ],
  "unchanged": [ /* fingerprints in both */ ]
}
```

Source:
[`backend/securescan/api/scans.py::compare_scans`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/scans.py).

## CI integration

The `Metbcy/securescan@v1` action runs `securescan diff` automatically
on `pull_request` events, posts the upserted PR comment, and uploads
SARIF — see [GitHub Action](../cli/github-action.md). To wire diff
into a custom CI:

```yaml
- name: Snapshot base
  run: |
    git checkout ${{ github.base_ref }}
    securescan scan . --type code --output json --output-file before.json
- name: Snapshot head
  run: |
    git checkout ${{ github.head_ref }}
    securescan scan . --type code --output json --output-file after.json
- name: Diff
  run: |
    securescan diff . \
      --base-snapshot before.json \
      --head-snapshot after.json \
      --output github-pr-comment \
      --output-file diff.md
```

## How fingerprints handle reformats

A reformat that does not change the matched line's *meaning* should
**not** reclassify findings as NEW. The fingerprint's
`normalized_line_context` collapses whitespace and trivial
reformatting before hashing, so:

| Change                                  | Fingerprint                |
| --------------------------------------- | -------------------------- |
| Reflow `eval(payload)` → `eval(\n  payload\n)` | Stable                     |
| Replace tabs with spaces                | Stable                     |
| Rename a variable used in the line      | Changes (semantic shift)   |
| Move the line to a different file       | Changes (file_path is in the hash) |

For the few cases where this is wrong (e.g. you move a function file
that the scanner re-flags), the inline `securescan: ignore` comment
travels with the code — the suppression survives the rename.

## Determinism

Both diff and compare are byte-deterministic given the same inputs:
the underlying `securescan scan` is deterministic
([Findings & severity](../scanning/findings-severity.md#fingerprints--cross-scan-identity)),
and the classification step is a pure set difference. So the same PR
push twice posts the same comment body; if the body has not changed,
the upsert is a no-op.

## Next

- [GitHub Action](../cli/github-action.md) — wires diff into PRs.
- [Suppression](../scanning/suppression.md) — particularly the
  baseline mechanism (`securescan baseline`).
- [CLI commands](../cli/commands.md).
