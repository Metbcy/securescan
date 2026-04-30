# Commands

A subcommand-by-subcommand walkthrough with realistic examples.
For the **full** flag list per command, run `securescan <cmd> --help`
— that's the source of truth.

<!-- toc -->

## `scan`

Full scan of a directory (or URL / hostname for DAST / network).
Outputs findings in any [output format](./overview.md#output-formats).

```bash
# Default: code + dependency
securescan scan ./your-repo

# Multiple types
securescan scan ./your-repo --type code --type dependency --type iac

# DAST against a URL
securescan scan https://staging.example.com --type dast

# Network probe
securescan scan example.com --type network

# Specify output file + format
securescan scan ./your-repo --type code \
  --output sarif --output-file results.sarif

# Fail the build on high
securescan scan ./your-repo --fail-on-severity high

# Force AI enrichment on (off by default in CI)
securescan scan ./your-repo --ai
```

Sample text output:

```text
Scanning ./your-repo (code, dependency)
  semgrep: 7 findings (4.31s)
  bandit: 2 findings (1.04s)
  trivy: 3 findings (12.7s)
  safety: 0 findings (0.6s)

[HIGH]   semgrep   backend/api.py:42         Use of eval()
[HIGH]   bandit    backend/db.py:12          SQL injection via str.format
[MEDIUM] trivy     requirements.txt          CVE-2024-12345 in requests<2.32.0
...

Summary
  Total: 12 findings (1 critical, 3 high, 5 medium, 2 low, 1 info)
  Risk score: 34.2
  fail-on-severity: none
```

## `diff`

Diff-aware scan: only NEW findings between two refs. The CI
workhorse.

```bash
# Ref mode — refs must exist in the local clone
securescan diff . --base-ref main --head-ref HEAD

# Snapshot mode — recommended for CI
securescan diff . \
  --base-snapshot before.json \
  --head-snapshot after.json \
  --output github-pr-comment

# Output as a GitHub review JSON (for inline-review mode)
securescan diff . --base-ref main --head-ref HEAD \
  --output github-review --repo Metbcy/securescan \
  --output-file review.json
```

Sample `github-pr-comment` output:

```markdown
<!-- securescan:diff -->
### SecureScan diff

3 new findings (●1 critical, ●1 high, ●1 medium) · 0 fixed · 14 unchanged
fail-on-severity: high

| Severity | Scanner | Title | Where |
| --- | --- | --- | --- |
| ● critical | semgrep | Use of eval() | `backend/api.py:42` |
| ● high | bandit | SQL injection via str.format | `backend/db.py:12` |
| ● medium | secrets | Possible AWS access key | `config/local.yml:5` |

<sub>Run `securescan diff` locally to reproduce. Markers identify this comment for upsert.</sub>
```

```admonish tip title="Snapshot mode in CI"
Each side of the diff runs `securescan scan ... --output json`
independently — possibly on different runners — and the diff step
is a single deterministic classification. This decouples the heavy
work from the diff and lets you cache snapshots across runs. See
[Diff & compare](../dashboard/diff.md).
```

## `compare`

Compare current scan against a saved baseline; report drift.

```bash
# What disappeared since the baseline?
securescan compare .securescan/baseline.json

# As a PR comment
securescan compare .securescan/baseline.json \
  --output github-pr-comment --output-file compare.md
```

The classifier produces:

| Bucket          | Meaning                                              |
| --------------- | ---------------------------------------------------- |
| `NEW`           | In current scan, not in baseline.                    |
| `DISAPPEARED`   | In baseline, not in current scan. (Your remediations.) |
| `STILL_PRESENT` | In both.                                             |

The PR-comment marker is `<!-- securescan:compare -->` so a comment
upserter can keep this on a separate thread from the
`<!-- securescan:diff -->` PR-diff comment.

## `baseline`

Write a canonical baseline JSON of current findings.

```bash
# Writes to .securescan/baseline.json (default)
securescan baseline

# Custom path
securescan baseline -o /path/to/baseline.json
```

The output is byte-deterministic: no timestamps, relative
`target_path`, sorted entries. Two identical scans produce two
identical baseline files — diffs cleanly in code review.

Common usage on adoption:

```bash
securescan baseline             # snapshot every existing finding
git add .securescan/baseline.json
git commit -m "chore: SecureScan baseline"
```

Then in CI:

```bash
securescan diff . --base-ref main --head-ref HEAD \
  --baseline .securescan/baseline.json   # only NEW findings appear
```

See [Suppression → baseline](../scanning/suppression.md#3-baseline-legacy-findings).

## `config validate`

Lint `.securescan.yml`:

```bash
$ securescan config validate
.securescan.yml: OK
  scan_types: code, dependency
  ignored_rules: 3
  severity_overrides: 2
  semgrep_rules: .securescan/rules/secrets.yml
```

Catches:

- Typos in severity values (`hgih` instead of `high`).
- Missing rule-pack paths.
- Collisions between `ignored_rules` and `severity_overrides` (a
  rule that is both ignored and severity-pinned).

Exit code `0` on OK, non-zero on validation failure.

## `history`

List past scans (talks to the backend if `serve` is running, otherwise
reads the local DB):

```bash
$ securescan history
ID                                   Target                Started              Status     Findings
0f1a93cb-44c2-4c8e-9f92-0a7c5a2e1b51 /home/me/proj-a       2026-04-29 20:11:09  completed  12
0d2c3a8f-4f1c-86e9-2b4b4ab0a8e0     /home/me/proj-a       2026-04-28 18:00:02  completed  14
2b3a93bc-8f4f-1c86-e92b-4b4ab0a8e0e1 https://staging       2026-04-28 17:30:10  failed     -
```

## `status`

List which scanners are installed and reachable. Read this first
when results look thinner than expected:

```bash
$ securescan status
Scanner       Type         Available  Version    Notes
semgrep       code         yes        1.71.0
bandit        code         yes        1.7.5
trivy         dependency   yes        0.49.1
safety        dependency   yes        2.3.5
checkov      iac          no                    pip install checkov
npm-audit     dependency   yes        npm 10.x   uses ambient npm on PATH
zap           dast         no                    /usr/share/zaproxy/zap.sh; recommended port 8090
nmap          network      yes        7.94
licenses      dependency   yes        4.3.4
secrets       code         yes
git-hygiene   code         yes
dockerfile    iac          yes
baseline      baseline     yes
builtin_dast  dast         yes
```

The same data is at `GET /api/v1/dashboard/status` — the dashboard's
`/scan` page reads it on mount.

## `serve`

Run the FastAPI dashboard backend:

```bash
# Default
securescan serve

# Bind on all interfaces (in a container)
securescan serve --host 0.0.0.0 --port 8000

# Single worker is the default and required
securescan serve --workers 1
```

Inside the container, the entry point is the same — `serve` is the
command that the bundled image runs.

See [Docker](../deployment/docker.md) and
[Production checklist](../deployment/production-checklist.md).

## Less-used / power-user flags

### Inline review mode integration

```bash
securescan diff . --base-ref main --head-ref HEAD \
  --output github-review \
  --repo Metbcy/securescan \
  --sha "$GITHUB_SHA" \
  --base-sha "$GITHUB_BASE_SHA" \
  --review-event COMMENT \
  --no-suggestions
```

These flags exist so the GitHub Action's `post-review.sh` can drive
the inline-review path, but they're useful for local debugging too:
the JSON payload is what the Reviews API expects, so you can
inspect it without posting.

### Baseline host probes

```bash
securescan scan / --type baseline --baseline-host-probes
```

For power users who want host-scope baseline probes alongside
target-scope scans. See [Scan types → baseline](../scanning/scan-types.md#baseline).

### Pinning the time field

```bash
SECURESCAN_FAKE_NOW="2026-04-29T20:00:00Z" \
  securescan scan ./your-repo --output json --output-file findings.json
```

Pins the only time-derived field in the output for byte-identical
test fixtures. Used in the SecureScan test suite; useful for any
CI replay that needs reproducible bytes.

## Source

- All commands route through
  [`backend/securescan/cli.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/cli.py)
  (Typer-based).
- The serve command bridges to
  [`backend/securescan/api/__init__.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/api/__init__.py).

## Next

- [GitHub Action](./github-action.md) — `securescan diff` wrapped for CI.
- [CLI overview](./overview.md) — flags + output formats reference.
- [Suppression](../scanning/suppression.md) — `--show-suppressed`, `--no-suppress`, baseline.
