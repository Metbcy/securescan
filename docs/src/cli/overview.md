# CLI overview

The `securescan` CLI is the **source of truth** for the data model:
the same fingerprints, severities, scan types, and suppression
mechanics that the dashboard exposes are first defined here. The web
UI is a mirror.

There are three primary modes:

- **One-shot scan** — `securescan scan` against a directory.
- **Diff scan** — `securescan diff` against two refs (or two
  pre-scanned snapshots). The CI workhorse.
- **Server** — `securescan serve` runs the FastAPI dashboard backend.

<!-- toc -->

## Install

The CLI is the same binary regardless of install path:

```bash
# Wheel from GitHub Releases (SecureScan is not currently on PyPI):
pip install https://github.com/Metbcy/securescan/releases/download/v0.10.2/securescan-0.10.2-py3-none-any.whl

# Or, the container (everything pre-installed):
docker run --rm -v "$PWD:/work" -w /work \
  ghcr.io/metbcy/securescan:v0.10.2 \
  scan . --type code
```

See [Install](../install.md) for full details.

## Subcommands

| Command                                 | What it does                                                                                |
| --------------------------------------- | ------------------------------------------------------------------------------------------- |
| `securescan scan <path>`                | Full scan of a directory. Outputs findings in any format.                                   |
| `securescan diff <path>`                | Diff-aware scan: only NEW findings introduced since the base ref.                           |
| `securescan compare <path> <baseline>`  | Compare current scan against a saved baseline; report drift (NEW / DISAPPEARED / STILL_PRESENT). |
| `securescan baseline [-o <path>]`       | Write a canonical baseline JSON of current findings (deterministic; check into git).         |
| `securescan config validate [<path>]`   | Lint `.securescan.yml` for typos, bad severities, missing rule-pack paths.                  |
| `securescan history`                    | List past saved scans.                                                                      |
| `securescan status`                     | List which scanners are installed and reachable.                                            |
| `securescan serve`                      | Run the FastAPI dashboard backend.                                                          |

Detailed examples for each: [Commands](./commands.md).

## Output formats

Pick with `--output <format>`:

| Format                | Use case                                                                                          |
| --------------------- | ------------------------------------------------------------------------------------------------- |
| `text` (TTY default)  | Human-readable terminal output.                                                                   |
| `json`                | Downstream tools, baselines, snapshot-mode diff inputs.                                           |
| `sarif`               | GitHub Code Scanning / Security tab; emits `partialFingerprints` so re-uploads dedup cleanly.     |
| `csv`                 | Spreadsheet import, compliance reports.                                                           |
| `junit`               | CI test-result tabs.                                                                              |
| `github-pr-comment`   | The default for `securescan diff`. Markdown with `<!-- securescan:diff -->` upsert marker.        |
| `github-review`       | GitHub Reviews API JSON payload (used by the inline-review action mode).                          |

`--output-file <path>` writes to a file instead of stdout.

## Determinism

Every CLI run is **byte-deterministic** for the same inputs:

- Findings are sorted by a canonical key.
- AI enrichment is auto-disabled in CI (`CI=true`).
- Wall-clock timestamps are excluded from byte-identity-sensitive sections.
- `SECURESCAN_FAKE_NOW` pins the only time-derived field that exists.

This is the property that makes the GitHub Action's "single PR comment,
upserted on every push" work — and makes SARIF re-uploads to
GitHub's Security tab dedup cleanly. See
[Architecture: determinism contract](../architecture.md#determinism-contract).

## Most-used flags

These are the flags you'll reach for most. The full list is
`securescan --help` (and per-subcommand `--help`).

### Global

| Flag             | Default | Notes                                                                  |
| ---------------- | ------- | ---------------------------------------------------------------------- |
| `--type <t>`     | `code` (for `diff`); `code,dependency` typical for `scan` | Repeatable. `code` / `dependency` / `iac` / `baseline` / `dast` / `network`. |
| `--output <fmt>` | `text` (TTY) / `json` (pipe) | One of the formats above.                                |
| `--output-file <path>` | stdout | Write to file.                                                    |
| `--ai` / `--no-ai`     | auto   | Force AI enrichment on / off (auto = off in CI).                  |
| `--fail-on-severity <s>` | none   | Exit non-zero if findings ≥ this severity exist.                |
| `--show-suppressed`    | off    | Include suppressed findings in output (with `[SUPPRESSED:reason]` prefix). |
| `--no-suppress`        | off    | Disable suppression entirely. Kill switch.                        |

### `diff`-specific

| Flag                 | Notes                                                       |
| -------------------- | ----------------------------------------------------------- |
| `--base-ref <ref>`   | Git ref for the "before" side. Resolved to a sha.           |
| `--head-ref <ref>`   | Git ref for the "after" side. Resolved to a sha.            |
| `--base-snapshot <file>` | Pre-scanned JSON for the base side (CI-friendly path).  |
| `--head-snapshot <file>` | Pre-scanned JSON for the head side.                     |
| `--baseline <file>`  | Path to baseline JSON to suppress legacy findings.          |
| `--repo`, `--sha`, `--base-sha` | For `--output github-review`: GitHub coordinates. Auto-resolved from git when omitted. |

```admonish note
`securescan diff` accepts ref mode (`--base-ref` / `--head-ref`) **or**
snapshot mode (`--base-snapshot` / `--head-snapshot`), never both.
Snapshot mode is the recommended CI path: each side runs
`securescan scan ... --output json` independently, then a single
classification step does the diff without re-checking-out the tree.
```

### `serve`-specific

| Flag                 | Default       | Notes                                                  |
| -------------------- | ------------- | ------------------------------------------------------ |
| `--host`             | `127.0.0.1`   | Bind interface. Use `0.0.0.0` in containers.           |
| `--port`             | `8000`        |                                                        |
| `--workers`          | `1`           | **Must stay 1.** See [Single-worker](../deployment/single-worker.md). |

## Auth from the CLI

When SecureScan's backend has auth configured, the CLI's commands
that hit the backend need a key. Two options:

1. **Set `SECURESCAN_API_KEY`** in the environment.
2. **Pass `--api-key <key>`** on the command line.

The env path is preferred because it doesn't end up in shell
history.

The relevant commands are: `history`, `status` (when probing a
remote backend), and the inline-review modes that POST to the
backend. `scan` / `diff` / `compare` / `baseline` work entirely
locally and do not need backend auth.

## Examples

### Scan a directory, fail on high

```bash
securescan scan ./your-repo --type code --type dependency \
  --fail-on-severity high \
  --output sarif --output-file results.sarif
```

### Diff for a PR (snapshot mode)

```bash
securescan scan . --type code --output json --output-file before.json
git checkout HEAD
securescan scan . --type code --output json --output-file after.json
securescan diff . \
  --base-snapshot before.json --head-snapshot after.json \
  --output github-pr-comment --output-file pr-comment.md
```

### Refresh a baseline

```bash
securescan baseline             # writes .securescan/baseline.json
securescan compare .securescan/baseline.json   # what disappeared since the last baseline?
```

### Validate a config

```bash
securescan config validate .securescan.yml
```

### Status check

```bash
securescan status
```

## Source

- Entry point:
  [`backend/securescan/cli.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/cli.py)
  (Typer-based).

```admonish tip title="--help is the source of truth for flags"
This page covers the most-used flags. For the **complete** flag
list per subcommand, run `securescan <subcommand> --help`. The CLI
is built with Typer; help text is auto-generated from the function
signatures.
```

## Next

- [Commands](./commands.md) — detailed examples for every subcommand.
- [GitHub Action](./github-action.md) — `securescan diff` wrapped for CI.
- [Suppression](../scanning/suppression.md) — for the `--show-suppressed` / `--no-suppress` flags.
