# Findings & severity

Every scanner output is normalized to the **same** finding shape. That
shape is what the API returns, what `securescan diff` compares, what
SARIF / JSON / CSV / JUnit exporters serialize, and what the dashboard
renders.

<!-- toc -->

## The Finding shape

```json
{
  "id": "f-2c1a93cb",
  "scan_id": "0f1a93cb-44c2-4c8e-9f92-0a7c5a2e1b51",
  "scanner": "semgrep",
  "scan_type": "code",
  "severity": "high",
  "title": "Use of eval()",
  "description": "Detected use of eval(); evaluating arbitrary input is dangerous.",
  "file_path": "backend/securescan/cli.py",
  "line": 142,
  "column": 8,
  "rule_id": "python.lang.security.audit.eval-detected",
  "cwe": "CWE-95",
  "fingerprint": "9d2f3a1b8c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
  "compliance_tags": ["OWASP-A03", "PCI-DSS-6.5.1"],
  "metadata": {
    "suppressed_by": null,
    "original_severity": null
  }
}
```

The Pydantic model is `Finding` in
[`backend/securescan/models.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/models.py).
The dashboard's findings endpoint (`GET /api/v1/scans/{id}/findings`)
returns `FindingWithState` — every field above plus an optional
`state: FindingState | null` for the triage verdict
(see [Triage workflow](./triage.md)).

## Severity

Five levels. The ramp is **a single tonal ramp around the warm hue**,
not stoplight RGB:

| Level      | Meaning                                                      | Default `--fail-on-severity` behavior |
| ---------- | ------------------------------------------------------------ | :-----------------------------------: |
| `critical` | Drop-everything. Active exploitation likely.                 | Fail                                  |
| `high`     | Real risk. Fix before release.                               | Fail                                  |
| `medium`   | Should fix; not blocking.                                    | Fail when `--fail-on-severity=medium` |
| `low`      | Nice to fix.                                                 |                                       |
| `info`     | Informational; not actionable on its own.                    |                                       |

Severity is **per-scanner** but normalized here. Different scanners
report on different scales (Trivy uses CVSS, Bandit uses
LOW/MEDIUM/HIGH, Semgrep uses INFO/WARNING/ERROR), and they all map
into this five-level common denominator.

You can override severity per rule via `.securescan.yml`:

```yaml
severity_overrides:
  python.lang.security.audit.dangerous-system-call: medium
  python.lang.security.audit.eval-detected: low
```

When an override applies, the original severity is preserved on
`metadata.original_severity`, and the dashboard renders
`severity (was: original)` in the row so the audit trail stays
visible.

## Risk score

The scan summary (`GET /api/v1/scans/{id}/summary`) carries a
`risk_score` field, a single number aimed at trend lines and
quarterly reviews. It is roughly:

> Weighted by severity rank (critical/high count for far more than
> low/info) and scanner confidence.

The exact formula lives in
[`backend/securescan/scoring.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/scoring.py)
and is intentionally *not* documented in detail here — the score is
useful as a *trend* indicator, not as a precise metric to negotiate.
For decisions, look at the severity counts directly.

```admonish note
For the dashboard Overview page's trend chart and the scan-detail
StatLine, severity counts are the primary metric. `risk_score` is a
single rolled-up number for headline use.
```

## Fingerprints — cross-scan identity

Every finding gets a deterministic fingerprint:

```text
sha256(
  scanner | rule_id | file_path | normalized_line_context | cwe
)
```

Construction is in
[`backend/securescan/fingerprint.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/fingerprint.py).
The `normalized_line_context` is the matched line with whitespace
collapsed and trivial reformat normalized — so renaming a variable
shifts the fingerprint, but reformatting the file does not.

This identity is what keeps:

- **Triage verdicts** sticky across rescans (`finding_states` is
  keyed on `fingerprint`, not `(scan_id, finding_id)`).
- **PR comment threads** stable across re-runs (the inline-review
  poster looks up existing comments by fingerprint and PATCHes them
  rather than posting duplicates).
- **SARIF re-uploads clean** — `partialFingerprints.primaryLocationLineHash`
  is set from the same value, so GitHub's Security tab dedupes.
- **`securescan compare`** sane — `NEW` / `STILL_PRESENT` /
  `DISAPPEARED` is computed by fingerprint set difference.

Practically: if you triage a finding as `false_positive` once, it
stays a false positive across every later scan of the same target,
even after `DELETE /scans/{id}`. See [Triage](./triage.md).

## Deduplication

Multiple scanners can find the *same* underlying issue from different
angles — Bandit and Semgrep both flag `eval()`. The orchestrator runs
`dedup_key` from
[`backend/securescan/dedup.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/dedup.py)
across the union of scanner outputs and keeps the higher-confidence
finding (the one whose scanner is more authoritative for that rule
class).

The dropped findings still show up in the scan's lifecycle log — they
are filtered before persistence, so the database only stores the
canonical finding for each underlying issue.

## Severity badges

The dashboard renders severity as a colored dot prefix + the level
text:

```text
● critical    coral background
● high        burnt orange
● medium      saffron
● low         dusty teal (NOT bright blue)
● info        ash
```

The exact OKLCH values live in
[`frontend/src/app/globals.css`](https://github.com/Metbcy/securescan/blob/main/frontend/src/app/globals.css).
There is no neon red / yellow / green — see [DESIGN.md][design] for
the rationale.

[design]: https://github.com/Metbcy/securescan/blob/main/DESIGN.md

## Compliance tags

Each finding can carry one or more `compliance_tags` — strings like
`OWASP-A03`, `PCI-DSS-6.5.1`, `SOC2-CC7.1`. The mapping engine
(`backend/securescan/compliance.py`) matches by CWE, rule_id, or
keyword and the dashboard renders chips per finding plus a coverage
summary on the Overview page. See [Compliance](./compliance.md) for
which frameworks are mapped and how.

## Suppression metadata

When a finding is suppressed (inline comment, config rule, or
baseline), `metadata.suppressed_by` is set to one of:

- `"inline"` — `# securescan: ignore RULE-ID` on the line.
- `"config"` — `.securescan.yml` `ignored_rules`.
- `"baseline"` — present in the saved baseline JSON.

By default, suppressed findings are hidden from CI output (PR
comments, SARIF) but rendered on a TTY (and in the dashboard via the
"Show suppressed" toggle) with a `[SUPPRESSED:<reason>]` prefix so
you can audit the breakdown without re-running. Force visibility
everywhere with `--show-suppressed`.

See [Suppression](./suppression.md).

## Output formats

| Format              | Where it lives                                                                                    | Use                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `text`              | CLI default for TTY runs.                                                                         | Human-readable terminal output.                                           |
| `json`              | `--output json` — finding records as a JSON array.                                                | Snapshot mode, downstream tools, baselines.                               |
| `sarif`             | `--output sarif` — SARIF v2.1.0 with `partialFingerprints`.                                       | GitHub Security tab, third-party SARIF readers.                           |
| `csv`               | `--output csv` — one row per finding.                                                             | Spreadsheet import, compliance reports.                                   |
| `junit`             | `--output junit` — failures = findings.                                                           | CI test-result tabs.                                                      |
| `github-pr-comment` | `--output github-pr-comment` — markdown with `<!-- securescan:diff -->` upsert marker.            | The default for `securescan diff`.                                        |
| `github-review`     | `--output github-review` — payload for GitHub's Reviews API.                                      | Inline-review mode of the GitHub Action.                                  |

All formats produce **byte-identical** output for the same inputs —
see [Architecture: determinism contract](../architecture.md#determinism-contract).

## Next

- [Suppression](./suppression.md) — three ways to silence a finding.
- [Triage](./triage.md) — verdicts that survive across scans.
- [Compliance](./compliance.md) — framework mapping.
