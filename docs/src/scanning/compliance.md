# Compliance

SecureScan ships a compliance-mapping engine that tags each finding
with framework references — OWASP Top 10, CIS, PCI-DSS, SOC 2 — by
matching the finding's CWE, `rule_id`, or scanner output keywords
against per-framework data files.

This is **a coverage indicator, not a certification**. SecureScan does
not certify your org against any framework; it surfaces *which*
findings would map to *which* controls so you can demonstrate
coverage and prioritize remediation.

<!-- toc -->

## Mapped frameworks

| Framework         | Where rules come from                                                                                                                              |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OWASP Top 10**  | CWE → A01–A10 mapping. Tags look like `OWASP-A03`, `OWASP-A07`.                                                                                    |
| **CIS Controls**  | Control category mapping (CIS-3, CIS-5, …) by rule_id keyword.                                                                                     |
| **PCI-DSS**       | Specific requirement IDs: `PCI-DSS-6.5.1` (injection), `PCI-DSS-2.2` (config), etc.                                                                |
| **SOC 2**         | Trust service criteria: `SOC2-CC6.1` (logical access), `SOC2-CC7.1` (change management), etc.                                                      |

The mapper lives in
[`backend/securescan/compliance.py`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/compliance.py)
and uses simple data files under
[`backend/securescan/data/`](https://github.com/Metbcy/securescan/blob/main/backend/securescan/data/).
Adding a framework means dropping a JSON file with the rule mappings
— no code change.

## How tags are computed

For each finding the mapper checks:

1. **CWE** (`cwe` field, e.g. `CWE-89`). Direct lookup against the
   framework's CWE → control table.
2. **rule_id**. Keyword match against per-framework lists
   (`B106` → SOC2-CC6.1; `eval-detected` → OWASP-A03; etc.).
3. **Scanner output keywords**. Falls back to substring match against
   `title` + `description` for rules without a CWE or specific
   mapping.

Results are deduplicated and sorted alphabetically. A finding can
carry multiple tags from multiple frameworks:

```json
{
  "rule_id": "python.lang.security.audit.eval-detected",
  "cwe": "CWE-95",
  "compliance_tags": [
    "OWASP-A03",
    "PCI-DSS-6.5.1",
    "SOC2-CC7.1"
  ]
}
```

## In the dashboard

### Per-finding chips

Each finding row in the table renders a **Compliance** column with
chip icons for each tag. Hover a chip to see the framework + control
name.

### Coverage cards

The Overview page renders one tokenized **coverage card** per
framework:

```text
┌─ OWASP Top 10 ─────────────────────────┐
│  6 / 10 controls observed              │
│  ●●●●●●○○○○                            │
│  Last seen: A03, A07 (this scan)       │
└────────────────────────────────────────┘
```

The cards link to a per-framework drill-down with the matching
findings grouped by control.

## API

### List findings filtered by compliance tag

```bash
curl "http://127.0.0.1:8000/api/v1/scans/$SCAN_ID/findings?compliance=OWASP-A03" \
  -H "X-API-Key: $K"
```

Returns only findings whose `compliance_tags` includes
`OWASP-A03`. Multiple filters can be combined with the `severity` /
`scan_type` query params (AND semantics).

### Coverage summary

```bash
curl "http://127.0.0.1:8000/api/v1/compliance/coverage?scan_id=$SCAN_ID" \
  -H "X-API-Key: $K"
```

```json
{
  "frameworks": {
    "OWASP": {
      "controls": ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"],
      "observed": ["A03", "A07"],
      "coverage_pct": 20.0
    },
    "PCI-DSS": {
      "controls": ["1.2", "2.2", "6.5.1", ...],
      "observed": ["6.5.1"],
      "coverage_pct": 12.5
    }
  }
}
```

## Use in PR review

Compliance tags are included in the SARIF output's
`properties.tags` per result:

```json
{
  "ruleId": "python.lang.security.audit.eval-detected",
  "level": "warning",
  "properties": {
    "tags": ["OWASP-A03", "PCI-DSS-6.5.1", "SOC2-CC7.1"],
    "suppressed_by": null
  }
}
```

When uploaded to GitHub's Security tab, those become searchable tags
on the alert.

In the PR comment (`github-pr-comment` output), tags are rendered
inline next to each finding so reviewers see compliance impact at a
glance:

```text
[HIGH] Use of eval()  ·  semgrep  ·  OWASP-A03  PCI-DSS-6.5.1  SOC2-CC7.1
  backend/api.py:42
```

## What this is *not*

```admonish important title="Not a certification artifact"
The compliance engine is a *coverage indicator*. It tags findings
that touch a control. It does **not**:

- Audit your org against the framework.
- Generate a control matrix on its own.
- Prove the absence of issues for unobserved controls.
- Replace the work of a qualified auditor.

What it gives you is a useful **prioritization signal** — a critical
finding that touches OWASP-A03 + PCI-DSS-6.5.1 + SOC2-CC7.1 should be
above one that touches none.
```

## Customizing mappings

To add or override a mapping, edit the per-framework JSON file under
`backend/securescan/data/`. Each entry is a `(rule_id | cwe | keyword)`
→ `[control_id, ...]` mapping. Restart the backend after edits.

A custom-framework PR is welcome; please include rationale and at
least one known-good test case.

## Next

- [Findings & severity](./findings-severity.md) — finding shape with `compliance_tags`.
- [API endpoints](../api/endpoints.md) — coverage / per-tag filtering endpoints.
