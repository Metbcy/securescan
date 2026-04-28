"""Export scan results in standard formats.

All exporters in this module produce byte-identical output for the same
logical input. Findings are passed through ``sort_findings_canonical``
before rendering, every dict-of-rules / set-of-tags is iterated in
sorted order, and wall-clock timestamps that would otherwise differ
between re-runs of the same scan are intentionally omitted from SARIF
(the scan's ``started_at``/``completed_at`` are still persisted on the
``Scan`` model itself for audit purposes).
"""
import xml.etree.ElementTree as ET

from .diff import ChangeSet
from .models import Finding, Scan, ScanSummary, Severity  # noqa: F401
from .ordering import sort_findings_canonical
from .render_pr_comment import render_pr_comment


def findings_to_sarif(findings: list[Finding], scan: Scan) -> dict:
    """Convert findings to SARIF v2.1.0 format for GitHub/GitLab integration.

    Output is deterministic: findings are sorted by the canonical key,
    rules are emitted in lexicographic ``ruleId`` order, and no
    wall-clock timestamps are included in ``invocations`` so the same
    logical scan re-uploaded to GitHub's Security tab does not generate
    spurious "new alert" diffs.

    Per-result ``partialFingerprints`` are emitted under the
    ``securescan/v1`` namespace key (a versioned algorithm identifier
    so a future fingerprint change can use ``securescan/v2`` without
    reconciliation). This is GitHub Code Scanning's canonical
    cross-upload dedup field. In addition, results sharing the same
    fingerprint are collapsed in-pass — some scanners (notably certain
    Semgrep configurations) emit the same logical finding twice, and
    that would otherwise surface as duplicate alerts on the Security
    tab. The representative kept is the one with the lowest
    ``line_start`` (canonical sort already places it first). Findings
    whose ``fingerprint`` is empty are passed through unchanged with
    no ``partialFingerprints`` entry and no dedup.
    """
    findings = sort_findings_canonical(findings)
    rules: dict[str, dict] = {}
    results: list[dict] = []

    severity_to_level = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "note",
    }

    deduped: list[Finding] = _dedupe_by_fingerprint(findings)

    for finding in deduped:
        fp = getattr(finding, "fingerprint", "") or ""

        rule_id = finding.rule_id or f"{finding.scanner}/{finding.title.lower().replace(' ', '-')[:50]}"

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.title[:100],
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.description},
                "defaultConfiguration": {
                    "level": severity_to_level.get(finding.severity, "warning")
                },
                "properties": {
                    "security-severity": _severity_score(finding.severity),
                    "tags": ["security"],
                },
            }
            if finding.cwe:
                rules[rule_id]["properties"]["tags"].append(finding.cwe)

        result = {
            "ruleId": rule_id,
            "level": severity_to_level.get(finding.severity, "warning"),
            "message": {"text": finding.description},
        }

        if finding.file_path:
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file_path},
                }
            }
            if finding.line_start:
                location["physicalLocation"]["region"] = {
                    "startLine": finding.line_start,
                }
                if finding.line_end:
                    location["physicalLocation"]["region"]["endLine"] = finding.line_end
            result["locations"] = [location]

        if fp:
            result["partialFingerprints"] = {"securescan/v1": fp}

        if finding.remediation:
            result["fixes"] = [{
                "description": {"text": finding.remediation},
            }]

        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecureScan",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/Metbcy/securescan",
                    "rules": [rule for _, rule in sorted(rules.items(), key=lambda kv: kv[0])],
                }
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": scan.status == "completed",
            }],
        }],
    }


def _dedupe_by_fingerprint(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing a non-empty ``fingerprint`` to a single
    representative. The representative kept is the one with the lowest
    concrete ``line_start``; a finding with a concrete line is preferred
    over one with ``line_start=None`` (precise location is more
    actionable for the user). First-encountered wins on ties, which
    preserves the caller's canonical-order tiebreaker and keeps the
    output deterministic.

    Findings with an empty fingerprint are passed through unchanged
    (the pre-fingerprint behavior — empty fingerprint means "treat as
    unique"). Input order among kept findings is preserved so the
    caller's canonical sort is not perturbed by this step.
    """
    by_fp: dict[str, Finding] = {}
    no_fp: list[Finding] = []
    order: list[tuple[str, str]] = []  # (kind, key); kind in {"fp", "nofp"}

    for finding in findings:
        fp = getattr(finding, "fingerprint", "") or ""
        if not fp:
            no_fp.append(finding)
            order.append(("nofp", str(len(no_fp) - 1)))
            continue

        existing = by_fp.get(fp)
        if existing is None:
            by_fp[fp] = finding
            order.append(("fp", fp))
            continue

        # Keep the one with the lowest line_start; concrete line numbers
        # are preferred over ``None`` (a finding with precise line info is
        # more actionable for the user than one without). First encountered
        # wins on ties, preserving the caller's canonical order.
        new_line = finding.line_start
        old_line = existing.line_start
        if _line_rank(new_line) < _line_rank(old_line):
            by_fp[fp] = finding

    out: list[Finding] = []
    for kind, key in order:
        if kind == "fp":
            out.append(by_fp[key])
        else:
            out.append(no_fp[int(key)])
    return out


def _line_rank(line: int | None) -> tuple[int, int]:
    """Sort key for ``line_start`` such that any concrete int is preferred
    (collates lower) over ``None``. Within concrete ints the natural order
    applies. Returns a 2-tuple so equal lines compare equal and the
    caller's first-encountered tiebreaker wins.
    """
    if line is None:
        return (1, 0)
    return (0, line)


def _severity_score(severity: Severity) -> str:
    """Map severity to CVSS-like score for SARIF."""
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "7.5",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "2.5",
        Severity.INFO: "0.5",
    }.get(severity, "5.0")


def findings_to_csv(findings: list[Finding]) -> str:
    """Export findings as CSV string. Findings are sorted canonically so
    the output is byte-identical for the same logical input.
    """
    findings = sort_findings_canonical(findings)
    lines = ["severity,scanner,title,file,line,rule_id,cwe,description,remediation"]
    for f in findings:
        row = [
            f.severity.value,
            f.scanner,
            f'"{f.title}"',
            f.file_path or "",
            str(f.line_start or ""),
            f.rule_id or "",
            f.cwe or "",
            f'"{f.description[:200]}"',
            f'"{(f.remediation or "")[:200]}"',
        ]
        lines.append(",".join(row))
    return "\n".join(lines)


def findings_to_junit(findings: list[Finding], scan: Scan) -> str:
    """Export findings as JUnit XML for CI/CD test frameworks. Findings
    are sorted canonically so the output is byte-identical for the same
    logical input.
    """
    findings = sort_findings_canonical(findings)
    suite = ET.Element("testsuite", {
        "name": "SecureScan",
        "tests": str(len(findings)),
        "failures": str(sum(1 for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH))),
        "errors": "0",
    })

    for finding in findings:
        tc = ET.SubElement(suite, "testcase", {
            "name": finding.title[:200],
            "classname": f"securescan.{finding.scanner}",
        })
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            failure = ET.SubElement(tc, "failure", {
                "type": finding.severity.value,
                "message": finding.title,
            })
            failure.text = f"{finding.description}\nFile: {finding.file_path or 'N/A'}\nLine: {finding.line_start or 'N/A'}\nRemediation: {finding.remediation or 'N/A'}"
        elif finding.severity == Severity.MEDIUM:
            ET.SubElement(tc, "system-out").text = finding.description

    return ET.tostring(suite, encoding="unicode", xml_declaration=True)


def findings_to_pr_comment(
    findings: list[Finding],
    *,
    repo: str | None = None,
    sha: str | None = None,
) -> str:
    """Render a flat finding list as a GitHub PR-comment Markdown body.

    Convenience wrapper around ``render_pr_comment`` for the common CLI
    path (``securescan scan --output github-pr-comment``) where the
    caller has a flat list of findings rather than a pre-classified
    ``ChangeSet``. All findings are treated as ``new`` -- there's no
    base scan to diff against.

    The ``securescan diff`` subcommand (SS6) constructs a real
    ``ChangeSet`` from base/head scans and calls ``render_pr_comment``
    directly, so the per-severity bucketing and new/fixed/unchanged
    summary table show real diff data instead of "everything is new".
    """
    changeset = ChangeSet(new=sort_findings_canonical(findings))
    return render_pr_comment(changeset, repo=repo, sha=sha)
