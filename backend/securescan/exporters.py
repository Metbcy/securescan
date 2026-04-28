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

from .models import Finding, Scan, ScanSummary, Severity  # noqa: F401
from .ordering import sort_findings_canonical


def findings_to_sarif(findings: list[Finding], scan: Scan) -> dict:
    """Convert findings to SARIF v2.1.0 format for GitHub/GitLab integration.

    Output is deterministic: findings are sorted by the canonical key,
    rules are emitted in lexicographic ``ruleId`` order, and no
    wall-clock timestamps are included in ``invocations`` so the same
    logical scan re-uploaded to GitHub's Security tab does not generate
    spurious "new alert" diffs.
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

    for finding in findings:
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
