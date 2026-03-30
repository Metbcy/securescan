"""Deduplicate findings across multiple scanners."""
from .models import Finding, Severity


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings reported by multiple scanners.

    Dedup strategy:
    1. Group by (file_path, line_start, normalized_title)
    2. If multiple findings match, keep the one with highest severity
    3. Merge metadata from duplicates into the kept finding
    """
    if not findings:
        return findings

    seen: dict[str, Finding] = {}

    for finding in findings:
        key = _dedup_key(finding)
        if key in seen:
            existing = seen[key]
            # Keep the higher severity one
            if _severity_rank(finding.severity) > _severity_rank(existing.severity):
                finding.metadata["also_reported_by"] = existing.scanner
                seen[key] = finding
            else:
                existing.metadata["also_reported_by"] = finding.scanner
        else:
            seen[key] = finding

    return list(seen.values())


def _dedup_key(finding: Finding) -> str:
    """Generate a deduplication key for a finding."""
    title_normalized = finding.title.lower().strip()
    # Remove scanner-specific prefixes
    for prefix in ["b", "cwe-", "rule-"]:
        title_normalized = title_normalized.removeprefix(prefix)

    parts = [
        finding.file_path or "no-file",
        str(finding.line_start or 0),
        title_normalized[:60],
    ]
    return "|".join(parts)


def _severity_rank(severity: Severity) -> int:
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }.get(severity, 0)
