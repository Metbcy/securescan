"""Risk scoring module for SecureScan."""
import math
from .models import Finding, Severity, ScanSummary


def calculate_risk_score(findings: list[Finding]) -> float:
    """Calculate a 0-100 risk score from findings.

    Scoring:
    - Start at 0 (perfect)
    - Each finding adds points based on severity
    - Score is capped at 100
    - Diminishing returns for many low-severity findings
    """
    if not findings:
        return 0.0

    weights = {
        Severity.CRITICAL: 15.0,
        Severity.HIGH: 8.0,
        Severity.MEDIUM: 3.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.2,
    }

    raw_score = sum(weights.get(f.severity, 0) for f in findings)
    # Logarithmic scaling to prevent runaway scores from many small findings
    # but ensure critical findings still push the score high
    score = min(100.0, 20 * math.log1p(raw_score))
    return round(score, 1)


def build_summary(findings: list[Finding], scanners_run: list[str]) -> ScanSummary:
    """Build a scan summary from findings."""
    severity_counts = {s: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity] += 1

    return ScanSummary(
        total_findings=len(findings),
        critical=severity_counts[Severity.CRITICAL],
        high=severity_counts[Severity.HIGH],
        medium=severity_counts[Severity.MEDIUM],
        low=severity_counts[Severity.LOW],
        info=severity_counts[Severity.INFO],
        risk_score=calculate_risk_score(findings),
        scanners_run=scanners_run,
    )
