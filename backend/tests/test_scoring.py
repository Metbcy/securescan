"""Tests for risk scoring."""

from securescan.models import Finding, ScanType, Severity
from securescan.scoring import build_summary, calculate_risk_score


def _make_finding(severity: Severity) -> Finding:
    return Finding(
        scan_id="test",
        scanner="test",
        scan_type=ScanType.CODE,
        severity=severity,
        title=f"Test {severity.value}",
        description="Test",
    )


def test_empty_findings():
    assert calculate_risk_score([]) == 0.0


def test_single_critical():
    score = calculate_risk_score([_make_finding(Severity.CRITICAL)])
    assert score > 40  # A single critical should be significant


def test_single_low():
    score = calculate_risk_score([_make_finding(Severity.LOW)])
    assert score < 20  # A single low should be minor


def test_score_increases_with_severity():
    low = calculate_risk_score([_make_finding(Severity.LOW)])
    medium = calculate_risk_score([_make_finding(Severity.MEDIUM)])
    high = calculate_risk_score([_make_finding(Severity.HIGH)])
    critical = calculate_risk_score([_make_finding(Severity.CRITICAL)])
    assert low < medium < high < critical


def test_score_capped_at_100():
    many_criticals = [_make_finding(Severity.CRITICAL) for _ in range(100)]
    assert calculate_risk_score(many_criticals) <= 100.0


def test_build_summary():
    findings = [
        _make_finding(Severity.CRITICAL),
        _make_finding(Severity.HIGH),
        _make_finding(Severity.HIGH),
        _make_finding(Severity.MEDIUM),
        _make_finding(Severity.LOW),
    ]
    summary = build_summary(findings, ["semgrep", "bandit"])
    assert summary.total_findings == 5
    assert summary.critical == 1
    assert summary.high == 2
    assert summary.medium == 1
    assert summary.low == 1
    assert summary.info == 0
    assert summary.risk_score > 0
    assert "semgrep" in summary.scanners_run
