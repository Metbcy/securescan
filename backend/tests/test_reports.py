"""Tests for report generation."""
from datetime import datetime
from pathlib import Path

import pytest

from src.models import Finding, Scan, ScanStatus, ScanSummary, ScanType, Severity
from src.reports import ReportGenerator
from src.scoring import build_summary


def _make_scan() -> Scan:
    return Scan(
        target_path="/test/project",
        scan_types=[ScanType.CODE],
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 3, 31, 10, 0, 0),
        completed_at=datetime(2026, 3, 31, 10, 5, 0),
        findings_count=3,
        risk_score=45.0,
        summary="Found 3 issues including SQL injection.",
    )


def _make_findings() -> list[Finding]:
    return [
        Finding(
            scan_id="test",
            scanner="semgrep",
            scan_type=ScanType.CODE,
            severity=Severity.CRITICAL,
            title="SQL Injection in user query",
            description="User input is concatenated directly into SQL query.",
            file_path="app/db.py",
            line_start=42,
            cwe="CWE-89",
            remediation="Use parameterized queries.",
            compliance_tags=["OWASP-A03", "PCI-6"],
        ),
        Finding(
            scan_id="test",
            scanner="bandit",
            scan_type=ScanType.CODE,
            severity=Severity.MEDIUM,
            title="Weak hash algorithm",
            description="MD5 is used for hashing.",
            file_path="app/auth.py",
            line_start=15,
            cwe="CWE-327",
            compliance_tags=["OWASP-A02"],
        ),
        Finding(
            scan_id="test",
            scanner="secrets",
            scan_type=ScanType.CODE,
            severity=Severity.LOW,
            title="Possible API key in source",
            description="String resembles an API key.",
            file_path="config.py",
            line_start=3,
            compliance_tags=[],
        ),
    ]


@pytest.fixture
def generator() -> ReportGenerator:
    template_dir = Path(__file__).resolve().parent.parent / "templates" / "reports"
    return ReportGenerator(template_dir)


def test_generate_html(generator: ReportGenerator):
    scan = _make_scan()
    findings = _make_findings()
    summary = build_summary(findings, ["semgrep", "bandit", "secrets"])
    html = generator.generate_html(scan, findings, summary, compliance_coverage=[])
    assert "Security Assessment Report" in html
    assert "SQL Injection" in html
    assert "CWE-89" in html
    assert "OWASP-A03" in html
    assert "semgrep" in html


def test_generate_html_with_compliance(generator: ReportGenerator):
    scan = _make_scan()
    findings = _make_findings()
    summary = build_summary(findings, ["semgrep"])
    coverage = [{
        "framework": "OWASP Top 10",
        "version": "2021",
        "total_controls": 10,
        "controls_violated": ["OWASP-A02", "OWASP-A03"],
        "controls_clear": ["OWASP-A01"],
        "violated_details": [
            {"id": "OWASP-A02", "name": "Cryptographic Failures"},
            {"id": "OWASP-A03", "name": "Injection"},
        ],
        "coverage_percentage": 20.0,
    }]
    html = generator.generate_html(scan, findings, summary, compliance_coverage=coverage)
    assert "Compliance" in html
    assert "OWASP Top 10" in html
    assert "Injection" in html


def test_generate_pdf(generator: ReportGenerator):
    scan = _make_scan()
    findings = _make_findings()
    summary = build_summary(findings, ["semgrep"])
    pdf_bytes = generator.generate_pdf(scan, findings, summary, compliance_coverage=[])
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
    assert pdf_bytes[:5] == b"%PDF-"
