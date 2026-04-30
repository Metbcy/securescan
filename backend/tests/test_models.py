"""Tests for Pydantic models."""

from securescan.models import (
    Finding,
    Scan,
    ScannerSkip,
    ScanRequest,
    ScanStatus,
    ScanSummary,
    ScanType,
    Severity,
)


def test_severity_enum():
    assert Severity.CRITICAL.value == "critical"
    assert Severity.HIGH.value == "high"
    assert Severity.MEDIUM.value == "medium"
    assert Severity.LOW.value == "low"
    assert Severity.INFO.value == "info"


def test_scan_status_enum():
    assert ScanStatus.PENDING.value == "pending"
    assert ScanStatus.RUNNING.value == "running"
    assert ScanStatus.COMPLETED.value == "completed"
    assert ScanStatus.FAILED.value == "failed"
    assert ScanStatus.CANCELLED.value == "cancelled"


def test_finding_creation():
    f = Finding(
        scan_id="test-scan",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=Severity.HIGH,
        title="Test Finding",
        description="Test description",
    )
    assert f.id  # auto-generated UUID
    assert f.scanner == "semgrep"
    assert f.severity == Severity.HIGH
    assert f.file_path is None
    assert f.metadata == {}


def test_finding_with_all_fields():
    f = Finding(
        scan_id="test-scan",
        scanner="bandit",
        scan_type=ScanType.CODE,
        severity=Severity.MEDIUM,
        title="Hardcoded password",
        description="Found hardcoded password",
        file_path="/src/config.py",
        line_start=42,
        line_end=42,
        rule_id="B105",
        cwe="CWE-259",
        remediation="Use environment variables",
        metadata={"confidence": "high"},
    )
    assert f.file_path == "/src/config.py"
    assert f.line_start == 42
    assert f.metadata["confidence"] == "high"


def test_scan_creation():
    s = Scan(target_path="/test/path", scan_types=[ScanType.CODE])
    assert s.id
    assert s.status == ScanStatus.PENDING
    assert s.findings_count == 0
    assert s.risk_score is None


def test_scan_request():
    sr = ScanRequest(target_path="/test")
    assert sr.scan_types == [ScanType.CODE, ScanType.DEPENDENCY]


def test_scan_summary():
    ss = ScanSummary(
        total_findings=10,
        critical=1,
        high=2,
        medium=3,
        low=4,
        info=0,
        risk_score=65.3,
        scanners_run=["semgrep", "bandit"],
    )
    assert ss.total_findings == 10
    assert ss.risk_score == 65.3


def test_scanner_skip_model():
    skip = ScannerSkip(name="bandit", reason="not installed", install_hint="pip install bandit")
    assert skip.name == "bandit"
    assert skip.reason == "not installed"
    assert skip.install_hint == "pip install bandit"
    # Round-trip via model_dump / parse to mirror DB JSON persistence.
    rebuilt = ScannerSkip(**skip.model_dump())
    assert rebuilt == skip


def test_scanner_skip_optional_install_hint():
    skip = ScannerSkip(name="trivy", reason="unavailable")
    assert skip.install_hint is None


def test_scan_has_scanners_run_and_skipped_defaults():
    s = Scan(target_path="/p", scan_types=[ScanType.CODE])
    assert s.scanners_run == []
    assert s.scanners_skipped == []
