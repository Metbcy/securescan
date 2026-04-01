"""Tests for compliance mapping engine."""
import json
import tempfile
from pathlib import Path

from src.compliance import ComplianceMapper
from src.models import Finding, ScanType, Severity


def _make_finding(
    cwe: str | None = None,
    rule_id: str | None = None,
    title: str = "Test finding",
    scanner: str = "test",
) -> Finding:
    return Finding(
        scan_id="test",
        scanner=scanner,
        scan_type=ScanType.CODE,
        severity=Severity.HIGH,
        title=title,
        description="Test description",
        cwe=cwe,
        rule_id=rule_id,
    )


def _make_data_dir() -> Path:
    """Create a temp dir with a minimal framework file for testing."""
    d = Path(tempfile.mkdtemp())
    framework = {
        "framework": "Test Framework",
        "version": "1.0",
        "controls": {
            "TEST-01": {
                "name": "Injection Prevention",
                "cwes": ["CWE-89", "CWE-79"],
                "keywords": ["SQL injection", "XSS"],
                "rule_ids": {"semgrep": ["rules.python.sql-injection"]},
            },
            "TEST-02": {
                "name": "Crypto",
                "cwes": ["CWE-327"],
                "keywords": ["weak cipher", "encryption"],
                "rule_ids": {},
            },
        },
    }
    (d / "test-framework.json").write_text(json.dumps(framework))
    return d


def test_load_frameworks():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    frameworks = mapper.list_frameworks()
    assert len(frameworks) == 1
    assert frameworks[0]["id"] == "test-framework"
    assert frameworks[0]["name"] == "Test Framework"
    assert frameworks[0]["total_controls"] == 2


def test_tag_by_cwe():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    finding = _make_finding(cwe="CWE-89")
    tags = mapper.tag_finding(finding)
    assert "TEST-01" in tags


def test_tag_by_rule_id():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    finding = _make_finding(rule_id="rules.python.sql-injection", scanner="semgrep")
    tags = mapper.tag_finding(finding)
    assert "TEST-01" in tags


def test_tag_by_keyword():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    finding = _make_finding(title="Possible SQL injection in query builder")
    tags = mapper.tag_finding(finding)
    assert "TEST-01" in tags


def test_no_match():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    finding = _make_finding(title="Unused variable")
    tags = mapper.tag_finding(finding)
    assert tags == []


def test_tag_findings_in_place():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    findings = [
        _make_finding(cwe="CWE-89"),
        _make_finding(title="Unused variable"),
        _make_finding(title="Weak cipher detected in TLS config"),
    ]
    mapper.tag_findings(findings)
    assert "TEST-01" in findings[0].compliance_tags
    assert findings[1].compliance_tags == []
    assert "TEST-02" in findings[2].compliance_tags


def test_multiple_framework_tags():
    """A finding can match controls across multiple frameworks."""
    d = Path(tempfile.mkdtemp())
    fw1 = {
        "framework": "FW1", "version": "1", "controls": {
            "FW1-A": {"name": "A", "cwes": ["CWE-89"], "keywords": [], "rule_ids": {}},
        }
    }
    fw2 = {
        "framework": "FW2", "version": "1", "controls": {
            "FW2-X": {"name": "X", "cwes": ["CWE-89"], "keywords": [], "rule_ids": {}},
        }
    }
    (d / "fw1.json").write_text(json.dumps(fw1))
    (d / "fw2.json").write_text(json.dumps(fw2))
    mapper = ComplianceMapper(d)
    finding = _make_finding(cwe="CWE-89")
    tags = mapper.tag_finding(finding)
    assert "FW1-A" in tags
    assert "FW2-X" in tags


def test_compliance_coverage():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    findings = [_make_finding(cwe="CWE-89")]
    mapper.tag_findings(findings)
    coverage = mapper.get_coverage(findings)
    assert len(coverage) == 1
    c = coverage[0]
    assert c["framework"] == "Test Framework"
    assert "TEST-01" in c["controls_violated"]
    assert "TEST-02" in c["controls_clear"]
    assert c["coverage_percentage"] == 50.0
