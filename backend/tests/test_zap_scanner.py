"""Tests for the OWASP ZAP scanner wrapper."""
import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from securescan.scanners.zap_scanner import ZapScanner, _RISK_MAP
from securescan.models import ScanType, Severity


# ---------------------------------------------------------------------------
# Basic properties
# ---------------------------------------------------------------------------

def test_scanner_name():
    scanner = ZapScanner()
    assert scanner.name == "zap"


def test_scanner_type():
    scanner = ZapScanner()
    assert scanner.scan_type == ScanType.DAST


# ---------------------------------------------------------------------------
# Availability checks
# ---------------------------------------------------------------------------

def test_not_available_when_no_zapv2():
    """is_available returns False when zapv2 cannot be imported."""
    with patch("securescan.scanners.zap_scanner._ZAP_AVAILABLE", False):
        scanner = ZapScanner()
        result = asyncio.run(scanner.is_available())
    assert result is False


def test_not_available_when_zap_not_running():
    """is_available returns False when the ZAP daemon raises an exception."""
    mock_zap = MagicMock()
    type(mock_zap.core).version = property(
        lambda self: (_ for _ in ()).throw(Exception("Connection refused"))
    )

    scanner = ZapScanner()
    with patch("securescan.scanners.zap_scanner._ZAP_AVAILABLE", True), \
         patch.object(scanner, "_make_zap", return_value=mock_zap):
        result = asyncio.run(scanner.is_available())
    assert result is False


def test_available_when_zap_running():
    """is_available returns True when ZAP responds to version check."""
    mock_zap = MagicMock()
    mock_zap.core.version = "2.14.0"

    scanner = ZapScanner()
    with patch("securescan.scanners.zap_scanner._ZAP_AVAILABLE", True), \
         patch.object(scanner, "_make_zap", return_value=mock_zap):
        result = asyncio.run(scanner.is_available())
    assert result is True


# ---------------------------------------------------------------------------
# No target_url → empty list
# ---------------------------------------------------------------------------

def test_no_target_url_returns_empty():
    scanner = ZapScanner()
    result = asyncio.run(scanner.scan("/path", "scan-1"))
    assert result == []


def test_none_target_url_returns_empty():
    scanner = ZapScanner()
    result = asyncio.run(scanner.scan("/path", "scan-1", target_url=None))
    assert result == []


# ---------------------------------------------------------------------------
# Alert → Finding mapping
# ---------------------------------------------------------------------------

def test_alerts_to_findings_high_risk():
    scanner = ZapScanner()
    alerts = [
        {
            "riskcode": "3",
            "alert": "SQL Injection",
            "description": "SQL Injection found",
            "pluginid": "40018",
            "solution": "Use parameterised queries",
            "url": "http://example.com/search",
            "param": "q",
            "evidence": "' OR '1'='1",
            "cweid": "89",
            "wascid": "19",
        }
    ]
    findings = scanner._alerts_to_findings(alerts, "scan-1", "http://example.com")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.title == "SQL Injection"
    assert f.rule_id == "zap-40018"
    assert f.scan_id == "scan-1"
    assert f.scanner == "zap"
    assert f.scan_type == ScanType.DAST
    assert f.remediation == "Use parameterised queries"
    assert f.metadata["cweid"] == "89"


def test_alerts_to_findings_medium_risk():
    scanner = ZapScanner()
    alerts = [{"riskcode": "2", "alert": "XSS", "description": "Cross-site scripting",
                "pluginid": "40012", "solution": "Encode output",
                "url": "", "param": "", "evidence": "", "cweid": "", "wascid": ""}]
    findings = scanner._alerts_to_findings(alerts, "scan-1", "http://example.com")
    assert findings[0].severity == Severity.MEDIUM


def test_alerts_to_findings_low_risk():
    scanner = ZapScanner()
    alerts = [{"riskcode": "1", "alert": "Cookie no HttpOnly", "description": "...",
                "pluginid": "10010", "solution": "Set HttpOnly",
                "url": "", "param": "", "evidence": "", "cweid": "", "wascid": ""}]
    findings = scanner._alerts_to_findings(alerts, "scan-1", "http://example.com")
    assert findings[0].severity == Severity.LOW


def test_alerts_to_findings_info_risk():
    scanner = ZapScanner()
    alerts = [{"riskcode": "0", "alert": "Info Leak", "description": "...",
                "pluginid": "10001", "solution": "",
                "url": "", "param": "", "evidence": "", "cweid": "", "wascid": ""}]
    findings = scanner._alerts_to_findings(alerts, "scan-1", "http://example.com")
    assert findings[0].severity == Severity.INFO


def test_alerts_to_findings_empty():
    scanner = ZapScanner()
    findings = scanner._alerts_to_findings([], "scan-1", "http://example.com")
    assert findings == []


def test_alerts_to_findings_unknown_risk_defaults_to_info():
    scanner = ZapScanner()
    alerts = [{"riskcode": "99", "alert": "Unknown", "description": "",
                "pluginid": "99999", "solution": "",
                "url": "", "param": "", "evidence": "", "cweid": "", "wascid": ""}]
    findings = scanner._alerts_to_findings(alerts, "scan-1", "http://example.com")
    assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------------------
# Full scan (mocked ZAP)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_scan_calls_spider_and_active_scan():
    """scan() runs spider then active scan and returns mapped findings."""
    scanner = ZapScanner()

    mock_zap = MagicMock()
    # Spider
    mock_zap.spider.scan.return_value = "1"
    mock_zap.spider.status.side_effect = ["50", "100"]
    # Active scan
    mock_zap.ascan.scan.return_value = "2"
    mock_zap.ascan.status.side_effect = ["50", "100"]
    # Alerts
    mock_zap.core.alerts.return_value = [
        {"riskcode": "3", "alert": "SQL Injection", "description": "SQLi found",
         "pluginid": "40018", "solution": "Use params",
         "url": "http://t.com/q", "param": "id", "evidence": "1=1", "cweid": "89", "wascid": "19"}
    ]

    with patch("securescan.scanners.zap_scanner._ZAP_AVAILABLE", True), \
         patch.object(scanner, "_make_zap", return_value=mock_zap):
        findings = await scanner.scan("/path", "scan-z", target_url="http://t.com")

    assert len(findings) == 1
    assert findings[0].title == "SQL Injection"
    assert findings[0].severity == Severity.HIGH
    mock_zap.spider.scan.assert_called_once_with("http://t.com")
    mock_zap.ascan.scan.assert_called_once_with("http://t.com")


@pytest.mark.asyncio
async def test_scan_returns_empty_when_no_zap():
    """scan() returns empty list when _make_zap returns None."""
    scanner = ZapScanner()
    with patch.object(scanner, "_make_zap", return_value=None):
        findings = await scanner.scan("/path", "scan-z", target_url="http://t.com")
    assert findings == []
