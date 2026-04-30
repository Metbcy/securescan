"""Tests for the built-in DAST scanner."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from securescan.models import ScanType, Severity
from securescan.scanners.dast_builtin import BuiltinDastScanner

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(headers: dict, cookies: list[str] | None = None) -> MagicMock:
    """Build a minimal httpx.Response mock."""
    resp = MagicMock(spec=httpx.Response)

    # Build a case-insensitive headers object backed by a plain dict
    raw_headers: list[tuple[bytes, bytes]] = []
    for k, v in headers.items():
        raw_headers.append((k.lower().encode(), v.encode()))
    if cookies:
        for c in cookies:
            raw_headers.append((b"set-cookie", c.encode()))

    real_headers = httpx.Headers(raw_headers)
    resp.headers = real_headers
    return resp


# ---------------------------------------------------------------------------
# Basic properties
# ---------------------------------------------------------------------------


def test_scanner_name():
    scanner = BuiltinDastScanner()
    assert scanner.name == "builtin_dast"


def test_scanner_type():
    scanner = BuiltinDastScanner()
    assert scanner.scan_type == ScanType.DAST


def test_always_available():
    scanner = BuiltinDastScanner()
    assert asyncio.run(scanner.is_available()) is True


# ---------------------------------------------------------------------------
# No target_url → empty list
# ---------------------------------------------------------------------------


def test_no_target_url_returns_empty():
    scanner = BuiltinDastScanner()
    result = asyncio.run(scanner.scan("/some/path", "scan-1"))
    assert result == []


def test_empty_target_url_kwarg_returns_empty():
    scanner = BuiltinDastScanner()
    result = asyncio.run(scanner.scan("/some/path", "scan-1", target_url=None))
    assert result == []


# ---------------------------------------------------------------------------
# Security header checks
# ---------------------------------------------------------------------------


def test_missing_all_security_headers():
    scanner = BuiltinDastScanner()
    response = _make_response({})
    findings = scanner._check_security_headers(response, "s1", "http://example.com")
    rule_ids = {f.rule_id for f in findings}
    assert "missing-header-strict-transport-security" in rule_ids
    assert "missing-header-content-security-policy" in rule_ids
    assert "missing-header-x-content-type-options" in rule_ids
    assert "missing-header-x-frame-options" in rule_ids
    assert "missing-header-referrer-policy" in rule_ids
    assert "missing-header-permissions-policy" in rule_ids
    assert len(findings) == 6


def test_all_security_headers_present():
    scanner = BuiltinDastScanner()
    headers = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()",
    }
    response = _make_response(headers)
    findings = scanner._check_security_headers(response, "s1", "http://example.com")
    assert findings == []


def test_partial_security_headers():
    scanner = BuiltinDastScanner()
    headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }
    response = _make_response(headers)
    findings = scanner._check_security_headers(response, "s1", "http://example.com")
    assert len(findings) == 4
    for f in findings:
        assert f.severity == Severity.MEDIUM


# ---------------------------------------------------------------------------
# Information-disclosure header checks
# ---------------------------------------------------------------------------


def test_info_disclosure_server_header():
    scanner = BuiltinDastScanner()
    response = _make_response({"Server": "Apache/2.4.51"})
    findings = scanner._check_info_disclosure_headers(response, "s1", "http://example.com")
    assert len(findings) == 1
    assert findings[0].rule_id == "info-disclosure-server"
    assert findings[0].severity == Severity.LOW
    assert "Apache/2.4.51" in findings[0].description


def test_info_disclosure_x_powered_by():
    scanner = BuiltinDastScanner()
    response = _make_response({"X-Powered-By": "PHP/8.1"})
    findings = scanner._check_info_disclosure_headers(response, "s1", "http://example.com")
    assert len(findings) == 1
    assert findings[0].rule_id == "info-disclosure-x-powered-by"


def test_no_info_disclosure_headers():
    scanner = BuiltinDastScanner()
    response = _make_response({"Content-Type": "text/html"})
    findings = scanner._check_info_disclosure_headers(response, "s1", "http://example.com")
    assert findings == []


# ---------------------------------------------------------------------------
# Cookie flag checks
# ---------------------------------------------------------------------------


def test_cookie_missing_secure_and_httponly():
    scanner = BuiltinDastScanner()
    response = _make_response({}, cookies=["session=abc123; Path=/"])
    findings = scanner._check_cookies(response, "s1", "http://example.com")
    rule_ids = {f.rule_id for f in findings}
    assert "cookie-missing-secure" in rule_ids
    assert "cookie-missing-httponly" in rule_ids


def test_cookie_with_all_flags():
    scanner = BuiltinDastScanner()
    response = _make_response({}, cookies=["session=abc123; Path=/; Secure; HttpOnly"])
    findings = scanner._check_cookies(response, "s1", "http://example.com")
    assert findings == []


def test_cookie_missing_only_secure():
    scanner = BuiltinDastScanner()
    response = _make_response({}, cookies=["session=abc123; Path=/; HttpOnly"])
    findings = scanner._check_cookies(response, "s1", "http://example.com")
    assert len(findings) == 1
    assert findings[0].rule_id == "cookie-missing-secure"


def test_cookie_missing_only_httponly():
    scanner = BuiltinDastScanner()
    response = _make_response({}, cookies=["session=abc123; Path=/; Secure"])
    findings = scanner._check_cookies(response, "s1", "http://example.com")
    assert len(findings) == 1
    assert findings[0].rule_id == "cookie-missing-httponly"


def test_multiple_cookies():
    scanner = BuiltinDastScanner()
    response = _make_response(
        {},
        cookies=[
            "sess=1; Secure; HttpOnly",
            "pref=dark; Path=/",  # missing both flags
        ],
    )
    findings = scanner._check_cookies(response, "s1", "http://example.com")
    # sess is fine, pref is missing both
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# Full scan integration (mocked httpx)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_full_scan_with_mock():
    """scan() calls httpx and aggregates findings from all checks."""
    scanner = BuiltinDastScanner()

    mock_response = _make_response(
        {"Server": "nginx/1.20"},
        cookies=["token=xyz; Path=/"],
    )

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(return_value=mock_response)

    with patch("securescan.scanners.dast_builtin.httpx.AsyncClient", return_value=mock_client):
        findings = await scanner.scan("/path", "scan-99", target_url="http://example.com")

    assert len(findings) > 0
    titles = [f.title for f in findings]
    # Should have missing security headers
    assert any("Missing security header" in t for t in titles)
    # Should have info-disclosure finding for Server header
    assert any("Server" in t for t in titles)
    # Should have cookie findings
    assert any("Cookie" in t for t in titles)
    # All findings reference correct scan/scanner
    for f in findings:
        assert f.scan_id == "scan-99"
        assert f.scanner == "builtin_dast"
        assert f.scan_type == ScanType.DAST


@pytest.mark.asyncio
async def test_scan_handles_request_error():
    """scan() returns an INFO finding when the HTTP request fails."""
    scanner = BuiltinDastScanner()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

    with patch("securescan.scanners.dast_builtin.httpx.AsyncClient", return_value=mock_client):
        findings = await scanner.scan("/path", "scan-err", target_url="http://unreachable.local")

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "request failed" in findings[0].title
