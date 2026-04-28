"""Tests for the Nmap network scanner."""
import asyncio
from unittest.mock import patch

import pytest

from securescan.scanners.nmap_scanner import (
    NmapScanner,
    _validate_target,
    _port_severity,
)
from securescan.models import ScanType, Severity


# ---------------------------------------------------------------------------
# Basic properties
# ---------------------------------------------------------------------------

def test_scanner_name():
    scanner = NmapScanner()
    assert scanner.name == "nmap"


def test_scanner_type():
    scanner = NmapScanner()
    assert scanner.scan_type == ScanType.NETWORK


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------

def test_available_when_nmap_found():
    scanner = NmapScanner()
    with patch("securescan.scanners.nmap_scanner.shutil.which", return_value="/usr/bin/nmap"):
        result = asyncio.run(scanner.is_available())
    assert result is True


def test_not_available_when_nmap_missing():
    scanner = NmapScanner()
    with patch("securescan.scanners.nmap_scanner.shutil.which", return_value=None):
        result = asyncio.run(scanner.is_available())
    assert result is False


# ---------------------------------------------------------------------------
# No target_host -> empty list
# ---------------------------------------------------------------------------

def test_no_target_host_returns_empty():
    scanner = NmapScanner()
    result = asyncio.run(scanner.scan("/path", "scan-1"))
    assert result == []


def test_none_target_host_returns_empty():
    scanner = NmapScanner()
    result = asyncio.run(scanner.scan("/path", "scan-1", target_host=None))
    assert result == []


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

def test_valid_ipv4():
    assert _validate_target("192.168.1.1") is True


def test_valid_ipv4_cidr():
    assert _validate_target("10.0.0.0/24") is True


def test_valid_hostname():
    assert _validate_target("example.com") is True


def test_valid_simple_hostname():
    assert _validate_target("localhost") is True


def test_invalid_target_shell_injection():
    assert _validate_target("192.168.1.1; rm -rf /") is False


def test_invalid_target_backtick():
    assert _validate_target("`id`") is False


def test_invalid_target_spaces():
    assert _validate_target("example.com extra") is False


# ---------------------------------------------------------------------------
# Port severity classification
# ---------------------------------------------------------------------------

def test_high_risk_ftp_port():
    assert _port_severity(21, "ftp") == Severity.HIGH


def test_high_risk_telnet_port():
    assert _port_severity(23, "telnet") == Severity.HIGH


def test_high_risk_redis_port():
    assert _port_severity(6379, "redis") == Severity.HIGH


def test_high_risk_mongo_port():
    assert _port_severity(27017, "mongodb") == Severity.HIGH


def test_high_risk_memcached_port():
    assert _port_severity(11211, "") == Severity.HIGH


def test_high_risk_vnc_port():
    assert _port_severity(5900, "vnc") == Severity.HIGH


def test_high_risk_service_name_telnet():
    assert _port_severity(2323, "telnet") == Severity.HIGH


def test_high_risk_service_name_ftp():
    assert _port_severity(2121, "ftp") == Severity.HIGH


def test_high_risk_service_rsh():
    assert _port_severity(514, "rsh") == Severity.HIGH


def test_high_risk_service_rlogin():
    assert _port_severity(513, "rlogin") == Severity.HIGH


def test_medium_risk_mysql():
    assert _port_severity(3306, "mysql") == Severity.MEDIUM


def test_medium_risk_postgres():
    assert _port_severity(5432, "postgresql") == Severity.MEDIUM


def test_medium_risk_mssql():
    assert _port_severity(1433, "ms-sql") == Severity.MEDIUM


def test_medium_risk_rdp():
    assert _port_severity(3389, "rdp") == Severity.MEDIUM


def test_medium_risk_smb():
    assert _port_severity(445, "smb") == Severity.MEDIUM


def test_info_risk_http():
    assert _port_severity(80, "http") == Severity.INFO


def test_info_risk_https():
    assert _port_severity(443, "https") == Severity.INFO


def test_info_risk_unknown_port():
    assert _port_severity(12345, "custom") == Severity.INFO


# ---------------------------------------------------------------------------
# XML parsing
# ---------------------------------------------------------------------------

SAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="21">
        <state state="open" reason="syn-ack"/>
        <service name="ftp" product="vsftpd" version="3.0.3"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="8.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.20"/>
      </port>
      <port protocol="tcp" portid="9999">
        <state state="closed" reason="reset"/>
        <service name="http" product="nginx" version="1.20"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

SAMPLE_XML_NO_PORTS = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
  </host>
</nmaprun>
"""


def test_parse_xml_open_ports():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML, "scan-1", "10.0.0.1")
    # Only open ports should generate findings (closed port 9999 excluded)
    assert len(findings) == 4


def test_parse_xml_closed_port_excluded():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML, "scan-1", "10.0.0.1")
    ports = [f.metadata["port"] for f in findings]
    assert 9999 not in ports


def test_parse_xml_ftp_is_high():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML, "scan-1", "10.0.0.1")
    ftp = next(f for f in findings if f.metadata["port"] == 21)
    assert ftp.severity == Severity.HIGH


def test_parse_xml_mysql_is_medium():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML, "scan-1", "10.0.0.1")
    mysql = next(f for f in findings if f.metadata["port"] == 3306)
    assert mysql.severity == Severity.MEDIUM


def test_parse_xml_http_is_info():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML, "scan-1", "10.0.0.1")
    http = next(f for f in findings if f.metadata["port"] == 80)
    assert http.severity == Severity.INFO


def test_parse_xml_ssh_is_info():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML, "scan-1", "10.0.0.1")
    ssh = next(f for f in findings if f.metadata["port"] == 22)
    assert ssh.severity == Severity.INFO


def test_parse_xml_finding_fields():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML, "scan-42", "10.0.0.1")
    for f in findings:
        assert f.scan_id == "scan-42"
        assert f.scanner == "nmap"
        assert f.scan_type == ScanType.NETWORK
        assert f.rule_id.startswith("open-port-")


def test_parse_xml_no_ports_element():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML_NO_PORTS, "scan-1", "10.0.0.2")
    assert findings == []


def test_parse_xml_invalid_xml():
    scanner = NmapScanner()
    findings = scanner._parse_xml("<not valid xml>>>>>", "scan-1", "10.0.0.1")
    assert findings == []


def test_parse_xml_empty_string():
    scanner = NmapScanner()
    findings = scanner._parse_xml("", "scan-1", "10.0.0.1")
    assert findings == []


def test_parse_xml_host_addr_in_metadata():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML, "scan-1", "10.0.0.1")
    for f in findings:
        assert f.metadata["host_addr"] == "10.0.0.1"


def test_parse_xml_service_details_in_title():
    scanner = NmapScanner()
    findings = scanner._parse_xml(SAMPLE_XML, "scan-1", "10.0.0.1")
    ftp = next(f for f in findings if f.metadata["port"] == 21)
    assert "ftp" in ftp.title.lower()
    assert "vsftpd" in ftp.title


def test_invalid_host_returns_info_finding():
    scanner = NmapScanner()
    result = asyncio.run(scanner.scan("/path", "scan-bad", target_host="bad host; ls"))
    assert len(result) == 1
    assert result[0].severity == Severity.INFO
    assert "Invalid" in result[0].title
