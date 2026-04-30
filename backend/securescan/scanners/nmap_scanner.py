"""Nmap network scanner wrapper.

Runs ``nmap -sV -oX`` via asyncio subprocess (no shell=True) and parses the
XML output with defusedxml.  Risk classification is based on port number and
detected service name.
"""

import asyncio
import os
import re
import tempfile
from pathlib import Path

import defusedxml.ElementTree as ET

from ..config import settings
from ..models import Finding, ScanType, Severity
from .base import BaseScanner
from .discovery import find_tool

# ---------------------------------------------------------------------------
# Risk-classification tables
# ---------------------------------------------------------------------------

# Ports that are inherently high-risk regardless of service name
_HIGH_RISK_PORTS: set[int] = {
    21,  # FTP (plaintext credentials)
    23,  # Telnet
    5900,  # VNC (often unauthenticated)
    6379,  # Redis (commonly unauthenticated)
    27017,  # MongoDB (often unauthenticated)
    11211,  # Memcached (amplification attacks)
}

# Database and Windows management ports - medium risk
_MEDIUM_RISK_PORTS: set[int] = {
    3306,  # MySQL
    5432,  # PostgreSQL
    1433,  # MSSQL
    1521,  # Oracle
    135,  # MS-RPC
    139,  # NetBIOS
    445,  # SMB
    3389,  # RDP
}

# Service names that are inherently insecure (plaintext protocols)
_HIGH_RISK_SERVICES: set[str] = {"telnet", "ftp", "rsh", "rlogin"}

# Pattern for allowed target_host values (IPv4, IPv6, hostname, CIDR)
_TARGET_PATTERN = re.compile(
    r"^("
    r"(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?"
    r"|"
    r"[0-9a-fA-F:]+(/\d{1,3})?"
    r"|"
    r"[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*(/\d{1,2})?"
    r")$"
)


def _validate_target(host: str) -> bool:
    """Return True if host matches the allowed pattern (IPv4/IPv6/hostname/CIDR)."""
    return bool(_TARGET_PATTERN.match(host.strip()))


def _port_severity(port: int, service: str) -> Severity:
    service_lower = service.lower()
    if port in _HIGH_RISK_PORTS or service_lower in _HIGH_RISK_SERVICES:
        return Severity.HIGH
    if port in _MEDIUM_RISK_PORTS:
        return Severity.MEDIUM
    return Severity.INFO


class NmapScanner(BaseScanner):
    name = "nmap"
    scan_type = ScanType.NETWORK
    description = (
        "Nmap-based network scanner. Runs a service-version scan (-sV) and "
        "classifies open ports by risk level."
    )
    checks = [
        "Open port discovery",
        "Service/version detection (-sV)",
        "Risk classification of high-risk and database ports",
        "Detection of insecure plaintext services",
    ]

    @property
    def install_hint(self) -> str:
        return "Install nmap: https://nmap.org/download.html"

    async def is_available(self) -> bool:
        return find_tool("nmap") is not None

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        target_host: str | None = kwargs.get("target_host")
        if not target_host:
            return []

        if not _validate_target(target_host):
            return [
                Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.INFO,
                    title="Invalid target_host value",
                    description=(
                        f"The target_host '{target_host}' did not match the "
                        "allowed pattern (IPv4, IPv6, hostname, or CIDR)."
                    ),
                    metadata={"target_host": target_host},
                )
            ]

        with tempfile.TemporaryDirectory() as tmpdir:
            xml_path = os.path.join(tmpdir, "nmap_output.xml")
            # Build the argument list - NO shell=True, args never concatenated into a string
            nmap_bin = find_tool("nmap")
            if nmap_bin is None:
                return []
            cmd: list[str] = [nmap_bin, "-sV", "-oX", xml_path, target_host]
            if settings.nmap_extra_args:
                cmd.extend(settings.nmap_extra_args.split())

            # asyncio.create_subprocess_exec is safe: arguments are passed as a
            # list and never interpreted by a shell.
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=settings.scan_timeout,
            )

            if proc.returncode != 0:
                return [
                    Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.INFO,
                        title="Nmap scan error",
                        description=stderr.decode(errors="replace"),
                        metadata={"target_host": target_host},
                    )
                ]

            xml_content = Path(xml_path).read_text(encoding="utf-8", errors="replace")

        return self._parse_xml(xml_content, scan_id, target_host)

    def _parse_xml(
        self,
        xml_content: str,
        scan_id: str,
        target_host: str,
    ) -> list[Finding]:
        """Parse nmap XML output and return a list of findings."""
        findings: list[Finding] = []
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return findings

        for host_el in root.findall("host"):
            addr_el = host_el.find("address")
            host_addr = addr_el.get("addr", target_host) if addr_el is not None else target_host

            ports_el = host_el.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                port_num = int(port_el.get("portid", "0"))
                protocol = port_el.get("protocol", "tcp")

                service_el = port_el.find("service")
                service_name = ""
                product = ""
                version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")

                severity = _port_severity(port_num, service_name)
                display_service = (
                    " ".join(filter(None, [service_name, product, version])) or "unknown"
                )

                title = f"Open port {port_num}/{protocol}: {display_service}"
                description = (
                    f"Host {host_addr} has port {port_num}/{protocol} open "
                    f"running {display_service}."
                )
                if severity == Severity.HIGH:
                    description += (
                        " This service is considered high-risk due to known "
                        "security weaknesses or lack of encryption."
                    )
                elif severity == Severity.MEDIUM:
                    description += (
                        " This is a database or management port that should "
                        "not be exposed to untrusted networks."
                    )

                findings.append(
                    Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=severity,
                        title=title,
                        description=description,
                        rule_id=f"open-port-{port_num}",
                        remediation=(
                            "Close or firewall the port if it is not required. "
                            "Replace insecure services with encrypted equivalents."
                        ),
                        metadata={
                            "target_host": target_host,
                            "host_addr": host_addr,
                            "port": port_num,
                            "protocol": protocol,
                            "service": service_name,
                            "product": product,
                            "version": version,
                        },
                    )
                )

        return findings
