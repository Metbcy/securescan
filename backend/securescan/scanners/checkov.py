"""Checkov IaC security scanner."""

import asyncio
import json

from ..config import settings
from ..models import Finding, ScanType, Severity
from .base import BaseScanner
from .discovery import find_tool


class CheckovScanner(BaseScanner):
    name = "checkov"
    scan_type = ScanType.IAC
    description = "Infrastructure as Code scanner that detects misconfigurations in Terraform, Kubernetes, Docker, and CloudFormation."
    checks = [
        "Overly permissive IAM policies",
        "Unencrypted storage & databases",
        "Open security groups & network rules",
        "Missing logging & monitoring",
        "Insecure Kubernetes pod configurations",
        "Docker security best practices",
    ]

    async def is_available(self) -> bool:
        return find_tool("checkov") is not None

    @property
    def install_hint(self) -> str:
        return "pip install checkov"

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        checkov_bin = find_tool("checkov")
        if checkov_bin is None:
            return findings
        try:
            proc = await asyncio.create_subprocess_exec(
                checkov_bin,
                "-d",
                target_path,
                "-o",
                "json",
                "--quiet",
                "--compact",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=settings.scan_timeout
            )

            if stdout:
                raw = stdout.decode()
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    return findings

                # Checkov can return a list of check-type results or a single dict
                check_results = data if isinstance(data, list) else [data]

                for check_block in check_results:
                    results = check_block.get("results", {})
                    failed_checks = results.get("failed_checks", [])

                    for check in failed_checks:
                        severity = self._map_severity(
                            check.get("check_result", {}).get("evaluated_keys_severity")
                            or check.get("severity")
                        )
                        guideline = check.get("guideline", "")
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                scanner=self.name,
                                scan_type=self.scan_type,
                                severity=severity,
                                title=check.get("check_id", "Unknown")
                                + ": "
                                + check.get("check_name", "Unknown check"),
                                description=check.get("check_name", "No description"),
                                file_path=check.get("file_path"),
                                line_start=check.get("file_line_range", [None])[0],
                                line_end=check.get("file_line_range", [None, None])[1]
                                if len(check.get("file_line_range", [])) > 1
                                else None,
                                rule_id=check.get("check_id"),
                                remediation=guideline if guideline else None,
                                metadata={
                                    "check_type": check_block.get("check_type", ""),
                                    "resource": check.get("resource", ""),
                                },
                            )
                        )
        except asyncio.TimeoutError:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.HIGH,
                    title="INCOMPLETE SCAN: Checkov scan timed out",
                    description=f"Scan timed out after {settings.scan_timeout}s",
                )
            )
        except Exception as e:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.INFO,
                    title="Checkov scan error",
                    description=str(e),
                )
            )
        return findings

    @staticmethod
    def _map_severity(checkov_severity: str | None) -> Severity:
        if not checkov_severity:
            return Severity.MEDIUM
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }
        return mapping.get(checkov_severity.upper(), Severity.MEDIUM)
