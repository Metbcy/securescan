import asyncio
import json
import shutil

from .base import BaseScanner
from ..models import Finding, ScanType, Severity
from ..config import settings


class TrivyScanner(BaseScanner):
    name = "trivy"
    scan_type = ScanType.DEPENDENCY

    async def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    @property
    def install_hint(self) -> str:
        return "See https://trivy.dev/latest/getting-started/installation/"

    async def scan(self, target_path: str, scan_id: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "trivy", "fs", "--format", "json", "--scanners", "vuln", target_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=settings.scan_timeout
            )

            if stdout:
                data = json.loads(stdout.decode())
                results = data.get("Results", [])
                for result in results:
                    vulns = result.get("Vulnerabilities") or []
                    target = result.get("Target", "")
                    for v in vulns:
                        severity = self._map_severity(v.get("Severity", "UNKNOWN"))
                        findings.append(Finding(
                            scan_id=scan_id,
                            scanner=self.name,
                            scan_type=self.scan_type,
                            severity=severity,
                            title=f"{v.get('VulnerabilityID', 'Unknown')} in {v.get('PkgName', 'unknown')}",
                            description=v.get("Description", v.get("Title", "No description")),
                            file_path=target,
                            rule_id=v.get("VulnerabilityID"),
                            cwe=self._extract_cwe(v),
                            remediation=f"Update to {v['FixedVersion']}" if v.get("FixedVersion") else None,
                            metadata={
                                "package": v.get("PkgName", ""),
                                "installed_version": v.get("InstalledVersion", ""),
                                "fixed_version": v.get("FixedVersion", ""),
                                "references": v.get("References", [])[:5],
                            },
                        ))
        except asyncio.TimeoutError:
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type,
                severity=Severity.INFO,
                title="Trivy scan timed out",
                description=f"Scan timed out after {settings.scan_timeout}s",
            ))
        except Exception as e:
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type,
                severity=Severity.INFO,
                title="Trivy scan error",
                description=str(e),
            ))
        return findings

    @staticmethod
    def _map_severity(trivy_severity: str) -> Severity:
        mapping = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "UNKNOWN": Severity.INFO,
        }
        return mapping.get(trivy_severity.upper(), Severity.INFO)

    @staticmethod
    def _extract_cwe(vuln: dict) -> str | None:
        cwe_ids = vuln.get("CweIDs", [])
        if cwe_ids:
            return cwe_ids[0]
        return None
