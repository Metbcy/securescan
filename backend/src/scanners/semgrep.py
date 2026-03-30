import asyncio
import json
import shutil

from .base import BaseScanner
from ..models import Finding, ScanType, Severity
from ..config import settings


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    scan_type = ScanType.CODE

    async def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    @property
    def install_hint(self) -> str:
        return "pip install semgrep"

    async def scan(self, target_path: str, scan_id: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "semgrep", "scan", "--json", "--config", "auto", target_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=settings.scan_timeout
            )

            if stdout:
                data = json.loads(stdout.decode())
                results = data.get("results", [])
                for r in results:
                    severity = self._map_severity(r.get("extra", {}).get("severity", "INFO"))
                    findings.append(Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=severity,
                        title=r.get("check_id", "Unknown rule"),
                        description=r.get("extra", {}).get("message", "No description"),
                        file_path=r.get("path"),
                        line_start=r.get("start", {}).get("line"),
                        line_end=r.get("end", {}).get("line"),
                        rule_id=r.get("check_id"),
                        cwe=self._extract_cwe(r),
                        remediation=r.get("extra", {}).get("fix"),
                        metadata=r.get("extra", {}).get("metadata", {}),
                    ))
        except asyncio.TimeoutError:
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type,
                severity=Severity.INFO,
                title="Semgrep scan timed out",
                description=f"Scan timed out after {settings.scan_timeout}s",
            ))
        except Exception as e:
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type,
                severity=Severity.INFO,
                title="Semgrep scan error",
                description=str(e),
            ))
        return findings

    @staticmethod
    def _map_severity(semgrep_severity: str) -> Severity:
        mapping = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        return mapping.get(semgrep_severity.upper(), Severity.LOW)

    @staticmethod
    def _extract_cwe(result: dict) -> str | None:
        metadata = result.get("extra", {}).get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        if isinstance(cwe_list, list) and cwe_list:
            return cwe_list[0] if isinstance(cwe_list[0], str) else str(cwe_list[0])
        if isinstance(cwe_list, str):
            return cwe_list
        return None
