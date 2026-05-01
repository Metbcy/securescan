import asyncio
import json
import os

from ..config import settings
from ..models import Finding, ScanType, Severity
from .base import BaseScanner
from .discovery import find_tool


class BanditScanner(BaseScanner):
    name = "bandit"
    scan_type = ScanType.CODE
    description = "Python-focused security linter that finds common security issues in Python code."
    checks = [
        "Use of unsafe functions (eval, exec, pickle)",
        "Hardcoded passwords & bind addresses",
        "Weak cryptographic algorithms",
        "SQL injection via string formatting",
        "Insecure temporary file creation",
        "Try/except with bare pass (error suppression)",
    ]

    async def is_available(self) -> bool:
        return find_tool("bandit") is not None

    @property
    def install_hint(self) -> str:
        return "pip install bandit"

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        findings: list[Finding] = []

        # Only scan if target contains Python files. Run the walk in a
        # worker thread — `os.walk` on a multi-thousand-file tree (e.g. a
        # Rust project's target/ dir) takes seconds of synchronous I/O,
        # which would otherwise block the asyncio event loop and stall
        # /health, SSE event delivery, and every other scanner.
        def _has_python_files(path: str) -> bool:
            for _root, _dirs, files in os.walk(path):
                if any(f.endswith(".py") for f in files):
                    return True
            return False

        has_python = await asyncio.to_thread(_has_python_files, target_path)
        if not has_python:
            return findings

        bandit_bin = find_tool("bandit")
        if bandit_bin is None:
            # Defensive: orchestrator skips scanners whose is_available()
            # is False, so this branch is only reachable if bandit was
            # uninstalled between the availability check and the scan.
            return findings

        try:
            proc = await asyncio.create_subprocess_exec(
                bandit_bin,
                "-r",
                target_path,
                "-f",
                "json",
                "--quiet",
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
                    severity = self._map_severity(
                        r.get("issue_severity", "LOW"),
                        r.get("issue_confidence", "LOW"),
                    )
                    cwe_data = r.get("issue_cwe", {})
                    cwe_str = None
                    if cwe_data and isinstance(cwe_data, dict):
                        cwe_id = cwe_data.get("id")
                        if cwe_id:
                            cwe_str = f"CWE-{cwe_id}"

                    findings.append(
                        Finding(
                            scan_id=scan_id,
                            scanner=self.name,
                            scan_type=self.scan_type,
                            severity=severity,
                            title=r.get("test_name", "Unknown issue"),
                            description=r.get("issue_text", "No description"),
                            file_path=r.get("filename"),
                            line_start=r.get("line_number"),
                            line_end=r.get("line_number"),
                            rule_id=r.get("test_id"),
                            cwe=cwe_str,
                            metadata={
                                "confidence": r.get("issue_confidence", "UNDEFINED"),
                                "more_info": r.get("more_info", ""),
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
                    title="INCOMPLETE SCAN: Bandit scan timed out",
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
                    title="Bandit scan error",
                    description=str(e),
                )
            )
        return findings

    @staticmethod
    def _map_severity(bandit_severity: str, bandit_confidence: str) -> Severity:
        sev = bandit_severity.upper()
        conf = bandit_confidence.upper()
        if sev == "HIGH" and conf == "HIGH":
            return Severity.HIGH
        if sev == "HIGH":
            return Severity.HIGH
        if sev == "MEDIUM":
            return Severity.MEDIUM
        if sev == "LOW":
            return Severity.LOW
        return Severity.LOW
