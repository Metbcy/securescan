"""Safety scanner — checks Python dependencies for known vulnerabilities."""

import asyncio
from pathlib import Path

from ..models import Finding, ScanType, Severity
from .base import BaseScanner
from .discovery import find_tool


class SafetyScanner(BaseScanner):
    name = "safety"
    scan_type = ScanType.DEPENDENCY
    description = "Scans Python dependencies (requirements.txt, Pipfile) for packages with known security vulnerabilities."
    checks = [
        "Known CVEs in Python packages",
        "Outdated packages with security fixes",
        "Insecure package versions",
        "requirements.txt vulnerability audit",
    ]

    async def is_available(self) -> bool:
        return find_tool("safety") is not None

    @property
    def install_hint(self) -> str:
        return "pip install safety"

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        findings = []
        target = Path(target_path)
        safety_bin = find_tool("safety")
        if safety_bin is None:
            return findings

        # Find requirements files. rglob is sync — offload to a thread
        # so the event loop stays responsive on large project trees.
        req_files = []
        if target.is_file() and target.name in ("requirements.txt", "Pipfile.lock"):
            req_files = [target]
        elif target.is_dir():
            req_files = await asyncio.to_thread(lambda: list(target.rglob("requirements*.txt")))

        if not req_files:
            return findings

        for req_file in req_files:
            try:
                proc = await asyncio.create_subprocess_exec(
                    safety_bin,
                    "check",
                    "--file",
                    str(req_file),
                    "--json",
                    "--output",
                    "json",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                output = stdout.decode(errors="ignore")

                if output.strip():
                    import json

                    try:
                        data = json.loads(output)
                        vulns = data if isinstance(data, list) else data.get("vulnerabilities", [])
                        for vuln in vulns:
                            # Safety output format varies by version
                            if isinstance(vuln, list):
                                # Old format: [package, affected, installed, description, id]
                                pkg = vuln[0] if len(vuln) > 0 else "unknown"
                                desc = vuln[3] if len(vuln) > 3 else "Vulnerability found"
                                vuln_id = vuln[4] if len(vuln) > 4 else None
                                findings.append(
                                    Finding(
                                        scan_id=scan_id,
                                        scanner=self.name,
                                        scan_type=self.scan_type,
                                        severity=Severity.HIGH,
                                        title=f"Vulnerable package: {pkg}",
                                        description=desc[:500],
                                        file_path=str(req_file),
                                        rule_id=f"safety/{vuln_id}" if vuln_id else None,
                                        remediation=f"Update {pkg} to a patched version.",
                                    )
                                )
                            elif isinstance(vuln, dict):
                                findings.append(
                                    Finding(
                                        scan_id=scan_id,
                                        scanner=self.name,
                                        scan_type=self.scan_type,
                                        severity=Severity.HIGH,
                                        title=f"Vulnerable package: {vuln.get('package_name', 'unknown')}",
                                        description=vuln.get("advisory", "Vulnerability found")[
                                            :500
                                        ],
                                        file_path=str(req_file),
                                        rule_id=f"safety/{vuln.get('vulnerability_id', '')}",
                                        remediation=f"Update to version {vuln.get('analyzed_version', 'latest')} or newer.",
                                    )
                                )
                    except json.JSONDecodeError:
                        pass
            except asyncio.TimeoutError:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.HIGH,
                        title="INCOMPLETE SCAN: Safety timed out",
                        description="Safety scan timed out. Results may be incomplete.",
                    )
                )
            except Exception:
                pass

        return findings
