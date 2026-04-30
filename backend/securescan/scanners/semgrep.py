import asyncio
import json
import sys
from pathlib import Path

from ..config import settings
from ..models import Finding, ScanType, Severity
from .base import BaseScanner
from .discovery import find_tool


class SemgrepScanner(BaseScanner):
    name = "semgrep"
    scan_type = ScanType.CODE
    description = "Multi-language static analysis tool that finds bugs, vulnerabilities, and anti-patterns using pattern matching rules."
    checks = [
        "SQL injection & command injection",
        "Cross-site scripting (XSS)",
        "Insecure deserialization",
        "Hardcoded secrets in code",
        "OWASP Top 10 vulnerabilities",
        "Language-specific anti-patterns",
    ]

    async def is_available(self) -> bool:
        return find_tool("semgrep") is not None

    @property
    def install_hint(self) -> str:
        return "pip install semgrep"

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        semgrep_rules: list[Path] | None = kwargs.get("semgrep_rules")

        # Validate any user-supplied rule paths *before* invoking semgrep so a
        # typo in ``.securescan.yml`` fails fast instead of silently falling
        # back to ``--config auto`` (which would mask the misconfiguration).
        if semgrep_rules:
            for rule_path in semgrep_rules:
                p = Path(rule_path)
                if not p.exists():
                    raise FileNotFoundError(
                        f"Semgrep rule path does not exist: {p} "
                        f"(paths in .securescan.yml are resolved relative to "
                        f"the config file's directory)"
                    )

        if semgrep_rules:
            config_args: list[str] = []
            for rule_path in semgrep_rules:
                config_args.extend(["--config", str(rule_path)])
            print(
                f"using {len(semgrep_rules)} custom Semgrep rule pack(s): "
                f"{[str(p) for p in semgrep_rules]}",
                file=sys.stderr,
            )
        else:
            config_args = ["--config", "auto"]

        argv = ["semgrep", "scan", "--json", *config_args, target_path]

        # Resolve the semgrep path here too (in case it lives in our venv
        # rather than on PATH). Defensive: skip cleanly if missing.
        semgrep_bin = find_tool("semgrep")
        if semgrep_bin is None:
            return []
        argv[0] = semgrep_bin

        findings: list[Finding] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
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
                    findings.append(
                        Finding(
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
                        )
                    )
        except asyncio.TimeoutError:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.HIGH,
                    title="INCOMPLETE SCAN: Semgrep scan timed out",
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
                    title="Semgrep scan error",
                    description=str(e),
                )
            )
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
