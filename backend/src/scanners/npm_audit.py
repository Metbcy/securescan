"""npm audit scanner — checks npm dependencies for known vulnerabilities."""
import asyncio
import json
import shutil
from pathlib import Path
from .base import BaseScanner
from ..models import Finding, ScanType, Severity

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class NpmAuditScanner(BaseScanner):
    name = "npm-audit"
    scan_type = ScanType.DEPENDENCY
    description = "Runs npm audit to find known vulnerabilities in JavaScript/Node.js package dependencies."
    checks = [
        "Known CVEs in npm packages",
        "Outdated packages with security patches",
        "Transitive dependency vulnerabilities",
        "npm advisory database checks",
    ]

    async def is_available(self) -> bool:
        return shutil.which("npm") is not None

    @property
    def install_hint(self) -> str:
        return "Install Node.js from https://nodejs.org"

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        findings = []
        target = Path(target_path)

        # Find package.json files (but skip node_modules)
        pkg_dirs = []
        if target.is_dir() and (target / "package.json").exists():
            pkg_dirs = [target]
        elif target.is_dir():
            for pj in target.rglob("package.json"):
                if "node_modules" not in str(pj):
                    pkg_dirs.append(pj.parent)

        for pkg_dir in pkg_dirs[:5]:  # Limit to 5 projects
            # Need both package.json and package-lock.json for npm audit
            if not (pkg_dir / "package-lock.json").exists():
                continue

            try:
                proc = await asyncio.create_subprocess_exec(
                    "npm", "audit", "--json",
                    cwd=str(pkg_dir),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                output = stdout.decode(errors="ignore")

                if not output.strip():
                    continue

                data = json.loads(output)

                # npm audit v2 format (npm 7+)
                vulns = data.get("vulnerabilities", {})
                for pkg_name, vuln_info in vulns.items():
                    severity = SEVERITY_MAP.get(vuln_info.get("severity", ""), Severity.MEDIUM)
                    via = vuln_info.get("via", [])

                    # Get advisory details
                    desc_parts = []
                    for v in via:
                        if isinstance(v, dict):
                            desc_parts.append(v.get("title", ""))

                    description = "; ".join(filter(None, desc_parts)) or f"Vulnerability in {pkg_name}"
                    fix_available = vuln_info.get("fixAvailable", False)

                    findings.append(Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=severity,
                        title=f"Vulnerable npm package: {pkg_name}",
                        description=description[:500],
                        file_path=str(pkg_dir / "package.json"),
                        rule_id=f"npm-audit/{pkg_name}",
                        remediation=f"Run 'npm audit fix' to auto-fix, or manually update {pkg_name}." if fix_available else f"Check for updates to {pkg_name} or find an alternative package.",
                        metadata={"fix_available": fix_available, "range": vuln_info.get("range", "")},
                    ))

            except asyncio.TimeoutError:
                findings.append(Finding(
                    scan_id=scan_id, scanner=self.name, scan_type=self.scan_type,
                    severity=Severity.HIGH,
                    title="INCOMPLETE SCAN: npm audit timed out",
                    description=f"npm audit timed out for {pkg_dir}.",
                ))
            except (json.JSONDecodeError, Exception):
                pass

        return findings
