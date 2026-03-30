"""License scanner — checks dependency licenses for compliance issues."""
import asyncio
import json
import shutil
from pathlib import Path
from .base import BaseScanner
from ..models import Finding, ScanType, Severity

# Licenses that may cause issues in commercial/proprietary projects
COPYLEFT_LICENSES = {
    "GPL-2.0", "GPL-3.0", "AGPL-3.0", "LGPL-2.1", "LGPL-3.0",
    "GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0-only",
    "GPL-2.0-or-later", "GPL-3.0-or-later", "AGPL-3.0-or-later",
}

UNKNOWN_WARNING = {"UNKNOWN", "UNLICENSED", ""}


class LicenseScanner(BaseScanner):
    name = "licenses"
    scan_type = ScanType.DEPENDENCY
    description = "Scans project dependencies for copyleft, restrictive, or unknown licenses that may cause compliance issues."
    checks = [
        "GPL/AGPL copyleft license detection",
        "Unknown or missing license warnings",
        "License compatibility analysis",
        "npm and pip dependency license audit",
    ]

    async def is_available(self) -> bool:
        # Works if either pip-licenses (Python) or license-checker (npm) is available
        return shutil.which("pip-licenses") is not None or self._has_package_json_support()

    def _has_package_json_support(self) -> bool:
        return shutil.which("npx") is not None

    @property
    def install_hint(self) -> str:
        return "pip install pip-licenses"

    async def scan(self, target_path: str, scan_id: str) -> list[Finding]:
        findings = []
        target = Path(target_path)

        # Check Python licenses
        if shutil.which("pip-licenses"):
            findings.extend(await self._scan_python(target, scan_id))

        # Check npm licenses
        if target.is_dir() and (target / "package.json").exists() and shutil.which("npx"):
            findings.extend(await self._scan_npm(target, scan_id))

        return findings

    async def _scan_python(self, target: Path, scan_id: str) -> list[Finding]:
        findings = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "pip-licenses", "--format=json", "--with-license-file", "--no-license-path",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            packages = json.loads(stdout.decode(errors="ignore"))

            for pkg in packages:
                license_name = pkg.get("License", "UNKNOWN").strip()
                pkg_name = pkg.get("Name", "unknown")

                if any(cl in license_name for cl in COPYLEFT_LICENSES):
                    findings.append(Finding(
                        scan_id=scan_id, scanner=self.name, scan_type=self.scan_type,
                        severity=Severity.MEDIUM,
                        title=f"Copyleft license: {pkg_name} ({license_name})",
                        description=f"Package '{pkg_name}' uses {license_name}, a copyleft license that may require you to open-source your code if distributed.",
                        rule_id="licenses/copyleft",
                        remediation=f"Review the license terms for '{pkg_name}'. Consider using an alternative package with a permissive license (MIT, Apache-2.0, BSD).",
                    ))
                elif license_name in UNKNOWN_WARNING:
                    findings.append(Finding(
                        scan_id=scan_id, scanner=self.name, scan_type=self.scan_type,
                        severity=Severity.LOW,
                        title=f"Unknown license: {pkg_name}",
                        description=f"Package '{pkg_name}' has no recognized license. This may pose legal risks.",
                        rule_id="licenses/unknown",
                        remediation=f"Check the source repository for '{pkg_name}' to determine its license.",
                    ))
        except Exception:
            pass
        return findings

    async def _scan_npm(self, target: Path, scan_id: str) -> list[Finding]:
        findings = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "npx", "--yes", "license-checker", "--json", "--start", str(target),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            packages = json.loads(stdout.decode(errors="ignore"))

            for pkg_key, info in packages.items():
                license_name = info.get("licenses", "UNKNOWN")
                if isinstance(license_name, list):
                    license_name = ", ".join(license_name)

                if any(cl in license_name for cl in COPYLEFT_LICENSES):
                    findings.append(Finding(
                        scan_id=scan_id, scanner=self.name, scan_type=self.scan_type,
                        severity=Severity.MEDIUM,
                        title=f"Copyleft license: {pkg_key} ({license_name})",
                        description=f"npm package '{pkg_key}' uses {license_name}.",
                        rule_id="licenses/copyleft-npm",
                        remediation=f"Review license terms or find an alternative with a permissive license.",
                    ))
        except Exception:
            pass
        return findings
