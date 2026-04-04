"""SBOM (Software Bill of Materials) generator for SecureScan."""

import asyncio
import json
import logging
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import SBOMComponent, SBOMDocument

logger = logging.getLogger(__name__)

# Directories to skip when searching for manifests
_SKIP_DIRS = {"node_modules", "vendor", ".git", "venv", ".venv", "__pycache__"}


class SBOMGenerator:
    """Generates a Software Bill of Materials for a given target path."""

    def __init__(self, target_path: str, scan_id: Optional[str] = None):
        self.target_path = Path(target_path).resolve()
        self.scan_id = scan_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def generate(self) -> SBOMDocument:
        """Generate an SBOM document. Tries Syft first, falls back to built-in parsers."""
        doc = SBOMDocument(
            target_path=str(self.target_path),
            scan_id=self.scan_id,
        )

        components: list[SBOMComponent] = []

        if shutil.which("syft"):
            try:
                components = await self._run_syft(doc.id)
            except Exception as exc:
                logger.warning("Syft failed (%s), falling back to built-in parsers.", exc)

        if not components:
            components = await self._builtin_parse(doc.id)

        # Deduplicate by purl (or name+version if no purl)
        seen: set[str] = set()
        unique: list[SBOMComponent] = []
        for comp in components:
            key = comp.purl if comp.purl else f"{comp.name}@{comp.version}"
            if key not in seen:
                seen.add(key)
                unique.append(comp)

        doc.components = unique
        return doc

    # ------------------------------------------------------------------
    # Syft integration
    # ------------------------------------------------------------------

    async def _run_syft(self, sbom_id: str) -> list[SBOMComponent]:
        # Uses create_subprocess_exec (not shell=True) — no injection risk
        proc = await asyncio.create_subprocess_exec(
            "syft", str(self.target_path), "-o", "cyclonedx-json", "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise RuntimeError(f"syft exited {proc.returncode}: {stderr.decode()[:200]}")

        data = json.loads(stdout.decode())
        components: list[SBOMComponent] = []
        for item in data.get("components", []):
            name = item.get("name", "")
            version = item.get("version", "")
            if not name:
                continue
            purl = item.get("purl")
            license_val: Optional[str] = None
            licenses = item.get("licenses", [])
            if licenses:
                lic = licenses[0]
                license_val = lic.get("expression") or lic.get("id") or lic.get("name")
            supplier: Optional[str] = None
            supplier_obj = item.get("supplier")
            if supplier_obj:
                supplier = supplier_obj.get("name")
            components.append(SBOMComponent(
                sbom_id=sbom_id,
                name=name,
                version=version or "unknown",
                type=item.get("type", "library"),
                purl=purl,
                license=license_val,
                supplier=supplier,
            ))
        return components

    # ------------------------------------------------------------------
    # Built-in manifest parsers
    # ------------------------------------------------------------------

    async def _builtin_parse(self, sbom_id: str) -> list[SBOMComponent]:
        components: list[SBOMComponent] = []
        manifest_map = {
            "package.json": self._parse_package_json,
            "requirements.txt": self._parse_requirements_txt,
            "go.mod": self._parse_go_mod,
            "Cargo.toml": self._parse_cargo_toml,
            "Gemfile.lock": self._parse_gemfile_lock,
            "composer.lock": self._parse_composer_lock,
            "Pipfile.lock": self._parse_pipfile_lock,
        }

        for manifest_name, parser in manifest_map.items():
            for manifest_path in self._find_manifests(manifest_name):
                try:
                    found = parser(manifest_path, sbom_id)
                    components.extend(found)
                except Exception as exc:
                    logger.warning("Failed to parse %s: %s", manifest_path, exc)

        return components

    def _find_manifests(self, filename: str) -> list[Path]:
        results: list[Path] = []
        try:
            for path in self.target_path.rglob(filename):
                # Check depth (max 4 levels below target)
                try:
                    rel = path.relative_to(self.target_path)
                except ValueError:
                    continue
                if len(rel.parts) > 5:  # 4 dirs + filename
                    continue
                # Skip excluded dirs
                if any(part in _SKIP_DIRS for part in rel.parts[:-1]):
                    continue
                results.append(path)
        except PermissionError:
            pass
        return results

    @staticmethod
    def _strip_semver(version: str) -> str:
        """Strip leading semver range operators."""
        return re.sub(r"^[\^~>=<\s]+", "", version).strip()

    def _parse_package_json(self, path: Path, sbom_id: str) -> list[SBOMComponent]:
        with open(path) as f:
            data = json.load(f)
        components: list[SBOMComponent] = []
        dep_sections = ["dependencies", "devDependencies", "peerDependencies"]
        for section in dep_sections:
            for name, version_spec in data.get(section, {}).items():
                if not isinstance(version_spec, str):
                    continue
                version = self._strip_semver(version_spec) or "unknown"
                purl = f"pkg:npm/{name}@{version}"
                components.append(SBOMComponent(
                    sbom_id=sbom_id,
                    name=name,
                    version=version,
                    purl=purl,
                ))
        return components

    def _parse_requirements_txt(self, path: Path, sbom_id: str) -> list[SBOMComponent]:
        components: list[SBOMComponent] = []
        with open(path) as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Handle inline comments
                line = line.split("#")[0].strip()
                # Parse name==version or name>=version etc.
                m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*[=><!\^~]+\s*([^\s,;]+)", line)
                if m:
                    name = m.group(1)
                    version = m.group(2).strip()
                else:
                    # Plain package name, no version
                    name = re.split(r"[\s=><!\^~\[;,]", line)[0]
                    version = "unknown"
                if not name:
                    continue
                purl = f"pkg:pypi/{name.lower()}@{version}"
                components.append(SBOMComponent(
                    sbom_id=sbom_id,
                    name=name,
                    version=version,
                    purl=purl,
                ))
        return components

    def _parse_go_mod(self, path: Path, sbom_id: str) -> list[SBOMComponent]:
        components: list[SBOMComponent] = []
        in_require = False
        with open(path) as f:
            for raw_line in f:
                line = raw_line.strip()
                if line.startswith("require ("):
                    in_require = True
                    continue
                if in_require and line == ")":
                    in_require = False
                    continue
                # Single-line require
                m_single = re.match(r"^require\s+(\S+)\s+(\S+)", line)
                if m_single:
                    module, version = m_single.group(1), m_single.group(2)
                    purl = f"pkg:golang/{module}@{version}"
                    components.append(SBOMComponent(
                        sbom_id=sbom_id,
                        name=module,
                        version=version,
                        purl=purl,
                    ))
                    continue
                if in_require and line and not line.startswith("//"):
                    parts = line.split()
                    if len(parts) >= 2:
                        module, version = parts[0], parts[1]
                        purl = f"pkg:golang/{module}@{version}"
                        components.append(SBOMComponent(
                            sbom_id=sbom_id,
                            name=module,
                            version=version,
                            purl=purl,
                        ))
        return components

    def _parse_cargo_toml(self, path: Path, sbom_id: str) -> list[SBOMComponent]:
        components: list[SBOMComponent] = []
        in_deps = False
        with open(path) as f:
            for raw_line in f:
                line = raw_line.strip()
                if line in ("[dependencies]", "[dev-dependencies]"):
                    in_deps = True
                    continue
                if line.startswith("[") and line not in ("[dependencies]", "[dev-dependencies]"):
                    in_deps = False
                    continue
                if not in_deps or not line or line.startswith("#"):
                    continue
                # name = "version" format
                m_simple = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"', line)
                if m_simple:
                    name, version = m_simple.group(1), m_simple.group(2)
                    version = self._strip_semver(version)
                    purl = f"pkg:cargo/{name}@{version}"
                    components.append(SBOMComponent(
                        sbom_id=sbom_id,
                        name=name,
                        version=version or "unknown",
                        purl=purl,
                    ))
                    continue
                # name = {version = "x", ...} format
                m_table = re.match(r'^([A-Za-z0-9_\-]+)\s*=\s*\{.*version\s*=\s*"([^"]+)"', line)
                if m_table:
                    name, version = m_table.group(1), m_table.group(2)
                    version = self._strip_semver(version)
                    purl = f"pkg:cargo/{name}@{version}"
                    components.append(SBOMComponent(
                        sbom_id=sbom_id,
                        name=name,
                        version=version or "unknown",
                        purl=purl,
                    ))
        return components

    def _parse_gemfile_lock(self, path: Path, sbom_id: str) -> list[SBOMComponent]:
        components: list[SBOMComponent] = []
        in_specs = False
        with open(path) as f:
            for raw_line in f:
                line = raw_line.rstrip()
                stripped = line.strip()
                if stripped == "specs:":
                    in_specs = True
                    continue
                if in_specs:
                    # Blank line or non-indented section header ends specs block
                    if not line.startswith(" ") and not line.startswith("\t"):
                        in_specs = False
                        continue
                    # Entries are indented with exactly 4 spaces: "    name (version)"
                    m = re.match(r"^    ([A-Za-z0-9_\-\.]+)\s+\(([^)]+)\)$", line)
                    if m:
                        name, version = m.group(1), m.group(2)
                        purl = f"pkg:gem/{name}@{version}"
                        components.append(SBOMComponent(
                            sbom_id=sbom_id,
                            name=name,
                            version=version,
                            purl=purl,
                        ))
        return components

    def _parse_composer_lock(self, path: Path, sbom_id: str) -> list[SBOMComponent]:
        components: list[SBOMComponent] = []
        with open(path) as f:
            data = json.load(f)
        for section in ["packages", "packages-dev"]:
            for pkg in data.get(section, []):
                name = pkg.get("name", "")
                version = pkg.get("version", "unknown")
                if not name:
                    continue
                # Strip leading "v" from version
                if version.startswith("v"):
                    version = version[1:]
                purl = f"pkg:composer/{name}@{version}"
                license_val: Optional[str] = None
                licenses = pkg.get("license", [])
                if licenses:
                    license_val = licenses[0] if isinstance(licenses, list) else str(licenses)
                components.append(SBOMComponent(
                    sbom_id=sbom_id,
                    name=name,
                    version=version,
                    purl=purl,
                    license=license_val,
                ))
        return components

    def _parse_pipfile_lock(self, path: Path, sbom_id: str) -> list[SBOMComponent]:
        components: list[SBOMComponent] = []
        with open(path) as f:
            data = json.load(f)
        for section in ["default", "develop"]:
            for name, info in data.get(section, {}).items():
                if not isinstance(info, dict):
                    continue
                version = info.get("version", "unknown")
                # Pipfile.lock versions look like "==1.2.3"
                version = re.sub(r"^==", "", version).strip()
                purl = f"pkg:pypi/{name.lower()}@{version}"
                components.append(SBOMComponent(
                    sbom_id=sbom_id,
                    name=name,
                    version=version,
                    purl=purl,
                ))
        return components

    # ------------------------------------------------------------------
    # Export methods
    # ------------------------------------------------------------------

    def export_cyclonedx(self, doc: SBOMDocument) -> dict:
        """Export SBOMDocument as CycloneDX 1.5 JSON."""
        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{doc.id}",
            "version": 1,
            "metadata": {
                "timestamp": doc.created_at.isoformat(),
                "tools": [{"name": "SecureScan", "version": "1.0"}],
                "component": {
                    "type": "application",
                    "name": Path(doc.target_path).name or doc.target_path,
                },
            },
            "components": [
                {
                    "type": comp.type,
                    "name": comp.name,
                    "version": comp.version,
                    "purl": comp.purl,
                    **({"licenses": [{"license": {"name": comp.license}}]} if comp.license else {}),
                    **({"supplier": {"name": comp.supplier}} if comp.supplier else {}),
                    "bom-ref": comp.id,
                }
                for comp in doc.components
            ],
        }

    def export_spdx(self, doc: SBOMDocument) -> dict:
        """Export SBOMDocument as SPDX 2.3 JSON."""
        doc_name = Path(doc.target_path).name or doc.target_path
        packages = []
        for comp in doc.components:
            pkg: dict = {
                "SPDXID": f"SPDXRef-{comp.id}",
                "name": comp.name,
                "versionInfo": comp.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
            }
            if comp.purl:
                pkg["externalRefs"] = [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": comp.purl,
                    }
                ]
            if comp.license:
                pkg["licenseConcluded"] = comp.license
                pkg["licenseDeclared"] = comp.license
            else:
                pkg["licenseConcluded"] = "NOASSERTION"
                pkg["licenseDeclared"] = "NOASSERTION"
            if comp.supplier:
                pkg["supplier"] = f"Organization: {comp.supplier}"
            packages.append(pkg)

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": doc_name,
            "documentNamespace": f"https://securescan.example.com/sbom/{doc.id}",
            "documentDescribes": [f"SPDXRef-{comp.id}" for comp in doc.components],
            "packages": packages,
            "creationInfo": {
                "created": doc.created_at.isoformat(),
                "creators": ["Tool: SecureScan-1.0"],
            },
        }
