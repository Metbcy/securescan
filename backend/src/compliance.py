"""Data-driven compliance framework mapping engine."""
import json
from pathlib import Path

from .models import Finding


class ComplianceMapper:
    """Maps findings to compliance framework controls using CWE, rule_id, and keyword matching."""

    def __init__(self, data_dir: Path):
        self._frameworks: dict[str, dict] = {}
        self._cwe_index: dict[str, list[str]] = {}
        self._rule_index: dict[str, list[str]] = {}
        self._keyword_index: list[tuple[str, str]] = []
        self._load(data_dir)

    def _load(self, data_dir: Path) -> None:
        for path in sorted(data_dir.glob("*.json")):
            raw = json.loads(path.read_text())
            fw_id = path.stem
            self._frameworks[fw_id] = raw
            for ctrl_id, ctrl in raw.get("controls", {}).items():
                for cwe in ctrl.get("cwes", []):
                    self._cwe_index.setdefault(cwe, []).append(ctrl_id)
                for scanner, rules in ctrl.get("rule_ids", {}).items():
                    for rule in rules:
                        key = f"{scanner}:{rule}"
                        self._rule_index.setdefault(key, []).append(ctrl_id)
                for kw in ctrl.get("keywords", []):
                    self._keyword_index.append((kw.lower(), ctrl_id))

    def tag_finding(self, finding: Finding) -> list[str]:
        """Return deduplicated compliance tags for a single finding."""
        tags: set[str] = set()
        if finding.cwe:
            cwe_normalized = finding.cwe.strip()
            if not cwe_normalized.startswith("CWE-"):
                num = cwe_normalized.split(":")[-1].split("-")[-1].strip()
                cwe_normalized = f"CWE-{num}"
            tags.update(self._cwe_index.get(cwe_normalized, []))
        if finding.rule_id and finding.scanner:
            key = f"{finding.scanner}:{finding.rule_id}"
            tags.update(self._rule_index.get(key, []))
        title_lower = finding.title.lower()
        for kw, ctrl_id in self._keyword_index:
            if kw in title_lower:
                tags.add(ctrl_id)
        return sorted(tags)

    def tag_findings(self, findings: list[Finding]) -> None:
        """Tag all findings in-place with compliance control IDs."""
        for finding in findings:
            finding.compliance_tags = self.tag_finding(finding)

    def list_frameworks(self) -> list[dict]:
        """Return metadata about loaded frameworks."""
        result = []
        for fw_id, fw_data in self._frameworks.items():
            result.append({
                "id": fw_id,
                "name": fw_data["framework"],
                "version": fw_data.get("version", ""),
                "total_controls": len(fw_data.get("controls", {})),
            })
        return result

    def get_coverage(self, findings: list[Finding]) -> list[dict]:
        """Calculate compliance coverage per framework from tagged findings."""
        all_tags: set[str] = set()
        for f in findings:
            all_tags.update(f.compliance_tags)
        result = []
        for fw_id, fw_data in self._frameworks.items():
            controls = fw_data.get("controls", {})
            all_control_ids = set(controls.keys())
            violated = all_control_ids & all_tags
            clear = all_control_ids - violated
            total = len(all_control_ids)
            result.append({
                "framework": fw_data["framework"],
                "framework_id": fw_id,
                "version": fw_data.get("version", ""),
                "total_controls": total,
                "controls_violated": sorted(violated),
                "controls_clear": sorted(clear),
                "violated_details": [
                    {"id": cid, "name": controls[cid]["name"]}
                    for cid in sorted(violated)
                ],
                "coverage_percentage": round(
                    (len(violated) / total * 100) if total > 0 else 0, 1
                ),
            })
        return result
