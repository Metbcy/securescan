# Phase 1: Compliance Mapping & Report Generation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add compliance framework tagging (OWASP/CIS/PCI-DSS/SOC2) to all findings and generate professional PDF/HTML security assessment reports from scan results.

**Architecture:** Data-driven compliance mapper loads JSON framework files and tags findings by CWE, rule_id, or keyword match. Report generator uses Jinja2 templates rendered to HTML, with WeasyPrint for PDF conversion. Both integrate into the existing scan pipeline after deduplication and before AI enrichment.

**Tech Stack:** Python, FastAPI, Jinja2, WeasyPrint, Pydantic, aiosqlite, Next.js/TypeScript/Tailwind (frontend)

---

### Task 1: Compliance Data Files

**Files:**
- Create: `backend/data/compliance/owasp-top10-2021.json`
- Create: `backend/data/compliance/cis-controls-v8.json`
- Create: `backend/data/compliance/pci-dss-v4.json`
- Create: `backend/data/compliance/soc2.json`

- [ ] **Step 1: Create directory and all four compliance framework JSON data files**

```bash
mkdir -p backend/data/compliance
```

Create each framework file containing the JSON structure:
```json
{
  "framework": "<Name>",
  "version": "<Version>",
  "controls": {
    "<CONTROL-ID>": {
      "name": "<Control Name>",
      "cwes": ["CWE-XX", ...],
      "keywords": ["keyword1", "keyword2", ...],
      "rule_ids": {}
    }
  }
}
```

**OWASP Top 10 2021** (`owasp-top10-2021.json`) — 10 controls (A01-A10):
- A01: Broken Access Control — CWEs: 22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275. Keywords: access control, authorization, privilege, IDOR, path traversal, directory traversal, CSRF, cross-site request forgery
- A02: Cryptographic Failures — CWEs: 261, 296, 310, 319, 321-331, 335-338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916. Keywords: crypto, encryption, cipher, hash, SSL, TLS, certificate, plaintext, cleartext, weak key, random
- A03: Injection — CWEs: 20, 74, 75, 77-80, 83, 87-100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917. Keywords: injection, SQL, XSS, cross-site scripting, command injection, LDAP injection, template injection, SSTI, eval, exec
- A04: Insecure Design — CWEs: 73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311-313, 316, 419, 430, 434, 444, 451, 472, 501, 522, 525, 539, 579, 598, 602, 642, 646, 650, 653, 656, 657, 799, 807, 840, 841, 927, 1021, 1173. Keywords: insecure design, trust boundary, business logic
- A05: Security Misconfiguration — CWEs: 2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004, 1032, 1174. Keywords: misconfiguration, default password, default credential, debug, verbose error, stack trace, XXE, XML external entity, directory listing, unnecessary feature
- A06: Vulnerable and Outdated Components — CWEs: 1035, 1104. Keywords: outdated, vulnerable component, CVE, known vulnerability, end of life, deprecated library, vulnerable dependency
- A07: Identification and Authentication Failures — CWEs: 255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216. Keywords: authentication, brute force, credential stuffing, session fixation, weak password, hardcoded password, hardcoded credential, default credential, session management
- A08: Software and Data Integrity Failures — CWEs: 345, 353, 426, 494, 502, 565, 784, 829, 830, 915. Keywords: deserialization, insecure deserialization, yaml.load, integrity, unsigned, unverified update
- A09: Security Logging and Monitoring Failures — CWEs: 117, 223, 532, 778. Keywords: logging, monitoring, audit log, log injection, insufficient logging, sensitive data in log
- A10: Server-Side Request Forgery — CWEs: 918. Keywords: SSRF, server-side request forgery, URL redirect, URL validation

**CIS Controls v8** (`cis-controls-v8.json`) — 18 controls (CIS-01 through CIS-18):
- CIS-01: Inventory and Control of Enterprise Assets. Keywords: asset inventory
- CIS-02: Inventory and Control of Software Assets. CWEs: 1035, 1104. Keywords: software inventory, SBOM
- CIS-03: Data Protection. CWEs: 311, 312, 319, 326, 327, 522. Keywords: data protection, encryption at rest, encryption in transit, sensitive data, PII
- CIS-04: Secure Configuration. CWEs: 2, 16, 260, 521, 756. Keywords: hardening, secure configuration, default configuration, default password, CIS benchmark, security baseline
- CIS-05: Account Management. CWEs: 250, 269, 276, 284, 732. Keywords: account management, privileged account, admin account, service account, least privilege
- CIS-06: Access Control Management. CWEs: 264, 284, 285, 639, 862, 863. Keywords: access control, role-based, RBAC, authorization, permission
- CIS-07: Continuous Vulnerability Management. CWEs: 1035, 1104. Keywords: vulnerability scan, CVE, patch management, vulnerability management, outdated
- CIS-08: Audit Log Management. CWEs: 117, 223, 532, 778. Keywords: audit log, logging, log management, log retention
- CIS-09: Email and Web Browser Protections. CWEs: 79, 601. Keywords: email security, phishing, browser security, content security policy, CSP
- CIS-10: Malware Defenses. CWEs: 494, 829. Keywords: malware, antivirus
- CIS-11: Data Recovery. Keywords: backup, data recovery, disaster recovery
- CIS-12: Network Infrastructure Management. CWEs: 757, 319. Keywords: network segmentation, firewall, network security, TLS, SSL
- CIS-13: Network Monitoring and Defense. Keywords: IDS, IPS, network monitoring
- CIS-14: Security Awareness and Skills Training. No CWEs/keywords.
- CIS-15: Service Provider Management. Keywords: third party, vendor, supply chain
- CIS-16: Application Software Security. CWEs: 20, 74, 79, 89, 94, 116, 502, 611, 798, 918. Keywords: SAST, DAST, code review, secure coding, input validation, output encoding
- CIS-17: Incident Response Management. Keywords: incident response
- CIS-18: Penetration Testing. Keywords: penetration test, pentest, red team

**PCI DSS v4.0** (`pci-dss-v4.json`) — 12 requirements (PCI-1 through PCI-12):
- PCI-1: Network Security Controls. Keywords: firewall, network segmentation
- PCI-2: Secure Configurations. CWEs: 2, 16, 260, 756. Keywords: default password, hardening, secure configuration
- PCI-3: Protect Stored Account Data. CWEs: 311, 312, 316, 326. Keywords: data at rest, encryption at rest, stored credentials
- PCI-4: Strong Cryptography During Transmission. CWEs: 319, 326, 327, 757. Keywords: TLS, SSL, encryption in transit, cleartext, plaintext
- PCI-5: Protect from Malicious Software. CWEs: 494, 829. Keywords: malware, antivirus
- PCI-6: Develop and Maintain Secure Systems. CWEs: 20, 74, 79, 89, 94, 116, 434, 502, 611, 798, 918. Keywords: secure coding, code review, vulnerability, injection, XSS, SQL injection, SAST, input validation
- PCI-7: Restrict Access by Business Need. CWEs: 264, 284, 285, 732, 862. Keywords: access control, least privilege, need to know, RBAC
- PCI-8: Identify Users and Authenticate Access. CWEs: 255, 287, 307, 521, 522, 798. Keywords: authentication, MFA, multi-factor, password policy, credential, hardcoded password
- PCI-9: Restrict Physical Access. No CWEs/keywords.
- PCI-10: Log and Monitor All Access. CWEs: 117, 223, 532, 778. Keywords: audit log, logging, monitoring, log integrity
- PCI-11: Test Security Regularly. Keywords: vulnerability scan, penetration test, IDS
- PCI-12: Organizational Policies. No CWEs/keywords.

**SOC 2** (`soc2.json`) — 8 trust criteria:
- SOC2-CC6: Logical and Physical Access Controls. CWEs: 250, 255, 264, 269, 276, 284, 285, 287, 306, 521, 522, 639, 732, 798, 862, 863. Keywords: access control, authentication, authorization, privilege, credential, hardcoded password, least privilege, MFA
- SOC2-CC7: System Operations. CWEs: 117, 223, 532, 778. Keywords: monitoring, logging, incident detection, vulnerability management
- SOC2-CC8: Change Management. Keywords: change management, code review, deployment
- SOC2-CC9: Risk Mitigation. CWEs: 1035, 1104. Keywords: risk assessment, vendor management, third party, vulnerability
- SOC2-C1: Confidentiality. CWEs: 200, 311, 312, 319, 326, 327, 359, 497, 522, 532. Keywords: confidential, encryption, data protection, sensitive data, PII, data leak, information disclosure
- SOC2-A1: Availability. Keywords: availability, backup, disaster recovery, redundancy, failover
- SOC2-PI1: Processing Integrity. CWEs: 20, 74, 79, 89, 94, 502. Keywords: input validation, data integrity, injection, data processing
- SOC2-P1: Privacy. CWEs: 200, 359, 532. Keywords: privacy, PII, personal data, GDPR, data subject, consent

- [ ] **Step 2: Commit compliance data files**

```bash
git add backend/data/compliance/
git commit -m "feat: add compliance framework data files (OWASP/CIS/PCI-DSS/SOC2)"
```

---

### Task 2: Compliance Mapper Engine

**Files:**
- Create: `backend/tests/test_compliance.py`
- Create: `backend/src/compliance.py`
- Modify: `backend/src/models.py` (add compliance_tags field)

- [ ] **Step 1: Add `compliance_tags` field to Finding model**

In `backend/src/models.py`, add after the `metadata` field in the `Finding` class:

```python
    compliance_tags: list[str] = Field(default_factory=list)
```

- [ ] **Step 2: Write failing tests for compliance mapper**

Create `backend/tests/test_compliance.py`:

```python
"""Tests for compliance mapping engine."""
import json
import tempfile
from pathlib import Path

from src.compliance import ComplianceMapper
from src.models import Finding, ScanType, Severity


def _make_finding(
    cwe: str | None = None,
    rule_id: str | None = None,
    title: str = "Test finding",
    scanner: str = "test",
) -> Finding:
    return Finding(
        scan_id="test",
        scanner=scanner,
        scan_type=ScanType.CODE,
        severity=Severity.HIGH,
        title=title,
        description="Test description",
        cwe=cwe,
        rule_id=rule_id,
    )


def _make_data_dir() -> Path:
    """Create a temp dir with a minimal framework file for testing."""
    d = Path(tempfile.mkdtemp())
    framework = {
        "framework": "Test Framework",
        "version": "1.0",
        "controls": {
            "TEST-01": {
                "name": "Injection Prevention",
                "cwes": ["CWE-89", "CWE-79"],
                "keywords": ["SQL injection", "XSS"],
                "rule_ids": {"semgrep": ["rules.python.sql-injection"]},
            },
            "TEST-02": {
                "name": "Crypto",
                "cwes": ["CWE-327"],
                "keywords": ["weak cipher", "encryption"],
                "rule_ids": {},
            },
        },
    }
    (d / "test-framework.json").write_text(json.dumps(framework))
    return d


def test_load_frameworks():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    frameworks = mapper.list_frameworks()
    assert len(frameworks) == 1
    assert frameworks[0]["id"] == "test-framework"
    assert frameworks[0]["name"] == "Test Framework"
    assert frameworks[0]["total_controls"] == 2


def test_tag_by_cwe():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    finding = _make_finding(cwe="CWE-89")
    tags = mapper.tag_finding(finding)
    assert "TEST-01" in tags


def test_tag_by_rule_id():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    finding = _make_finding(rule_id="rules.python.sql-injection", scanner="semgrep")
    tags = mapper.tag_finding(finding)
    assert "TEST-01" in tags


def test_tag_by_keyword():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    finding = _make_finding(title="Possible SQL injection in query builder")
    tags = mapper.tag_finding(finding)
    assert "TEST-01" in tags


def test_no_match():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    finding = _make_finding(title="Unused variable")
    tags = mapper.tag_finding(finding)
    assert tags == []


def test_tag_findings_in_place():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    findings = [
        _make_finding(cwe="CWE-89"),
        _make_finding(title="Unused variable"),
        _make_finding(title="Weak cipher detected in TLS config"),
    ]
    mapper.tag_findings(findings)
    assert "TEST-01" in findings[0].compliance_tags
    assert findings[1].compliance_tags == []
    assert "TEST-02" in findings[2].compliance_tags


def test_multiple_framework_tags():
    """A finding can match controls across multiple frameworks."""
    d = Path(tempfile.mkdtemp())
    fw1 = {
        "framework": "FW1", "version": "1", "controls": {
            "FW1-A": {"name": "A", "cwes": ["CWE-89"], "keywords": [], "rule_ids": {}},
        }
    }
    fw2 = {
        "framework": "FW2", "version": "1", "controls": {
            "FW2-X": {"name": "X", "cwes": ["CWE-89"], "keywords": [], "rule_ids": {}},
        }
    }
    (d / "fw1.json").write_text(json.dumps(fw1))
    (d / "fw2.json").write_text(json.dumps(fw2))
    mapper = ComplianceMapper(d)
    finding = _make_finding(cwe="CWE-89")
    tags = mapper.tag_finding(finding)
    assert "FW1-A" in tags
    assert "FW2-X" in tags


def test_compliance_coverage():
    data_dir = _make_data_dir()
    mapper = ComplianceMapper(data_dir)
    findings = [_make_finding(cwe="CWE-89")]
    mapper.tag_findings(findings)
    coverage = mapper.get_coverage(findings)
    assert len(coverage) == 1
    c = coverage[0]
    assert c["framework"] == "Test Framework"
    assert "TEST-01" in c["controls_violated"]
    assert "TEST-02" in c["controls_clear"]
    assert c["coverage_percentage"] == 50.0
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd backend && python -m pytest tests/test_compliance.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'src.compliance'`

- [ ] **Step 4: Implement the compliance mapper**

Create `backend/src/compliance.py`:

```python
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
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_compliance.py -v
```

Expected: All 8 tests PASS

- [ ] **Step 6: Commit**

```bash
git add backend/src/compliance.py backend/src/models.py backend/tests/test_compliance.py
git commit -m "feat: add compliance mapping engine with CWE/rule_id/keyword matching"
```

---

### Task 3: Database Schema Update & Pipeline Integration

**Files:**
- Modify: `backend/src/database.py` (add compliance_tags column, update serialization)
- Modify: `backend/src/api/scans.py` (integrate compliance mapper)
- Modify: `backend/src/cli.py` (integrate compliance mapper)
- Modify: `backend/src/config.py` (add compliance_data_dir setting)

- [ ] **Step 1: Add `compliance_data_dir` to config**

In `backend/src/config.py`, add to the `Settings` class:

```python
    compliance_data_dir: str = "data/compliance"
    report_template_dir: str = "templates/reports"
```

- [ ] **Step 2: Update database schema — add compliance_tags column**

In `backend/src/database.py`, in the `init_db()` function, add after the findings table creation and before `await db.commit()`:

```python
        # Migration: add compliance_tags column if not present
        try:
            await db.execute("ALTER TABLE findings ADD COLUMN compliance_tags TEXT DEFAULT '[]'")
            await db.commit()
        except Exception:
            pass  # Column already exists
```

- [ ] **Step 3: Update `save_findings` to persist compliance_tags**

In `backend/src/database.py`, update `save_findings()` — change the INSERT SQL to include `compliance_tags` as the 15th column and add `json.dumps(f.compliance_tags)` as the 15th value in the tuple.

The SQL becomes:
```sql
INSERT OR REPLACE INTO findings
    (id, scan_id, scanner, scan_type, severity, title, description,
     file_path, line_start, line_end, rule_id, cwe, remediation, metadata, compliance_tags)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
```

Add to the tuple after `json.dumps(f.metadata)`:
```python
                    json.dumps(f.compliance_tags),
```

- [ ] **Step 4: Update `_row_to_finding` to read compliance_tags**

In `backend/src/database.py`, add to the `_row_to_finding()` Finding constructor, after `metadata=`:

```python
        compliance_tags=json.loads(row["compliance_tags"]) if row["compliance_tags"] else [],
```

- [ ] **Step 5: Add compliance filtering to `get_findings`**

In `backend/src/database.py`, add `compliance: Optional[str] = None` parameter to `get_findings()` and add after the `scan_type` filter:

```python
        if compliance:
            query += " AND compliance_tags LIKE ?"
            params.append(f'%"{compliance}"%')
```

- [ ] **Step 6: Integrate compliance mapper into API scan pipeline**

In `backend/src/api/scans.py`, add imports:

```python
from pathlib import Path
from ..compliance import ComplianceMapper
from ..config import settings
```

In `_run_scan()`, add after `all_findings = deduplicate_findings(all_findings)` and before `summary = build_summary(...)`:

```python
        # Compliance tagging
        compliance_data_dir = Path(settings.compliance_data_dir)
        if compliance_data_dir.exists():
            mapper = ComplianceMapper(compliance_data_dir)
            mapper.tag_findings(all_findings)
```

- [ ] **Step 7: Integrate compliance mapper into CLI scan pipeline**

In `backend/src/cli.py`, add import:

```python
from .compliance import ComplianceMapper
```

In `_run_scan_async()`, add after `all_findings = deduplicate_findings(all_findings)` and before `summary = build_summary(...)`:

```python
    # Compliance tagging
    compliance_data_dir = Path(settings.compliance_data_dir)
    if compliance_data_dir.exists():
        mapper = ComplianceMapper(compliance_data_dir)
        mapper.tag_findings(all_findings)
        tagged_count = sum(1 for f in all_findings if f.compliance_tags)
        console.print(f"  [green]\u2713 Compliance: tagged {tagged_count}/{len(all_findings)} findings[/green]")
```

- [ ] **Step 8: Add compliance filter to findings API endpoint**

In `backend/src/api/scans.py`, update the `list_findings` endpoint signature to add `compliance: Optional[str] = None` and pass it to `get_findings()`:

```python
@router.get("/{scan_id}/findings", response_model=list[Finding])
async def list_findings(
    scan_id: str,
    severity: Optional[str] = None,
    scan_type: Optional[str] = None,
    compliance: Optional[str] = None,
):
    """Get findings for a scan, optionally filtered by severity, scan_type, or compliance tag."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return await get_findings(scan_id, severity=severity, scan_type=scan_type, compliance=compliance)
```

- [ ] **Step 9: Commit**

```bash
git add backend/src/config.py backend/src/database.py backend/src/api/scans.py backend/src/cli.py
git commit -m "feat: integrate compliance tagging into scan pipeline and database"
```

---

### Task 4: Compliance API Endpoints

**Files:**
- Create: `backend/src/api/compliance.py`
- Modify: `backend/src/api/__init__.py` (register new router)

- [ ] **Step 1: Create compliance API router**

Create `backend/src/api/compliance.py`:

```python
"""Compliance framework API endpoints."""
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query

from ..compliance import ComplianceMapper
from ..config import settings
from ..database import get_findings, get_scan

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


def _get_mapper() -> ComplianceMapper:
    data_dir = Path(settings.compliance_data_dir)
    if not data_dir.exists():
        raise HTTPException(status_code=500, detail="Compliance data directory not found")
    return ComplianceMapper(data_dir)


@router.get("/frameworks")
async def list_frameworks():
    """List available compliance frameworks and their control counts."""
    mapper = _get_mapper()
    return {"frameworks": mapper.list_frameworks()}


@router.get("/coverage")
async def compliance_coverage(scan_id: str = Query(..., description="Scan ID")):
    """Get per-framework compliance coverage for a scan."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = await get_findings(scan_id)
    mapper = _get_mapper()
    return {"coverage": mapper.get_coverage(findings)}
```

- [ ] **Step 2: Register the compliance router in the FastAPI app**

Read `backend/src/api/__init__.py` and add:

```python
from .compliance import router as compliance_router
```

And include the router:

```python
app.include_router(compliance_router)
```

- [ ] **Step 3: Commit**

```bash
git add backend/src/api/compliance.py backend/src/api/__init__.py
git commit -m "feat: add compliance frameworks and coverage API endpoints"
```

---

### Task 5: Report HTML Template

**Files:**
- Create: `backend/templates/reports/report.html`

- [ ] **Step 1: Create the template directory and Jinja2 HTML report template**

```bash
mkdir -p backend/templates/reports
```

Create `backend/templates/reports/report.html` — a full HTML page with inline CSS (for PDF compatibility via WeasyPrint). The template receives these variables:
- `scan` (Scan model)
- `findings` (list of Finding, sorted by severity)
- `summary` (ScanSummary model)
- `compliance_coverage` (list of coverage dicts)
- `top_findings` (list of critical/high findings)

Template sections:
1. **Cover page** — title, target path, risk score badge (color-coded: >=70 critical/red, >=50 high/orange, >=25 medium/yellow, >=1 low/blue, else info/gray), scan ID, date
2. **Executive summary** — AI summary text, stat grid (5 columns: critical/high/medium/low/info counts), total findings, scanners used, top 3 critical findings as ordered list
3. **Compliance summary** — table with framework/version/violated/clear/coverage%, then per-framework violated control detail tables
4. **Findings by severity** — grouped by severity level, each finding as a card showing title, description, file:line, CWE, compliance tags as badges, remediation in green box
5. **Scanner coverage** — table of scanners that ran, scan duration

Use `@page { size: A4; margin: 2cm; }` for PDF sizing. Use system font stack. Severity badges use colored inline-block spans. Compliance tags use small blue badges.

- [ ] **Step 2: Commit**

```bash
git add backend/templates/reports/report.html
git commit -m "feat: add Jinja2 HTML report template for security assessments"
```

---

### Task 6: Report Generator & API Endpoints

**Files:**
- Create: `backend/tests/test_reports.py`
- Create: `backend/src/reports.py`
- Modify: `backend/src/api/scans.py` (add report endpoint)
- Modify: `backend/pyproject.toml` (add jinja2 + weasyprint dependencies)

- [ ] **Step 1: Add dependencies to pyproject.toml**

Add to the `dependencies` list in `backend/pyproject.toml`:

```toml
    "jinja2>=3.1.0",
    "weasyprint>=62.0",
```

Install them:

```bash
cd backend && pip install jinja2 weasyprint
```

- [ ] **Step 2: Write failing tests for report generator**

Create `backend/tests/test_reports.py`:

```python
"""Tests for report generation."""
from datetime import datetime
from pathlib import Path

import pytest

from src.models import Finding, Scan, ScanStatus, ScanSummary, ScanType, Severity
from src.reports import ReportGenerator
from src.scoring import build_summary


def _make_scan() -> Scan:
    return Scan(
        target_path="/test/project",
        scan_types=[ScanType.CODE],
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 3, 31, 10, 0, 0),
        completed_at=datetime(2026, 3, 31, 10, 5, 0),
        findings_count=3,
        risk_score=45.0,
        summary="Found 3 issues including SQL injection.",
    )


def _make_findings() -> list[Finding]:
    return [
        Finding(
            scan_id="test",
            scanner="semgrep",
            scan_type=ScanType.CODE,
            severity=Severity.CRITICAL,
            title="SQL Injection in user query",
            description="User input is concatenated directly into SQL query.",
            file_path="app/db.py",
            line_start=42,
            cwe="CWE-89",
            remediation="Use parameterized queries.",
            compliance_tags=["OWASP-A03", "PCI-6"],
        ),
        Finding(
            scan_id="test",
            scanner="bandit",
            scan_type=ScanType.CODE,
            severity=Severity.MEDIUM,
            title="Weak hash algorithm",
            description="MD5 is used for hashing.",
            file_path="app/auth.py",
            line_start=15,
            cwe="CWE-327",
            compliance_tags=["OWASP-A02"],
        ),
        Finding(
            scan_id="test",
            scanner="secrets",
            scan_type=ScanType.CODE,
            severity=Severity.LOW,
            title="Possible API key in source",
            description="String resembles an API key.",
            file_path="config.py",
            line_start=3,
            compliance_tags=[],
        ),
    ]


@pytest.fixture
def generator() -> ReportGenerator:
    template_dir = Path(__file__).resolve().parent.parent / "templates" / "reports"
    return ReportGenerator(template_dir)


def test_generate_html(generator: ReportGenerator):
    scan = _make_scan()
    findings = _make_findings()
    summary = build_summary(findings, ["semgrep", "bandit", "secrets"])
    html = generator.generate_html(scan, findings, summary, compliance_coverage=[])
    assert "Security Assessment Report" in html
    assert "SQL Injection" in html
    assert "CWE-89" in html
    assert "OWASP-A03" in html
    assert "semgrep" in html


def test_generate_html_with_compliance(generator: ReportGenerator):
    scan = _make_scan()
    findings = _make_findings()
    summary = build_summary(findings, ["semgrep"])
    coverage = [{
        "framework": "OWASP Top 10",
        "version": "2021",
        "total_controls": 10,
        "controls_violated": ["OWASP-A02", "OWASP-A03"],
        "controls_clear": ["OWASP-A01"],
        "violated_details": [
            {"id": "OWASP-A02", "name": "Cryptographic Failures"},
            {"id": "OWASP-A03", "name": "Injection"},
        ],
        "coverage_percentage": 20.0,
    }]
    html = generator.generate_html(scan, findings, summary, compliance_coverage=coverage)
    assert "Compliance Summary" in html
    assert "OWASP Top 10" in html
    assert "Injection" in html


def test_generate_pdf(generator: ReportGenerator):
    scan = _make_scan()
    findings = _make_findings()
    summary = build_summary(findings, ["semgrep"])
    pdf_bytes = generator.generate_pdf(scan, findings, summary, compliance_coverage=[])
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
    assert pdf_bytes[:5] == b"%PDF-"
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd backend && python -m pytest tests/test_reports.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'src.reports'`

- [ ] **Step 4: Implement the report generator**

Create `backend/src/reports.py`:

```python
"""Security assessment report generation (HTML + PDF)."""
from pathlib import Path

import jinja2

from .models import Finding, Scan, ScanSummary, Severity


class ReportGenerator:
    """Generate HTML and PDF security assessment reports from scan results."""

    def __init__(self, template_dir: Path):
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=True,
        )

    def generate_html(
        self,
        scan: Scan,
        findings: list[Finding],
        summary: ScanSummary,
        compliance_coverage: list[dict],
    ) -> str:
        """Render findings into an HTML report string."""
        severity_rank = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_rank.get(f.severity, 5))
        top_findings = [f for f in sorted_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        template = self._env.get_template("report.html")
        return template.render(
            scan=scan,
            findings=sorted_findings,
            summary=summary,
            compliance_coverage=compliance_coverage,
            top_findings=top_findings,
        )

    def generate_pdf(
        self,
        scan: Scan,
        findings: list[Finding],
        summary: ScanSummary,
        compliance_coverage: list[dict],
    ) -> bytes:
        """Render findings into a PDF report via WeasyPrint."""
        from weasyprint import HTML
        html_string = self.generate_html(scan, findings, summary, compliance_coverage)
        return HTML(string=html_string).write_pdf()
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd backend && python -m pytest tests/test_reports.py -v
```

Expected: All 3 tests PASS

- [ ] **Step 6: Add report API endpoint to scans router**

In `backend/src/api/scans.py`, add imports at the top:

```python
from fastapi.responses import HTMLResponse, Response
from ..reports import ReportGenerator
```

Add the endpoint **before** the `read_scan` endpoint (to avoid `/{scan_id}` catching `/report` routes):

```python
@router.get("/{scan_id}/report")
async def generate_report(
    scan_id: str,
    format: str = Query("html", description="Report format: html or pdf"),
):
    """Generate a security assessment report for a scan."""
    scan = await get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan must be completed to generate a report")

    findings_list = await get_findings(scan_id)
    summary_data = await get_scan_summary(scan_id)

    compliance_coverage = []
    compliance_data_dir = Path(settings.compliance_data_dir)
    if compliance_data_dir.exists():
        mapper = ComplianceMapper(compliance_data_dir)
        compliance_coverage = mapper.get_coverage(findings_list)

    generator = ReportGenerator(Path(settings.report_template_dir))

    if format == "pdf":
        pdf_bytes = generator.generate_pdf(scan, findings_list, summary_data, compliance_coverage)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="securescan-report-{scan_id[:8]}.pdf"'},
        )
    else:
        html = generator.generate_html(scan, findings_list, summary_data, compliance_coverage)
        return HTMLResponse(content=html)
```

- [ ] **Step 7: Commit**

```bash
git add backend/pyproject.toml backend/src/reports.py backend/tests/test_reports.py backend/src/api/scans.py
git commit -m "feat: add PDF/HTML report generation with compliance coverage"
```

---

### Task 7: CLI Report Output Formats

**Files:**
- Modify: `backend/src/cli.py`

- [ ] **Step 1: Add report-html and report-pdf output formats to CLI**

In `backend/src/cli.py`, add import at top:

```python
from .reports import ReportGenerator
```

In the `scan()` command, add two new `elif` branches after the existing `elif output == "junit":` block:

```python
    elif output == "report-html":
        compliance_coverage = []
        compliance_data_dir = Path(settings.compliance_data_dir)
        if compliance_data_dir.exists():
            mapper = ComplianceMapper(compliance_data_dir)
            compliance_coverage = mapper.get_coverage(findings)
        summary_obj = build_summary(findings, [])
        generator = ReportGenerator(Path(settings.report_template_dir))
        output_content = generator.generate_html(result_scan, findings, summary_obj, compliance_coverage)
    elif output == "report-pdf":
        compliance_coverage = []
        compliance_data_dir = Path(settings.compliance_data_dir)
        if compliance_data_dir.exists():
            mapper = ComplianceMapper(compliance_data_dir)
            compliance_coverage = mapper.get_coverage(findings)
        summary_obj = build_summary(findings, [])
        generator = ReportGenerator(Path(settings.report_template_dir))
        pdf_bytes = generator.generate_pdf(result_scan, findings, summary_obj, compliance_coverage)
        if output_file:
            Path(output_file).write_bytes(pdf_bytes)
            console.print(f"[green]PDF report written to {output_file}[/green]")
        else:
            console.print("[red]PDF output requires --output-file[/red]")
        output_content = None
```

- [ ] **Step 2: Commit**

```bash
git add backend/src/cli.py
git commit -m "feat: add report-html and report-pdf CLI output formats"
```

---

### Task 8: Frontend — Compliance Badges & Report Download

**Files:**
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/components/findings-table.tsx`
- Modify: `frontend/src/app/page.tsx`
- Modify: `frontend/src/app/scan/page.tsx`

- [ ] **Step 1: Add compliance types and API functions to frontend**

In `frontend/src/lib/api.ts`:

Add `compliance_tags: string[];` to the `Finding` interface (after `metadata`).

Add at the end of the file:

```typescript
// --- Compliance ---

export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  total_controls: number;
}

export interface ComplianceCoverage {
  framework: string;
  framework_id: string;
  version: string;
  total_controls: number;
  controls_violated: string[];
  controls_clear: string[];
  violated_details: { id: string; name: string }[];
  coverage_percentage: number;
}

export async function fetchComplianceFrameworks(): Promise<ComplianceFramework[]> {
  const res = await fetch(`${API_BASE}/api/compliance/frameworks`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch compliance frameworks");
  const data = await res.json();
  return data.frameworks;
}

export async function fetchComplianceCoverage(scanId: string): Promise<ComplianceCoverage[]> {
  const res = await fetch(`${API_BASE}/api/compliance/coverage?scan_id=${encodeURIComponent(scanId)}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch compliance coverage");
  const data = await res.json();
  return data.coverage;
}

export function getReportUrl(scanId: string, format: "pdf" | "html"): string {
  return `${API_BASE}/api/scans/${scanId}/report?format=${format}`;
}
```

- [ ] **Step 2: Add compliance tags column to findings table**

In `frontend/src/components/findings-table.tsx`:

Add a `Compliance` header after `Line`:
```tsx
            <th className="px-4 py-3">Compliance</th>
```

Add a compliance `<td>` after the Line `<td>` in each finding row:
```tsx
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {f.compliance_tags?.map((tag) => (
                        <span
                          key={tag}
                          className="inline-block px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-500/15 text-blue-400 border border-blue-500/20"
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </td>
```

- [ ] **Step 3: Add compliance coverage section to dashboard**

In `frontend/src/app/page.tsx`:

Add imports:
```typescript
import { fetchComplianceCoverage } from "@/lib/api";
import type { ComplianceCoverage } from "@/lib/api";
```

Add state:
```typescript
const [compliance, setCompliance] = useState<ComplianceCoverage[]>([]);
```

In the `load()` function, after fetching summary/findings for the latest scan, add:
```typescript
            fetchComplianceCoverage(latest.id).then(setCompliance).catch(() => {});
```

Add the compliance section in the JSX between the trend chart and findings sections:
```tsx
      {compliance.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold mb-3">Compliance Coverage</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {compliance.map((c) => (
              <div key={c.framework_id} className="rounded-xl border border-[#262626] bg-[#141414] p-4">
                <h3 className="text-sm font-medium text-[#ededed] mb-1">{c.framework}</h3>
                <p className="text-xs text-[#52525b] mb-3">v{c.version}</p>
                <div className="flex items-end gap-2 mb-2">
                  <span className="text-2xl font-bold text-red-400">{c.controls_violated.length}</span>
                  <span className="text-sm text-[#52525b]">/ {c.total_controls} controls violated</span>
                </div>
                <div className="w-full h-2 bg-[#262626] rounded-full overflow-hidden">
                  <div className="h-full bg-red-500 rounded-full" style={{ width: `${c.coverage_percentage}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
```

- [ ] **Step 4: Add report download buttons to scan results page**

In `frontend/src/app/scan/page.tsx`:

Add imports:
```typescript
import { Download } from "lucide-react";
import { getReportUrl } from "@/lib/api";
```

After the "Scan completed" success indicator div, add:
```tsx
          <div className="flex gap-3">
            <a
              href={getReportUrl(scan.id, "pdf")}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#262626] bg-[#141414] hover:bg-[#1a1a1a] text-sm font-medium text-[#ededed] transition-colors"
            >
              <Download size={14} />
              PDF Report
            </a>
            <a
              href={getReportUrl(scan.id, "html")}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#262626] bg-[#141414] hover:bg-[#1a1a1a] text-sm font-medium text-[#ededed] transition-colors"
            >
              <Download size={14} />
              HTML Report
            </a>
          </div>
```

- [ ] **Step 5: Commit**

```bash
git add frontend/src/lib/api.ts frontend/src/components/findings-table.tsx frontend/src/app/page.tsx frontend/src/app/scan/page.tsx
git commit -m "feat: add compliance badges, coverage dashboard, and report download to frontend"
```

---

### Task 9: Verification

**Files:** None (verification only)

- [ ] **Step 1: Run all backend tests**

```bash
cd backend && python -m pytest tests/ -v
```

Expected: All tests PASS

- [ ] **Step 2: Verify frontend builds**

```bash
cd frontend && npm run build
```

Expected: Build succeeds with no TypeScript errors

- [ ] **Step 3: Smoke test the compliance API**

```bash
cd backend && python -m uvicorn src.main:app --port 8000 &
sleep 2
curl -s http://localhost:8000/api/compliance/frameworks | python3 -m json.tool
kill %1
```

Expected: JSON response listing 4 frameworks with control counts

- [ ] **Step 4: Final commit if any fixes were needed**

Only run if previous steps required fixes:

```bash
git add -A && git commit -m "fix: address issues found during Phase 1 verification"
```
