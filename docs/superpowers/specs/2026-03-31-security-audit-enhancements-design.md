# SecureScan: Security Audit & Pentesting Companion — Design Spec

**Date:** 2026-03-31
**Approach:** Deliverable-First (Phase 1: compliance + reports on existing scanners, Phase 2: new scanners)

---

## Overview

Enhance SecureScan from a code/dependency scanner into a full-stack security audit tool. A security professional should be able to scan code, infrastructure, running web apps, and networks, then produce professional reports mapped to compliance frameworks (OWASP Top 10, CIS Benchmarks, PCI-DSS, SOC2).

**Two phases:**
1. **Compliance mapping engine + report generation** — immediate value upgrade for existing 11 scanners
2. **New scanners** — DAST (ZAP + built-in), network scanning (nmap), SBOM generation (Syft + built-in fallback)

---

## Phase 1: Compliance Mapping & Report Generation

### 1.1 Compliance Mapping Engine

**Purpose:** Tag every finding with the compliance framework controls it violates, enabling filtering, reporting, and coverage analysis by framework.

#### Data Model Changes

**`Finding` model** — add field:
```python
compliance_tags: list[str] = Field(default_factory=list)
# e.g., ["OWASP-A03", "PCI-DSS-6.5.1", "CIS-18.2"]
```

**Database schema** — add column to `findings` table:
```sql
compliance_tags TEXT DEFAULT '[]'  -- JSON array of strings
```

#### Mapping Engine (`src/compliance.py`)

A data-driven lookup engine. No business logic per framework — just data files.

```python
class ComplianceMapper:
    """Maps findings to compliance framework controls."""

    def __init__(self, data_dir: Path):
        self.frameworks: dict[str, ComplianceFramework] = {}
        # Load all JSON files from data_dir

    def tag_finding(self, finding: Finding) -> list[str]:
        """Return compliance tags for a finding based on CWE, rule_id, scanner, and title keywords."""

    def tag_findings(self, findings: list[Finding]) -> None:
        """Tag all findings in-place."""
```

**Matching strategy** (in priority order):
1. **CWE match** — finding has `cwe` field → look up CWE in framework mappings (most precise)
2. **Rule ID match** — finding has `rule_id` → look up scanner-specific rule mappings
3. **Keyword match** — case-insensitive substring match of keywords against finding `title` (fallback for findings without CWE/rule_id). A finding can match multiple controls across frameworks.

#### Compliance Data Files (`backend/data/compliance/`)

One JSON file per framework. Structure:

```json
{
  "framework": "OWASP Top 10 2021",
  "version": "2021",
  "controls": {
    "OWASP-A01": {
      "name": "Broken Access Control",
      "cwes": ["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441", "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566", "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-1275"],
      "keywords": ["access control", "authorization", "privilege", "IDOR", "path traversal", "directory traversal"],
      "rule_ids": {}
    },
    "OWASP-A02": {
      "name": "Cryptographic Failures",
      "cwes": ["CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337", "CWE-338", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759", "CWE-760", "CWE-780", "CWE-818", "CWE-916"],
      "keywords": ["crypto", "encryption", "cipher", "hash", "SSL", "TLS", "certificate", "plaintext", "cleartext"],
      "rule_ids": {}
    }
  }
}
```

**Frameworks to ship:**
- `owasp-top10-2021.json` — OWASP Top 10 (10 controls, well-defined CWE lists from OWASP)
- `cis-controls-v8.json` — CIS Critical Security Controls v8 (18 control families)
- `pci-dss-v4.json` — PCI DSS v4.0 (12 requirements, focused on 6.x software security)
- `soc2.json` — SOC 2 Trust Services Criteria (5 categories: Security, Availability, Processing Integrity, Confidentiality, Privacy)

#### Integration Point

In `api/scans.py` `_run_scan()` and `cli.py` `_run_scan_async()`, after deduplication and before AI enrichment:

```python
from .compliance import ComplianceMapper
mapper = ComplianceMapper(Path(settings.compliance_data_dir))
mapper.tag_findings(all_findings)
```

#### API Additions

- `GET /api/scans/{id}/findings?compliance=OWASP-A03` — filter by compliance tag
- `GET /api/compliance/frameworks` — list available frameworks with control counts
- `GET /api/compliance/coverage?scan_id={id}` — per-framework coverage: which controls have findings, which are clear

---

### 1.2 Report Generation

**Purpose:** Generate professional PDF and HTML security assessment reports from scan results.

#### Architecture

- **Template engine:** Jinja2 for HTML templates
- **PDF generation:** WeasyPrint (Python library, renders HTML/CSS to PDF — no external binary needed, pip-installable)
- **Templates directory:** `templates/reports/`

#### Report Structure

```
1. Cover Page
   - "Security Assessment Report"
   - Target path/URL
   - Date, scan ID
   - Overall risk score (color-coded gauge)

2. Executive Summary
   - 2-3 sentence AI-generated summary (already exists via Groq)
   - Risk score with interpretation (Low/Medium/High/Critical)
   - Key statistics: total findings, breakdown by severity
   - Top 3 most critical findings (title + one-line description)

3. Compliance Summary
   - Per-framework table: framework name, controls violated, controls clear, coverage %
   - Visual pass/fail indicators per control

4. Findings by Severity
   - Grouped sections: Critical, High, Medium, Low, Info
   - Each finding shows: title, description, file/line, CWE, compliance tags, remediation
   - Severity section headers with counts

5. Findings by Compliance Framework
   - Same findings reorganized by framework control
   - Shows which controls are violated and by which findings

6. Scanner Coverage
   - Which scanners ran, which were unavailable
   - Scan duration, target info

7. Appendix
   - Full finding details with metadata
   - Methodology notes
```

#### New Files

**`src/reports.py`** — Report generation engine:
```python
class ReportGenerator:
    def __init__(self, template_dir: Path):
        self.env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir))

    async def generate_html(self, scan: Scan, findings: list[Finding],
                            summary: ScanSummary, compliance_coverage: dict) -> str:
        """Render findings into an HTML report."""

    async def generate_pdf(self, scan: Scan, findings: list[Finding],
                           summary: ScanSummary, compliance_coverage: dict) -> bytes:
        """Render findings into a PDF report via WeasyPrint."""
```

**`templates/reports/report.html`** — Jinja2 HTML template with inline CSS (for PDF compatibility).

#### API Additions

- `GET /api/scans/{id}/report?format=html` — returns HTML report
- `GET /api/scans/{id}/report?format=pdf` — returns PDF report (Content-Type: application/pdf)

#### CLI Addition

- `securescan scan ... --output report-html --output-file report.html`
- `securescan scan ... --output report-pdf --output-file report.pdf`

#### Dependencies

Add to `pyproject.toml`:
```toml
"jinja2>=3.1.0",
"weasyprint>=62.0",
```

---

### 1.3 Frontend Updates (Phase 1)

#### Compliance Tags in Findings Table

- Add a "Compliance" column to `FindingsTable` showing tags as colored badges
- In the expanded finding row, show full compliance control names with descriptions
- Add compliance filter dropdown to findings page

#### Compliance Dashboard

- New section on the dashboard homepage: "Compliance Coverage"
- Per-framework card showing: framework name, controls violated vs total, coverage percentage bar
- Clicking a framework card filters findings by that framework

#### Report Download

- Add "Download Report" button on scan detail page with format dropdown (PDF / HTML)
- Button triggers `GET /api/scans/{id}/report?format=pdf|html` and downloads the file

#### New Frontend Types (`lib/api.ts`)

```typescript
export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  total_controls: number;
}

export interface ComplianceCoverage {
  framework: string;
  controls_violated: string[];
  controls_clear: string[];
  coverage_percentage: number;
}
```

#### New API Functions

```typescript
export async function fetchComplianceFrameworks(): Promise<ComplianceFramework[]>
export async function fetchComplianceCoverage(scanId: string): Promise<ComplianceCoverage[]>
export async function downloadReport(scanId: string, format: "pdf" | "html"): Promise<Blob>
```

---

## Phase 2: New Scanners

### 2.1 DAST Scanner (Dynamic Application Security Testing)

**Purpose:** Test running web applications for vulnerabilities by sending actual HTTP requests.

#### Target Model Changes

The current `ScanRequest` only accepts `target_path` (filesystem). DAST and network scanners need URL/host targets.

**`ScanRequest` model** — add optional fields:
```python
class ScanRequest(BaseModel):
    target_path: Optional[str] = None
    target_url: Optional[str] = None       # For DAST scans
    target_host: Optional[str] = None      # For network scans
    scan_types: list[ScanType] = Field(default=[ScanType.CODE, ScanType.DEPENDENCY], min_length=1)
```

Validation: at least one target field must be provided. DAST requires `target_url`. Network requires `target_host`. Code/dependency/iac/baseline require `target_path`.

**`ScanType` enum** — add:
```python
DAST = "dast"
NETWORK = "network"
```

**`Scan` model** — add:
```python
target_url: Optional[str] = None
target_host: Optional[str] = None
```

**Database** — add columns `target_url TEXT` and `target_host TEXT` to scans table.

**`BaseScanner`** — update signature:
```python
async def scan(self, target_path: str, scan_id: str,
               target_url: str | None = None,
               target_host: str | None = None) -> list[Finding]:
```

This is backward-compatible — existing scanners ignore the new params.

#### Built-in DAST Scanner (`scanners/dast_builtin.py`)

A lightweight Python-native scanner. No external dependencies. Checks:

- **Security headers** — Missing `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Permissions-Policy`
- **SSL/TLS issues** — Expired certs, weak cipher suites, protocol version (via `ssl` stdlib)
- **Common misconfigurations** — Open CORS (`Access-Control-Allow-Origin: *`), server version disclosure, directory listing enabled
- **Cookie security** — Missing `Secure`, `HttpOnly`, `SameSite` flags
- **Basic path probing** — Check for common exposed paths: `/.env`, `/.git/config`, `/wp-admin`, `/phpmyadmin`, `/server-status`, `/debug`, `/.well-known/security.txt`

Uses `httpx` (already a dependency) for async HTTP requests.

```python
class BuiltinDASTScanner(BaseScanner):
    name = "dast-builtin"
    scan_type = ScanType.DAST
    description = "Lightweight web security scanner checking headers, SSL, cookies, and common misconfigurations."

    async def is_available(self) -> bool:
        return True  # No external dependency

    async def scan(self, target_path: str, scan_id: str,
                   target_url: str | None = None, **kwargs) -> list[Finding]:
        if not target_url:
            return []
        # ... header checks, SSL checks, cookie checks, path probes
```

#### ZAP DAST Scanner (`scanners/dast_zap.py`)

Wraps OWASP ZAP's CLI/API for comprehensive DAST. External dependency — gracefully degrades.

- Uses ZAP's `zap-baseline.py` for passive scanning (fast, safe)
- Uses ZAP's `zap-full-scan.py` for active scanning (optional, slower)
- Parses ZAP's JSON output into `Finding` objects
- Maps ZAP alert confidence/risk to SecureScan severity levels

```python
class ZAPScanner(BaseScanner):
    name = "zap"
    scan_type = ScanType.DAST
    description = "OWASP ZAP comprehensive web application security scanner."

    async def is_available(self) -> bool:
        return shutil.which("zap-baseline.py") is not None or shutil.which("zap.sh") is not None

    @property
    def install_hint(self) -> str:
        return "docker pull ghcr.io/zaproxy/zaproxy:stable  OR  snap install zaproxy"
```

---

### 2.2 Network Scanner

**Purpose:** Discover open ports, running services, and OS fingerprints on target hosts.

#### nmap Scanner (`scanners/nmap.py`)

External tool wrapper. Maps nmap output to findings.

**Checks:**
- Open ports with service versions
- Known vulnerable service versions (via nmap NSE scripts)
- Weak SSH configurations
- Exposed database ports (3306, 5432, 27017, 6379)
- Default/anonymous service access
- OS detection results

```python
class NmapScanner(BaseScanner):
    name = "nmap"
    scan_type = ScanType.NETWORK
    description = "Network port scanning, service detection, and vulnerability discovery."
    checks = [
        "Open port discovery",
        "Service version detection",
        "Known vulnerability scripts (NSE)",
        "Exposed database ports",
        "Weak SSH/TLS configurations",
    ]

    async def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    @property
    def install_hint(self) -> str:
        return "sudo pacman -S nmap  OR  apt install nmap"

    async def scan(self, target_path: str, scan_id: str,
                   target_host: str | None = None, **kwargs) -> list[Finding]:
        if not target_host:
            return []
        # Run: nmap -sV -sC --script vuln -oX - {target_host}
        # Parse XML output into findings
```

**Severity mapping:**
- Exposed database ports without auth → Critical
- Known CVE from NSE vuln scripts → High
- Unnecessary open ports → Medium
- Service version disclosure → Low
- Open ports with standard services → Info

---

### 2.3 SBOM Generation

**Purpose:** Generate a Software Bill of Materials listing all components, dependencies, and their versions.

SBOM is not a vulnerability scanner — it's an inventory. It produces a deliverable (CycloneDX/SPDX JSON) and optionally cross-references components against known vulnerabilities.

#### Architecture

SBOM is a separate feature, not a `ScanType`. It runs alongside scans but produces a different output.

#### Syft Integration (`src/sbom.py`)

```python
class SBOMGenerator:
    """Generate Software Bill of Materials using Syft or built-in fallback."""

    async def generate(self, target_path: str) -> SBOMResult:
        """Generate SBOM. Uses Syft if available, falls back to built-in parser."""

    async def generate_with_syft(self, target_path: str) -> SBOMResult:
        """Run syft and parse CycloneDX JSON output."""
        # syft {target_path} -o cyclonedx-json

    async def generate_builtin(self, target_path: str) -> SBOMResult:
        """Parse common manifest files directly."""
        # Parses: package.json, package-lock.json, requirements.txt, Pipfile.lock,
        #         go.mod, go.sum, Cargo.toml, Cargo.lock, pom.xml, build.gradle,
        #         Gemfile.lock, composer.lock
```

#### SBOM Data Model

```python
class SBOMComponent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sbom_id: str
    name: str
    version: str
    type: str          # "library", "framework", "application", "os"
    purl: str | None   # Package URL (pkg:npm/express@4.18.2)
    license: str | None
    supplier: str | None

class SBOMResult(BaseModel):
    id: str
    scan_id: str | None
    target_path: str
    format: str        # "cyclonedx" or "spdx"
    components: list[SBOMComponent]
    generated_at: datetime
    tool: str          # "syft" or "builtin"
```

#### Database

New table:
```sql
CREATE TABLE IF NOT EXISTS sbom_components (
    id TEXT PRIMARY KEY,
    sbom_id TEXT NOT NULL,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    type TEXT NOT NULL,
    purl TEXT,
    license TEXT,
    supplier TEXT
);

CREATE TABLE IF NOT EXISTS sboms (
    id TEXT PRIMARY KEY,
    scan_id TEXT,
    target_path TEXT NOT NULL,
    format TEXT NOT NULL,
    component_count INTEGER DEFAULT 0,
    generated_at TEXT NOT NULL,
    tool TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
```

#### API Additions

- `POST /api/sbom/generate` — generate SBOM for a target path
- `GET /api/sbom/{id}` — get SBOM metadata
- `GET /api/sbom/{id}/components` — list components with pagination
- `GET /api/sbom/{id}/export?format=cyclonedx|spdx` — download in standard format
- `GET /api/scans/{id}/sbom` — get SBOM associated with a scan (if generated alongside)

#### CLI Addition

```
securescan sbom /path/to/project --output cyclonedx --output-file sbom.json
```

#### Report Integration

SBOM summary included as a section in PDF/HTML reports:
- Component count by type
- License distribution
- Top dependencies by transitive dependency count

---

### 2.4 Frontend Updates (Phase 2)

#### Scan Form Enhancements

Update the scan creation form (`/scan` page):
- When DAST scan type is selected, show a URL input field instead of / in addition to path picker
- When Network scan type is selected, show a host/IP input field
- Validation: ensure appropriate target is provided for selected scan types

#### DAST Results Display

- Findings from DAST scanners display with URL context instead of file paths
- HTTP response details shown in expanded finding view (status code, headers)

#### Network Scan Results

- Port/service findings displayed in a dedicated table format: port, protocol, service, version, state
- Visual port map showing open ports

#### SBOM Page (`/sbom`)

New page in sidebar navigation:
- SBOM generation form (target path input)
- Component list table: name, version, type, license, purl
- Search/filter components
- Export buttons (CycloneDX JSON, SPDX JSON)
- License distribution pie chart

---

## Cross-Cutting Concerns

### Scanner Registration

New scanners are added to `scanners/__init__.py` following the existing pattern:
```python
from .dast_builtin import BuiltinDASTScanner
from .dast_zap import ZAPScanner
from .nmap import NmapScanner

ALL_SCANNERS = [
    # ... existing 11 scanners ...
    BuiltinDASTScanner(),
    ZAPScanner(),
    NmapScanner(),
]
```

The `get_scanners_for_types()` function automatically picks them up.

### Scan Runner Changes

`_run_scan()` in `api/scans.py` needs to:
1. Pass `target_url` and `target_host` through to scanner `scan()` methods
2. Call compliance mapper after deduplication
3. Persist compliance tags to database

### Config Additions

```python
class Settings(BaseSettings):
    # ... existing ...
    compliance_data_dir: str = "data/compliance"
    report_template_dir: str = "templates/reports"
    zap_path: Optional[str] = None        # Custom ZAP path
    nmap_extra_args: str = ""             # Additional nmap arguments
    sbom_format: str = "cyclonedx"        # Default SBOM output format
```

### Dependencies Summary

Add to `pyproject.toml`:
```toml
"jinja2>=3.1.0",
"weasyprint>=62.0",
```

No new Python dependencies for DAST (uses httpx), nmap (subprocess), or SBOM builtin (file parsing). Syft is an external binary like Trivy/Semgrep.

### Docker Updates

Add to backend `Dockerfile`:
```dockerfile
# Phase 2 external tools
RUN apt-get update && apt-get install -y nmap
# ZAP and Syft are optional, installed via their own methods
```

---

## Implementation Order (Approach B)

### Phase 1 (Deliverable-First) — 6 steps
1. Compliance data files (`data/compliance/` — all 4 frameworks)
2. Compliance mapper engine (`src/compliance.py`)
3. Integrate compliance tagging into scan pipeline + database schema
4. Report templates (`templates/reports/report.html`)
5. Report generator (`src/reports.py`) + API endpoints + CLI flags
6. Frontend: compliance badges, compliance dashboard section, report download button

### Phase 2 (New Scanners) — 5 steps
7. Model changes (ScanType.DAST/NETWORK, target_url/target_host fields, DB migration)
8. Built-in DAST scanner + ZAP scanner
9. nmap network scanner
10. SBOM generator (Syft + builtin fallback) + database + API + CLI
11. Frontend: scan form updates, SBOM page, network results display

---

## What This Does NOT Include

- **Authentication/RBAC** — No user accounts or access control. Single-user tool.
- **Scheduled scans** — No cron/recurring scans. Manual trigger only.
- **Notifications** — No Slack/email/webhook alerts.
- **Ticket integration** — No Jira/GitHub Issues creation.
- **Vulnerability lifecycle** — No finding status tracking (open/resolved/false-positive).

These are enterprise/DevSecOps features that can be added in a future phase if needed.
