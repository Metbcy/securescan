# Phase 2: New Scanners (DAST, Network, SBOM) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dynamic application security testing (DAST), network scanning, and Software Bill of Materials (SBOM) generation to SecureScan's capabilities.

**Architecture:** Two new ScanType enum values (DAST, NETWORK) with corresponding scanners. Built-in DAST uses httpx for lightweight checks; ZAP wrapper delegates to OWASP ZAP. Nmap scanner wraps the nmap CLI with XML output parsing. SBOM is a separate feature (not a ScanType) that generates CycloneDX/SPDX inventory from Syft or built-in manifest parsing.

**Tech Stack:** Python, httpx, python-owasp-zap-v2.4, defusedxml, FastAPI, aiosqlite, Next.js/TypeScript/Tailwind

---

### Task 1: Model & Database Changes for DAST/Network/SBOM

**Files:**
- Modify: `backend/src/models.py`
- Modify: `backend/src/database.py`
- Modify: `backend/src/config.py`
- Test: `backend/tests/test_models_phase2.py`

- [ ] **Step 1: Write failing test for new ScanType enum values and model fields**

```python
# backend/tests/test_models_phase2.py
import pytest
from src.models import ScanType, Scan, ScanRequest, SBOMComponent, SBOMDocument


def test_dast_scan_type_exists():
    assert ScanType.DAST.value == "dast"


def test_network_scan_type_exists():
    assert ScanType.NETWORK.value == "network"


def test_scan_has_target_url():
    scan = Scan(target_path="/tmp", scan_types=["dast"], target_url="http://example.com")
    assert scan.target_url == "http://example.com"


def test_scan_has_target_host():
    scan = Scan(target_path="/tmp", scan_types=["network"], target_host="192.168.1.1")
    assert scan.target_host == "192.168.1.1"


def test_scan_request_has_target_url():
    req = ScanRequest(target_path="/tmp", scan_types=["dast"], target_url="http://example.com")
    assert req.target_url == "http://example.com"


def test_sbom_component_model():
    comp = SBOMComponent(
        id="comp-1",
        sbom_id="sbom-1",
        name="lodash",
        version="4.17.21",
        type="library",
        purl="pkg:npm/lodash@4.17.21",
    )
    assert comp.name == "lodash"
    assert comp.purl == "pkg:npm/lodash@4.17.21"


def test_sbom_document_model():
    doc = SBOMDocument(
        id="sbom-1",
        scan_id="scan-1",
        target_path="/tmp/project",
        format="cyclonedx",
        components=[],
    )
    assert doc.format == "cyclonedx"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_models_phase2.py -v`
Expected: FAIL with ImportError (ScanType.DAST, target_url, SBOMComponent not defined)

- [ ] **Step 3: Add DAST and NETWORK to ScanType enum**

In `backend/src/models.py`, add to the `ScanType` enum:

```python
class ScanType(str, Enum):
    CODE = "code"
    DEPENDENCY = "dependency"
    IAC = "iac"
    BASELINE = "baseline"
    DAST = "dast"
    NETWORK = "network"
```

- [ ] **Step 4: Add target_url and target_host to Scan and ScanRequest**

In `backend/src/models.py`, add optional fields to `ScanRequest`:

```python
class ScanRequest(BaseModel):
    target_path: str
    scan_types: list[str]
    target_url: Optional[str] = None
    target_host: Optional[str] = None
```

Add the same fields to `Scan`:

```python
class Scan(BaseModel):
    # ... existing fields ...
    target_url: Optional[str] = None
    target_host: Optional[str] = None
```

- [ ] **Step 5: Add SBOMComponent and SBOMDocument models**

In `backend/src/models.py`, add:

```python
class SBOMComponent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    sbom_id: str
    name: str
    version: str
    type: str = "library"
    purl: Optional[str] = None
    license: Optional[str] = None
    supplier: Optional[str] = None


class SBOMDocument(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    scan_id: Optional[str] = None
    target_path: str
    format: str = "cyclonedx"
    components: list[SBOMComponent] = []
    created_at: datetime = Field(default_factory=datetime.now)
```

- [ ] **Step 6: Update database schema for new fields**

In `backend/src/database.py`, update `init_db()` to add columns to the scans table and create SBOM tables:

```python
# In init_db(), after existing CREATE TABLE scans:
await db.execute("""
    CREATE TABLE IF NOT EXISTS sbom_documents (
        id TEXT PRIMARY KEY,
        scan_id TEXT,
        target_path TEXT NOT NULL,
        format TEXT NOT NULL DEFAULT 'cyclonedx',
        created_at TEXT NOT NULL,
        FOREIGN KEY (scan_id) REFERENCES scans(id)
    )
""")
await db.execute("""
    CREATE TABLE IF NOT EXISTS sbom_components (
        id TEXT PRIMARY KEY,
        sbom_id TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT NOT NULL,
        type TEXT NOT NULL DEFAULT 'library',
        purl TEXT,
        license TEXT,
        supplier TEXT,
        FOREIGN KEY (sbom_id) REFERENCES sbom_documents(id)
    )
""")
```

Add ALTER TABLE statements for existing scans table (wrapped in try/except for idempotency):

```python
for col in ["target_url", "target_host"]:
    try:
        await db.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")
    except Exception:
        pass
```

- [ ] **Step 7: Add SBOM persistence functions**

In `backend/src/database.py`, add:

```python
async def save_sbom(doc: SBOMDocument) -> None:
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        await db.execute(
            "INSERT OR REPLACE INTO sbom_documents (id, scan_id, target_path, format, created_at) VALUES (?, ?, ?, ?, ?)",
            (doc.id, doc.scan_id, doc.target_path, doc.format, doc.created_at.isoformat()),
        )
        for comp in doc.components:
            await db.execute(
                "INSERT OR REPLACE INTO sbom_components (id, sbom_id, name, version, type, purl, license, supplier) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (comp.id, comp.sbom_id, comp.name, comp.version, comp.type, comp.purl, comp.license, comp.supplier),
            )
        await db.commit()


async def get_sbom(sbom_id: str) -> Optional[SBOMDocument]:
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        row = await db.execute_fetchall("SELECT * FROM sbom_documents WHERE id = ?", (sbom_id,))
        if not row:
            return None
        doc_row = dict(row[0])
        comps = await db.execute_fetchall("SELECT * FROM sbom_components WHERE sbom_id = ?", (sbom_id,))
        components = [SBOMComponent(**dict(c)) for c in comps]
        return SBOMDocument(
            id=doc_row["id"],
            scan_id=doc_row["scan_id"],
            target_path=doc_row["target_path"],
            format=doc_row["format"],
            components=components,
            created_at=datetime.fromisoformat(doc_row["created_at"]),
        )


async def get_sboms_for_scan(scan_id: str) -> list[SBOMDocument]:
    async with aiosqlite.connect(settings.database_path) as db:
        db.row_factory = aiosqlite.Row
        rows = await db.execute_fetchall("SELECT * FROM sbom_documents WHERE scan_id = ?", (scan_id,))
        results = []
        for doc_row in rows:
            doc_row = dict(doc_row)
            comps = await db.execute_fetchall("SELECT * FROM sbom_components WHERE sbom_id = ?", (doc_row["id"],))
            components = [SBOMComponent(**dict(c)) for c in comps]
            results.append(SBOMDocument(
                id=doc_row["id"],
                scan_id=doc_row["scan_id"],
                target_path=doc_row["target_path"],
                format=doc_row["format"],
                components=components,
                created_at=datetime.fromisoformat(doc_row["created_at"]),
            ))
        return results
```

- [ ] **Step 8: Add config settings for Phase 2**

In `backend/src/config.py`, add to `Settings`:

```python
class Settings(BaseSettings):
    # ... existing ...
    nmap_extra_args: str = ""
    zap_api_key: Optional[str] = None
    zap_address: str = "http://localhost:8080"
    dast_timeout: int = 120
```

- [ ] **Step 9: Update scan row serialization**

In `backend/src/database.py`, update `_scan_from_row()` to include `target_url` and `target_host`:

```python
def _scan_from_row(row: dict) -> Scan:
    return Scan(
        # ... existing fields ...
        target_url=row.get("target_url"),
        target_host=row.get("target_host"),
    )
```

Update `save_scan()` to persist the new fields in INSERT and UPDATE queries.

- [ ] **Step 10: Run tests to verify they pass**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_models_phase2.py -v`
Expected: All PASS

- [ ] **Step 11: Commit**

```bash
git add backend/src/models.py backend/src/database.py backend/src/config.py backend/tests/test_models_phase2.py
git commit -m "feat: add DAST/network scan types, SBOM models, and database schema"
```

---

### Task 2: Built-in DAST Scanner

**Files:**
- Create: `backend/src/scanners/dast_builtin.py`
- Test: `backend/tests/test_dast_builtin.py`

- [ ] **Step 1: Write failing test for built-in DAST scanner**

```python
# backend/tests/test_dast_builtin.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.scanners.dast_builtin import BuiltinDASTScanner
from src.models import ScanType


@pytest.fixture
def scanner():
    return BuiltinDASTScanner()


def test_scanner_name(scanner):
    assert scanner.name == "builtin_dast"
    assert scanner.scan_type == ScanType.DAST


@pytest.mark.asyncio
async def test_is_available(scanner):
    assert await scanner.is_available() is True


@pytest.mark.asyncio
async def test_scan_missing_headers():
    scanner = BuiltinDASTScanner()
    with patch("src.scanners.dast_builtin.httpx.AsyncClient") as MockClient:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {}
        mock_response.url = "http://example.com"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        MockClient.return_value = mock_client

        findings = await scanner.scan("/tmp", "scan-1", target_url="http://example.com")
        # Should find missing security headers
        header_findings = [f for f in findings if "header" in f.title.lower()]
        assert len(header_findings) > 0


@pytest.mark.asyncio
async def test_scan_no_url_returns_empty():
    scanner = BuiltinDASTScanner()
    findings = await scanner.scan("/tmp", "scan-1")
    assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_dast_builtin.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement the built-in DAST scanner**

```python
# backend/src/scanners/dast_builtin.py
"""Lightweight built-in DAST scanner using httpx.

Checks for missing security headers, insecure cookies, mixed content,
and basic information disclosure without requiring external tools.
"""

import logging
from typing import Optional

import httpx

from ..models import Finding, ScanType
from .base import BaseScanner

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "title": "Missing Strict-Transport-Security Header",
        "severity": "medium",
        "description": "The HTTP Strict-Transport-Security (HSTS) header is not set. This allows downgrade attacks and cookie hijacking.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "cwe": "CWE-319",
    },
    "Content-Security-Policy": {
        "title": "Missing Content-Security-Policy Header",
        "severity": "medium",
        "description": "No Content-Security-Policy header found. This makes the application more susceptible to XSS attacks.",
        "remediation": "Add a Content-Security-Policy header with appropriate directives.",
        "cwe": "CWE-79",
    },
    "X-Content-Type-Options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": "low",
        "description": "The X-Content-Type-Options header is not set to 'nosniff'. Browsers may MIME-sniff responses.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
        "cwe": "CWE-16",
    },
    "X-Frame-Options": {
        "title": "Missing X-Frame-Options Header",
        "severity": "medium",
        "description": "No X-Frame-Options header set. The site may be vulnerable to clickjacking.",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
        "cwe": "CWE-1021",
    },
    "X-XSS-Protection": {
        "title": "Missing X-XSS-Protection Header",
        "severity": "low",
        "description": "The X-XSS-Protection header is not set.",
        "remediation": "Add header: X-XSS-Protection: 1; mode=block",
        "cwe": "CWE-79",
    },
    "Referrer-Policy": {
        "title": "Missing Referrer-Policy Header",
        "severity": "low",
        "description": "No Referrer-Policy header. The browser may send the full URL as a referrer to other sites.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
        "cwe": "CWE-200",
    },
    "Permissions-Policy": {
        "title": "Missing Permissions-Policy Header",
        "severity": "info",
        "description": "No Permissions-Policy header found. Browser features are not explicitly restricted.",
        "remediation": "Add a Permissions-Policy header to restrict browser features.",
        "cwe": "CWE-16",
    },
}

DANGEROUS_HEADERS_TO_CHECK = {
    "Server": {
        "title": "Server Version Disclosure",
        "severity": "info",
        "description": "The Server header discloses server software and version information.",
        "remediation": "Remove or genericize the Server header to prevent information disclosure.",
        "cwe": "CWE-200",
    },
    "X-Powered-By": {
        "title": "Technology Stack Disclosure (X-Powered-By)",
        "severity": "info",
        "description": "The X-Powered-By header reveals the technology stack used by the application.",
        "remediation": "Remove the X-Powered-By header.",
        "cwe": "CWE-200",
    },
}


class BuiltinDASTScanner(BaseScanner):
    name = "builtin_dast"
    scan_type = ScanType.DAST
    description = "Lightweight DAST checks: security headers, cookies, info disclosure"
    checks = ["security-headers", "cookie-flags", "info-disclosure"]

    async def is_available(self) -> bool:
        return True

    async def scan(
        self,
        target_path: str,
        scan_id: str,
        *,
        target_url: Optional[str] = None,
        **kwargs,
    ) -> list[Finding]:
        if not target_url:
            logger.info("No target_url provided, skipping built-in DAST scan")
            return []

        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                timeout=30.0,
                follow_redirects=True,
                verify=False,
            ) as client:
                response = await client.get(target_url)

                # Check missing security headers
                for header_name, info in SECURITY_HEADERS.items():
                    if header_name.lower() not in {k.lower() for k in response.headers.keys()}:
                        findings.append(Finding(
                            scan_id=scan_id,
                            scanner=self.name,
                            scan_type=self.scan_type.value,
                            severity=info["severity"],
                            title=info["title"],
                            description=f"{info['description']}\n\nURL: {response.url}",
                            file_path=str(response.url),
                            cwe=info["cwe"],
                            remediation=info["remediation"],
                            metadata={"url": str(response.url), "check": "missing-header"},
                        ))

                # Check info-disclosure headers
                for header_name, info in DANGEROUS_HEADERS_TO_CHECK.items():
                    val = response.headers.get(header_name)
                    if val:
                        findings.append(Finding(
                            scan_id=scan_id,
                            scanner=self.name,
                            scan_type=self.scan_type.value,
                            severity=info["severity"],
                            title=info["title"],
                            description=f"{info['description']}\n\nValue: {val}\nURL: {response.url}",
                            file_path=str(response.url),
                            cwe=info["cwe"],
                            remediation=info["remediation"],
                            metadata={"url": str(response.url), "header_value": val, "check": "info-disclosure"},
                        ))

                # Check cookie security flags
                for cookie in response.cookies.jar:
                    issues = []
                    if not cookie.secure:
                        issues.append("Secure flag not set")
                    if "httponly" not in str(getattr(cookie, "_rest", {})).lower():
                        issues.append("HttpOnly flag not set")

                    if issues:
                        findings.append(Finding(
                            scan_id=scan_id,
                            scanner=self.name,
                            scan_type=self.scan_type.value,
                            severity="medium",
                            title=f"Insecure Cookie: {cookie.name}",
                            description=f"Cookie '{cookie.name}' has security issues: {', '.join(issues)}",
                            file_path=str(response.url),
                            cwe="CWE-614",
                            remediation="Set Secure and HttpOnly flags on all cookies. Add SameSite=Strict where appropriate.",
                            metadata={"url": str(response.url), "cookie": cookie.name, "issues": issues, "check": "cookie-flags"},
                        ))

        except httpx.RequestError as e:
            logger.error("DAST scan failed for %s: %s", target_url, e)
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type.value,
                severity="info",
                title="DAST Scan Connection Error",
                description=f"Could not connect to {target_url}: {e}",
                file_path=target_url,
                metadata={"error": str(e)},
            ))

        return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_dast_builtin.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/scanners/dast_builtin.py backend/tests/test_dast_builtin.py
git commit -m "feat: add built-in DAST scanner with header/cookie/info-disclosure checks"
```

---

### Task 3: ZAP Scanner Wrapper

**Files:**
- Create: `backend/src/scanners/zap_scanner.py`
- Test: `backend/tests/test_zap_scanner.py`

- [ ] **Step 1: Write failing test for ZAP scanner**

```python
# backend/tests/test_zap_scanner.py
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from src.scanners.zap_scanner import ZAPScanner
from src.models import ScanType


@pytest.fixture
def scanner():
    return ZAPScanner()


def test_scanner_name(scanner):
    assert scanner.name == "zap"
    assert scanner.scan_type == ScanType.DAST


@pytest.mark.asyncio
async def test_not_available_when_no_zap():
    scanner = ZAPScanner()
    with patch("src.scanners.zap_scanner.ZAPv2", None):
        assert await scanner.is_available() is False


@pytest.mark.asyncio
async def test_scan_no_url_returns_empty():
    scanner = ZAPScanner()
    findings = await scanner.scan("/tmp", "scan-1")
    assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_zap_scanner.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement ZAP scanner wrapper**

```python
# backend/src/scanners/zap_scanner.py
"""OWASP ZAP scanner wrapper.

Connects to a running ZAP instance via its API, triggers a spider + active scan,
and collects alerts as findings.
"""

import asyncio
import logging
from typing import Optional

from ..config import get_settings
from ..models import Finding, ScanType
from .base import BaseScanner

logger = logging.getLogger(__name__)

try:
    from zapv2 import ZAPv2
except ImportError:
    ZAPv2 = None

SEVERITY_MAP = {
    "0": "info",      # Informational
    "1": "low",       # Low
    "2": "medium",    # Medium
    "3": "high",      # High
}


class ZAPScanner(BaseScanner):
    name = "zap"
    scan_type = ScanType.DAST
    description = "OWASP ZAP active scanner for comprehensive DAST"
    checks = ["zap-spider", "zap-active-scan", "zap-alerts"]
    install_hint = "pip install python-owasp-zap-v2.4 and ensure ZAP is running"

    async def is_available(self) -> bool:
        if ZAPv2 is None:
            return False
        settings = get_settings()
        try:
            zap = ZAPv2(apikey=settings.zap_api_key or "", proxies={"http": settings.zap_address, "https": settings.zap_address})
            zap.core.version
            return True
        except Exception:
            return False

    async def scan(
        self,
        target_path: str,
        scan_id: str,
        *,
        target_url: Optional[str] = None,
        **kwargs,
    ) -> list[Finding]:
        if not target_url:
            logger.info("No target_url provided, skipping ZAP scan")
            return []

        if ZAPv2 is None:
            logger.warning("ZAP Python client not installed")
            return []

        settings = get_settings()
        zap = ZAPv2(
            apikey=settings.zap_api_key or "",
            proxies={"http": settings.zap_address, "https": settings.zap_address},
        )

        findings: list[Finding] = []
        try:
            # Spider the target
            logger.info("Starting ZAP spider on %s", target_url)
            spider_id = zap.spider.scan(target_url)
            while int(zap.spider.status(spider_id)) < 100:
                await asyncio.sleep(2)

            # Active scan
            logger.info("Starting ZAP active scan on %s", target_url)
            scan_id_zap = zap.ascan.scan(target_url)
            while int(zap.ascan.status(scan_id_zap)) < 100:
                await asyncio.sleep(5)

            # Collect alerts
            alerts = zap.core.alerts(baseurl=target_url)
            for alert in alerts:
                severity = SEVERITY_MAP.get(str(alert.get("risk", "0")), "info")
                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type.value,
                    severity=severity,
                    title=alert.get("alert", "ZAP Alert"),
                    description=alert.get("description", ""),
                    file_path=alert.get("url", target_url),
                    cwe=f"CWE-{alert['cweid']}" if alert.get("cweid") and alert["cweid"] != "-1" else None,
                    remediation=alert.get("solution", ""),
                    rule_id=f"zap-{alert.get('pluginid', 'unknown')}",
                    metadata={
                        "url": alert.get("url", ""),
                        "param": alert.get("param", ""),
                        "evidence": alert.get("evidence", ""),
                        "confidence": alert.get("confidence", ""),
                        "reference": alert.get("reference", ""),
                        "wascid": alert.get("wascid", ""),
                    },
                ))

        except Exception as e:
            logger.error("ZAP scan failed: %s", e)
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type.value,
                severity="info",
                title="ZAP Scan Error",
                description=f"ZAP scan failed: {e}",
                file_path=target_url,
                metadata={"error": str(e)},
            ))

        return findings
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_zap_scanner.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/scanners/zap_scanner.py backend/tests/test_zap_scanner.py
git commit -m "feat: add OWASP ZAP scanner wrapper"
```

---

### Task 4: Nmap Network Scanner

**Files:**
- Create: `backend/src/scanners/nmap_scanner.py`
- Test: `backend/tests/test_nmap_scanner.py`

- [ ] **Step 1: Write failing test for nmap scanner**

```python
# backend/tests/test_nmap_scanner.py
import pytest
from unittest.mock import AsyncMock, patch
from src.scanners.nmap_scanner import NmapScanner
from src.models import ScanType


@pytest.fixture
def scanner():
    return NmapScanner()


def test_scanner_name(scanner):
    assert scanner.name == "nmap"
    assert scanner.scan_type == ScanType.NETWORK


@pytest.mark.asyncio
async def test_scan_no_host_returns_empty():
    scanner = NmapScanner()
    findings = await scanner.scan("/tmp", "scan-1")
    assert findings == []


@pytest.mark.asyncio
async def test_parse_nmap_xml():
    scanner = NmapScanner()
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open"/>
            <service name="ssh" product="OpenSSH" version="8.9"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open"/>
            <service name="http" product="nginx" version="1.18.0"/>
          </port>
          <port protocol="tcp" portid="23">
            <state state="open"/>
            <service name="telnet"/>
          </port>
        </ports>
      </host>
    </nmaprun>"""
    findings = scanner._parse_nmap_xml(xml, "scan-1")
    assert len(findings) >= 3
    # Telnet should be high severity
    telnet = [f for f in findings if "23" in f.title and "telnet" in f.title.lower()]
    assert len(telnet) == 1
    assert telnet[0].severity == "high"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_nmap_scanner.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement nmap scanner**

Note: This scanner runs the `nmap` CLI tool using Python's `asyncio.create_subprocess_exec` for safe, non-shell command execution (no shell=True, no string interpolation). The target host is validated before use.

```python
# backend/src/scanners/nmap_scanner.py
"""Nmap network scanner wrapper.

Runs nmap with XML output, parses results to identify open ports,
services, and potential security issues.
"""

import asyncio
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from defusedxml import ElementTree as ET

from ..config import get_settings
from ..models import Finding, ScanType
from .base import BaseScanner

logger = logging.getLogger(__name__)

# Ports that are inherently risky when exposed
HIGH_RISK_PORTS = {
    21: ("FTP", "high", "CWE-319"),
    23: ("Telnet", "high", "CWE-319"),
    135: ("MS-RPC", "medium", "CWE-284"),
    139: ("NetBIOS", "medium", "CWE-284"),
    445: ("SMB", "medium", "CWE-284"),
    1433: ("MSSQL", "medium", "CWE-284"),
    1521: ("Oracle DB", "medium", "CWE-284"),
    3306: ("MySQL", "medium", "CWE-284"),
    3389: ("RDP", "medium", "CWE-284"),
    5432: ("PostgreSQL", "medium", "CWE-284"),
    5900: ("VNC", "high", "CWE-284"),
    6379: ("Redis", "high", "CWE-284"),
    11211: ("Memcached", "high", "CWE-284"),
    27017: ("MongoDB", "high", "CWE-284"),
}

# Services considered insecure regardless of port
INSECURE_SERVICES = {"telnet", "ftp", "rsh", "rlogin", "rexec"}


def _validate_host(host: str) -> str:
    """Validate and sanitize target host. Raises ValueError if invalid."""
    import re
    host = host.strip()
    # Allow IPv4, IPv6, or valid hostnames only
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    ipv6_pattern = r"^[0-9a-fA-F:]+$"
    hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$"
    cidr_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"

    if not (re.match(ipv4_pattern, host) or re.match(ipv6_pattern, host) or
            re.match(hostname_pattern, host) or re.match(cidr_pattern, host)):
        raise ValueError(f"Invalid target host: {host}")

    return host


class NmapScanner(BaseScanner):
    name = "nmap"
    scan_type = ScanType.NETWORK
    description = "Network port and service scanner using nmap"
    checks = ["open-ports", "service-detection", "risky-services"]
    install_hint = "Install nmap: apt install nmap / brew install nmap"

    async def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def _parse_nmap_xml(self, xml_content: str, scan_id: str) -> list[Finding]:
        """Parse nmap XML output into findings."""
        findings: list[Finding] = []
        root = ET.fromstring(xml_content)

        for host in root.findall(".//host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                protocol = port_el.get("protocol", "tcp")
                port_num = int(port_el.get("portid", "0"))
                service_el = port_el.find("service")

                service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                service_str = f"{service_name}"
                if product:
                    service_str += f" ({product}"
                    if version:
                        service_str += f" {version}"
                    service_str += ")"

                # Determine severity
                severity = "info"
                cwe = None
                remediation = "Review whether this port needs to be exposed. Close unnecessary ports and restrict access with firewall rules."

                if port_num in HIGH_RISK_PORTS:
                    label, severity, cwe = HIGH_RISK_PORTS[port_num]
                    remediation = f"{label} on port {port_num} is a security risk. Close this port or restrict access via firewall. Consider using encrypted alternatives."
                elif service_name.lower() in INSECURE_SERVICES:
                    severity = "high"
                    cwe = "CWE-319"
                    remediation = f"{service_name} transmits data in cleartext. Replace with an encrypted protocol (e.g., SSH instead of Telnet)."

                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type.value,
                    severity=severity,
                    title=f"Open port {port_num}/{protocol} — {service_name}",
                    description=f"Host {addr} has port {port_num}/{protocol} open running {service_str}.",
                    file_path=addr,
                    line_start=port_num,
                    cwe=cwe,
                    remediation=remediation,
                    metadata={
                        "host": addr,
                        "port": port_num,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                    },
                ))

        return findings

    async def scan(
        self,
        target_path: str,
        scan_id: str,
        *,
        target_host: Optional[str] = None,
        **kwargs,
    ) -> list[Finding]:
        if not target_host:
            logger.info("No target_host provided, skipping nmap scan")
            return []

        try:
            validated_host = _validate_host(target_host)
        except ValueError as e:
            logger.error("Invalid target host: %s", e)
            return []

        settings = get_settings()
        with tempfile.TemporaryDirectory() as tmpdir:
            xml_path = Path(tmpdir) / "nmap_output.xml"

            # Build nmap command: service detection + XML output
            cmd = ["nmap", "-sV", "-oX", str(xml_path)]

            # Add extra args from config (split safely)
            extra = settings.nmap_extra_args.strip()
            if extra:
                cmd.extend(extra.split())

            cmd.append(validated_host)

            logger.info("Running nmap: %s", " ".join(cmd))

            # Use asyncio subprocess for non-blocking execution
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=settings.scan_timeout,
            )

            if proc.returncode != 0:
                logger.error("nmap failed (rc=%d): %s", proc.returncode, stderr.decode())
                return [Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type.value,
                    severity="info",
                    title="Nmap Scan Error",
                    description=f"Nmap exited with code {proc.returncode}: {stderr.decode()[:500]}",
                    file_path=validated_host,
                    metadata={"error": stderr.decode()[:500]},
                )]

            xml_content = xml_path.read_text()
            return self._parse_nmap_xml(xml_content, scan_id)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_nmap_scanner.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add backend/src/scanners/nmap_scanner.py backend/tests/test_nmap_scanner.py
git commit -m "feat: add nmap network scanner with XML parsing and risk classification"
```

---

### Task 5: SBOM Generator

**Files:**
- Create: `backend/src/sbom.py`
- Create: `backend/src/api/sbom.py`
- Test: `backend/tests/test_sbom.py`

- [ ] **Step 1: Write failing test for SBOM generator**

```python
# backend/tests/test_sbom.py
import json
import pytest
from pathlib import Path
from src.sbom import SBOMGenerator


@pytest.fixture
def generator():
    return SBOMGenerator()


@pytest.fixture
def tmp_project(tmp_path):
    """Create a temp project with package.json and requirements.txt."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({
        "name": "test-project",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "4.17.21",
        },
        "devDependencies": {
            "jest": "^29.0.0",
        },
    }))

    req = tmp_path / "requirements.txt"
    req.write_text("flask==2.3.0\nrequests>=2.28.0\n# comment line\n\n")

    return tmp_path


def test_parse_package_json(generator, tmp_project):
    components = generator._parse_package_json(tmp_project / "package.json")
    names = {c.name for c in components}
    assert "express" in names
    assert "lodash" in names
    assert "jest" in names


def test_parse_requirements_txt(generator, tmp_project):
    components = generator._parse_requirements_txt(tmp_project / "requirements.txt")
    names = {c.name for c in components}
    assert "flask" in names
    assert "requests" in names
    assert len(components) == 2  # comment and blank line skipped


@pytest.mark.asyncio
async def test_generate_sbom(generator, tmp_project):
    doc = await generator.generate(str(tmp_project), format="cyclonedx")
    assert doc.format == "cyclonedx"
    assert len(doc.components) >= 4  # 3 npm + 2 pip (minus duplicates)
    names = {c.name for c in doc.components}
    assert "express" in names
    assert "flask" in names


def test_export_cyclonedx(generator, tmp_project):
    import asyncio
    doc = asyncio.get_event_loop().run_until_complete(
        generator.generate(str(tmp_project), format="cyclonedx")
    )
    exported = generator.export_cyclonedx(doc)
    data = json.loads(exported)
    assert data["bomFormat"] == "CycloneDX"
    assert len(data["components"]) > 0


def test_export_spdx(generator, tmp_project):
    import asyncio
    doc = asyncio.get_event_loop().run_until_complete(
        generator.generate(str(tmp_project), format="spdx")
    )
    exported = generator.export_spdx(doc)
    data = json.loads(exported)
    assert data["spdxVersion"] == "SPDX-2.3"
    assert len(data["packages"]) > 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_sbom.py -v`
Expected: FAIL with ModuleNotFoundError

- [ ] **Step 3: Implement SBOM generator**

```python
# backend/src/sbom.py
"""Software Bill of Materials (SBOM) generator.

Supports two strategies:
1. Syft (preferred) — if installed, delegates to Syft for comprehensive SBOM generation.
2. Built-in fallback — parses common manifest files: package.json, requirements.txt,
   go.mod, Cargo.toml, Gemfile.lock, composer.lock, Pipfile.lock.

Exports in CycloneDX 1.5 and SPDX 2.3 JSON formats.
"""

import json
import logging
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import uuid4

from .models import SBOMComponent, SBOMDocument

logger = logging.getLogger(__name__)

# Map of manifest filename to parser method name
MANIFEST_PARSERS = {
    "package.json": "_parse_package_json",
    "requirements.txt": "_parse_requirements_txt",
    "go.mod": "_parse_go_mod",
    "Cargo.toml": "_parse_cargo_toml",
    "Gemfile.lock": "_parse_gemfile_lock",
    "composer.lock": "_parse_composer_lock",
    "Pipfile.lock": "_parse_pipfile_lock",
}


class SBOMGenerator:
    """Generate SBOM from a project directory."""

    def _parse_package_json(self, path: Path) -> list[SBOMComponent]:
        """Parse npm package.json for dependencies."""
        data = json.loads(path.read_text())
        components = []
        for dep_key in ("dependencies", "devDependencies", "peerDependencies"):
            deps = data.get(dep_key, {})
            for name, version in deps.items():
                # Strip semver range operators
                clean_version = re.sub(r"^[\^~>=<]*", "", version)
                components.append(SBOMComponent(
                    sbom_id="",  # filled by generate()
                    name=name,
                    version=clean_version,
                    type="library",
                    purl=f"pkg:npm/{name}@{clean_version}",
                ))
        return components

    def _parse_requirements_txt(self, path: Path) -> list[SBOMComponent]:
        """Parse Python requirements.txt."""
        components = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Split on version specifiers
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*([><=!~]+\s*[\d\.]+)?", line)
            if match:
                name = match.group(1)
                version = re.sub(r"^[><=!~]+\s*", "", match.group(2) or "0.0.0")
                components.append(SBOMComponent(
                    sbom_id="",
                    name=name,
                    version=version,
                    type="library",
                    purl=f"pkg:pypi/{name}@{version}",
                ))
        return components

    def _parse_go_mod(self, path: Path) -> list[SBOMComponent]:
        """Parse Go go.mod for dependencies."""
        components = []
        in_require = False
        for line in path.read_text().splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if line == ")":
                in_require = False
                continue
            if in_require or line.startswith("require "):
                line = line.replace("require ", "").strip()
                if line.startswith("//"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    mod_path = parts[0]
                    version = parts[1]
                    name = mod_path.split("/")[-1] if "/" in mod_path else mod_path
                    components.append(SBOMComponent(
                        sbom_id="",
                        name=name,
                        version=version,
                        type="library",
                        purl=f"pkg:golang/{mod_path}@{version}",
                    ))
        return components

    def _parse_cargo_toml(self, path: Path) -> list[SBOMComponent]:
        """Parse Rust Cargo.toml for dependencies (basic parsing)."""
        components = []
        in_deps = False
        for line in path.read_text().splitlines():
            line = line.strip()
            if line == "[dependencies]" or line == "[dev-dependencies]":
                in_deps = True
                continue
            if line.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps and "=" in line:
                parts = line.split("=", 1)
                name = parts[0].strip()
                version_str = parts[1].strip().strip('"').strip("'")
                # Handle {version = "x.y.z", ...} format
                if version_str.startswith("{"):
                    match = re.search(r'version\s*=\s*"([^"]+)"', version_str)
                    version_str = match.group(1) if match else "0.0.0"
                components.append(SBOMComponent(
                    sbom_id="",
                    name=name,
                    version=version_str,
                    type="library",
                    purl=f"pkg:cargo/{name}@{version_str}",
                ))
        return components

    def _parse_gemfile_lock(self, path: Path) -> list[SBOMComponent]:
        """Parse Ruby Gemfile.lock for dependencies."""
        components = []
        in_specs = False
        for line in path.read_text().splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs:
                if not line.startswith("    "):
                    if line.strip() and not line.startswith("      "):
                        in_specs = False
                        continue
                match = re.match(r"^\s{4}(\S+)\s+\((.+)\)", line)
                if match:
                    components.append(SBOMComponent(
                        sbom_id="",
                        name=match.group(1),
                        version=match.group(2),
                        type="library",
                        purl=f"pkg:gem/{match.group(1)}@{match.group(2)}",
                    ))
        return components

    def _parse_composer_lock(self, path: Path) -> list[SBOMComponent]:
        """Parse PHP composer.lock for dependencies."""
        data = json.loads(path.read_text())
        components = []
        for pkg in data.get("packages", []) + data.get("packages-dev", []):
            name = pkg.get("name", "")
            version = pkg.get("version", "").lstrip("v")
            if name:
                components.append(SBOMComponent(
                    sbom_id="",
                    name=name,
                    version=version,
                    type="library",
                    purl=f"pkg:composer/{name}@{version}",
                ))
        return components

    def _parse_pipfile_lock(self, path: Path) -> list[SBOMComponent]:
        """Parse Python Pipfile.lock for dependencies."""
        data = json.loads(path.read_text())
        components = []
        for section in ("default", "develop"):
            pkgs = data.get(section, {})
            for name, info in pkgs.items():
                version = info.get("version", "").lstrip("=")
                if name and version:
                    components.append(SBOMComponent(
                        sbom_id="",
                        name=name,
                        version=version,
                        type="library",
                        purl=f"pkg:pypi/{name}@{version}",
                    ))
        return components

    async def generate(
        self,
        target_path: str,
        format: str = "cyclonedx",
        scan_id: Optional[str] = None,
    ) -> SBOMDocument:
        """Generate SBOM for target path. Uses Syft if available, otherwise built-in parsers."""
        sbom_id = str(uuid4())

        # Try Syft first
        if shutil.which("syft"):
            try:
                return await self._generate_with_syft(target_path, sbom_id, format, scan_id)
            except Exception as e:
                logger.warning("Syft failed, falling back to built-in: %s", e)

        # Built-in fallback
        return self._generate_builtin(target_path, sbom_id, format, scan_id)

    def _generate_builtin(
        self,
        target_path: str,
        sbom_id: str,
        format: str,
        scan_id: Optional[str],
    ) -> SBOMDocument:
        """Generate SBOM by parsing manifest files."""
        target = Path(target_path)
        all_components: list[SBOMComponent] = []
        seen_purls: set[str] = set()

        for manifest_name, parser_method in MANIFEST_PARSERS.items():
            # Search for manifest files (max depth 3)
            for manifest_path in target.rglob(manifest_name):
                # Skip node_modules, vendor, etc.
                parts = manifest_path.relative_to(target).parts
                if any(p in {"node_modules", "vendor", ".git", "venv", ".venv", "__pycache__"} for p in parts):
                    continue
                # Limit depth
                if len(parts) > 4:
                    continue

                try:
                    parser = getattr(self, parser_method)
                    components = parser(manifest_path)
                    for comp in components:
                        comp.sbom_id = sbom_id
                        if comp.purl and comp.purl not in seen_purls:
                            seen_purls.add(comp.purl)
                            all_components.append(comp)
                        elif not comp.purl:
                            all_components.append(comp)
                except Exception as e:
                    logger.warning("Failed to parse %s: %s", manifest_path, e)

        return SBOMDocument(
            id=sbom_id,
            scan_id=scan_id,
            target_path=target_path,
            format=format,
            components=all_components,
        )

    async def _generate_with_syft(
        self,
        target_path: str,
        sbom_id: str,
        format: str,
        scan_id: Optional[str],
    ) -> SBOMDocument:
        """Generate SBOM using Syft."""
        import asyncio

        syft_format = "cyclonedx-json" if format == "cyclonedx" else "spdx-json"
        proc = await asyncio.create_subprocess_exec(
            "syft", target_path, "-o", syft_format, "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode != 0:
            raise RuntimeError(f"Syft failed: {stderr.decode()[:500]}")

        data = json.loads(stdout.decode())
        components = []

        if format == "cyclonedx":
            for comp in data.get("components", []):
                components.append(SBOMComponent(
                    sbom_id=sbom_id,
                    name=comp.get("name", ""),
                    version=comp.get("version", ""),
                    type=comp.get("type", "library"),
                    purl=comp.get("purl", ""),
                    license="; ".join(
                        lic.get("license", {}).get("id", "")
                        for lic in comp.get("licenses", [])
                    ) or None,
                ))
        else:  # spdx
            for pkg in data.get("packages", []):
                components.append(SBOMComponent(
                    sbom_id=sbom_id,
                    name=pkg.get("name", ""),
                    version=pkg.get("versionInfo", ""),
                    type="library",
                    purl=next(
                        (ref.get("referenceLocator", "")
                         for ref in pkg.get("externalRefs", [])
                         if ref.get("referenceType") == "purl"),
                        None,
                    ),
                    license=pkg.get("licenseDeclared"),
                    supplier=pkg.get("supplier"),
                ))

        return SBOMDocument(
            id=sbom_id,
            scan_id=scan_id,
            target_path=target_path,
            format=format,
            components=components,
        )

    def export_cyclonedx(self, doc: SBOMDocument) -> str:
        """Export SBOM as CycloneDX 1.5 JSON."""
        return json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{doc.id}",
            "version": 1,
            "metadata": {
                "timestamp": doc.created_at.isoformat(),
                "tools": [{"vendor": "SecureScan", "name": "securescan-sbom", "version": "1.0.0"}],
                "component": {
                    "type": "application",
                    "name": Path(doc.target_path).name,
                },
            },
            "components": [
                {
                    "type": comp.type,
                    "name": comp.name,
                    "version": comp.version,
                    **({"purl": comp.purl} if comp.purl else {}),
                    **({"licenses": [{"license": {"id": comp.license}}]} if comp.license else {}),
                    **({"supplier": {"name": comp.supplier}} if comp.supplier else {}),
                }
                for comp in doc.components
            ],
        }, indent=2)

    def export_spdx(self, doc: SBOMDocument) -> str:
        """Export SBOM as SPDX 2.3 JSON."""
        return json.dumps({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": Path(doc.target_path).name,
            "documentNamespace": f"https://securescan.local/sbom/{doc.id}",
            "creationInfo": {
                "created": doc.created_at.isoformat(),
                "creators": ["Tool: SecureScan-SBOM-1.0.0"],
            },
            "packages": [
                {
                    "SPDXID": f"SPDXRef-Package-{i}",
                    "name": comp.name,
                    "versionInfo": comp.version,
                    "downloadLocation": "NOASSERTION",
                    **({"licenseDeclared": comp.license} if comp.license else {"licenseDeclared": "NOASSERTION"}),
                    **({"supplier": comp.supplier} if comp.supplier else {}),
                    **({"externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": comp.purl}]} if comp.purl else {}),
                }
                for i, comp in enumerate(doc.components)
            ],
        }, indent=2)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_sbom.py -v`
Expected: All PASS

- [ ] **Step 5: Implement SBOM API endpoints**

```python
# backend/src/api/sbom.py
"""SBOM generation and retrieval API endpoints."""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse

from ..database import get_sbom, get_sboms_for_scan, save_sbom
from ..sbom import SBOMGenerator

router = APIRouter(prefix="/api/sbom", tags=["sbom"])

_generator = SBOMGenerator()


@router.post("/generate")
async def generate_sbom(
    target_path: str = Query(..., description="Path to scan for SBOM"),
    format: str = Query("cyclonedx", description="Output format: cyclonedx or spdx"),
    scan_id: str = Query(None, description="Optional scan ID to link SBOM to"),
):
    """Generate a Software Bill of Materials for the target path."""
    if format not in ("cyclonedx", "spdx"):
        raise HTTPException(status_code=400, detail="Format must be 'cyclonedx' or 'spdx'")

    doc = await _generator.generate(target_path, format=format, scan_id=scan_id)
    await save_sbom(doc)

    if format == "cyclonedx":
        content = _generator.export_cyclonedx(doc)
    else:
        content = _generator.export_spdx(doc)

    return JSONResponse(content={"sbom_id": doc.id, "format": format, "component_count": len(doc.components), "document": __import__("json").loads(content)})


@router.get("/{sbom_id}")
async def get_sbom_by_id(sbom_id: str):
    """Retrieve a previously generated SBOM."""
    doc = await get_sbom(sbom_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="SBOM not found")
    return doc


@router.get("/{sbom_id}/export")
async def export_sbom(
    sbom_id: str,
    format: str = Query("cyclonedx", description="Export format: cyclonedx or spdx"),
):
    """Export SBOM in CycloneDX or SPDX format."""
    doc = await get_sbom(sbom_id)
    if doc is None:
        raise HTTPException(status_code=404, detail="SBOM not found")

    if format == "cyclonedx":
        content = _generator.export_cyclonedx(doc)
    else:
        content = _generator.export_spdx(doc)

    return JSONResponse(
        content=__import__("json").loads(content),
        headers={"Content-Disposition": f"attachment; filename=sbom-{sbom_id}.json"},
    )


@router.get("/scan/{scan_id}")
async def get_sboms_for_scan_endpoint(scan_id: str):
    """Get all SBOMs linked to a scan."""
    return await get_sboms_for_scan(scan_id)
```

- [ ] **Step 6: Register SBOM router in app**

In `backend/src/api/__init__.py`, add:

```python
from .sbom import router as sbom_router
app.include_router(sbom_router)
```

- [ ] **Step 7: Commit**

```bash
git add backend/src/sbom.py backend/src/api/sbom.py backend/tests/test_sbom.py backend/src/api/__init__.py
git commit -m "feat: add SBOM generator with CycloneDX/SPDX export and API endpoints"
```

---

### Task 6: Register New Scanners & Update Scan Pipeline

**Files:**
- Modify: `backend/src/scanners/__init__.py`
- Modify: `backend/src/api/scans.py`
- Test: `backend/tests/test_scan_pipeline_phase2.py`

- [ ] **Step 1: Write failing test for scanner registration**

```python
# backend/tests/test_scan_pipeline_phase2.py
import pytest
from src.scanners import get_scanners_for_types, ALL_SCANNERS


def test_dast_scanners_registered():
    dast = get_scanners_for_types(["dast"])
    names = {s.name for s in dast}
    assert "builtin_dast" in names
    assert "zap" in names


def test_network_scanner_registered():
    net = get_scanners_for_types(["network"])
    names = {s.name for s in net}
    assert "nmap" in names


def test_all_scanners_includes_new():
    names = {s.name for s in ALL_SCANNERS}
    assert "builtin_dast" in names
    assert "zap" in names
    assert "nmap" in names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_scan_pipeline_phase2.py -v`
Expected: FAIL (new scanners not registered)

- [ ] **Step 3: Register new scanners**

In `backend/src/scanners/__init__.py`, add imports and instances:

```python
from .dast_builtin import BuiltinDASTScanner
from .zap_scanner import ZAPScanner
from .nmap_scanner import NmapScanner

ALL_SCANNERS = [
    # ... existing scanners ...
    BuiltinDASTScanner(),
    ZAPScanner(),
    NmapScanner(),
]
```

- [ ] **Step 4: Update scan pipeline to pass target_url and target_host**

In `backend/src/api/scans.py`, update `create_scan()` to pass the new fields from request to scan:

```python
@router.post("", response_model=Scan)
async def create_scan(request: ScanRequest):
    try:
        validated_path = validate_target_path(request.target_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    scan = Scan(
        target_path=validated_path,
        scan_types=request.scan_types,
        target_url=request.target_url,
        target_host=request.target_host,
    )
    await save_scan(scan)
    task = asyncio.create_task(_run_scan(scan.id))
    _RUNNING_SCAN_TASKS[scan.id] = task
    task.add_done_callback(lambda _: _RUNNING_SCAN_TASKS.pop(scan.id, None))
    return scan
```

Update `_run_scan()` to pass target_url and target_host to scanners:

```python
async def _run_one(scanner):
    results = await scanner.scan(
        scan.target_path,
        scan.id,
        target_url=scan.target_url,
        target_host=scan.target_host,
    )
    return scanner.name, results
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /home/amirb/Documents/securescan/backend && python -m pytest tests/test_scan_pipeline_phase2.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add backend/src/scanners/__init__.py backend/src/api/scans.py backend/tests/test_scan_pipeline_phase2.py
git commit -m "feat: register DAST/network scanners and pass target fields through pipeline"
```

---

### Task 7: Frontend Updates for DAST, Network & SBOM

**Files:**
- Modify: `frontend/src/lib/api.ts`
- Modify: `frontend/src/app/scan/page.tsx`
- Modify: `frontend/src/components/sidebar.tsx`
- Create: `frontend/src/app/sbom/page.tsx`

- [ ] **Step 1: Add new types and API functions to api.ts**

In `frontend/src/lib/api.ts`, add the new scan types to the SCAN_TYPES constant, add SBOM types, and update `startScan`:

```typescript
// Add to existing Scan interface
export interface Scan {
  // ... existing fields ...
  target_url?: string;
  target_host?: string;
}

// Add SBOM types
export interface SBOMComponent {
  id: string;
  sbom_id: string;
  name: string;
  version: string;
  type: string;
  purl?: string;
  license?: string;
  supplier?: string;
}

export interface SBOMDocument {
  id: string;
  scan_id?: string;
  target_path: string;
  format: string;
  components: SBOMComponent[];
  created_at: string;
}

// Update startScan to accept optional URL/host
export async function startScan(
  targetPath: string,
  scanTypes: string[],
  targetUrl?: string,
  targetHost?: string,
): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      target_path: targetPath,
      scan_types: scanTypes,
      target_url: targetUrl || undefined,
      target_host: targetHost || undefined,
    }),
  });
  if (!res.ok) throw new Error("Failed to start scan");
  return res.json();
}

// SBOM API functions
export async function generateSBOM(
  targetPath: string,
  format: string = "cyclonedx",
  scanId?: string,
): Promise<{ sbom_id: string; format: string; component_count: number; document: Record<string, unknown> }> {
  const params = new URLSearchParams({ target_path: targetPath, format });
  if (scanId) params.set("scan_id", scanId);
  const res = await fetch(`${API_BASE}/api/sbom/generate?${params}`, { method: "POST" });
  if (!res.ok) throw new Error("Failed to generate SBOM");
  return res.json();
}

export async function fetchSBOM(sbomId: string): Promise<SBOMDocument> {
  const res = await fetch(`${API_BASE}/api/sbom/${sbomId}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to fetch SBOM");
  return res.json();
}

export async function exportSBOM(sbomId: string, format: string = "cyclonedx"): Promise<Record<string, unknown>> {
  const res = await fetch(`${API_BASE}/api/sbom/${sbomId}/export?format=${format}`, { cache: "no-store" });
  if (!res.ok) throw new Error("Failed to export SBOM");
  return res.json();
}
```

- [ ] **Step 2: Add DAST and Network scan type options and input fields to scan page**

In `frontend/src/app/scan/page.tsx`, add to SCAN_TYPES:

```typescript
const SCAN_TYPES = [
  { id: "code", label: "Code Analysis" },
  { id: "dependency", label: "Dependency Scan" },
  { id: "iac", label: "IaC Analysis" },
  { id: "baseline", label: "Baseline Scan" },
  { id: "dast", label: "DAST (Web App)" },
  { id: "network", label: "Network Scan" },
];
```

Add state for target URL and host:

```typescript
const [targetUrl, setTargetUrl] = useState("");
const [targetHost, setTargetHost] = useState("");
```

Add conditional input fields in the form (after the scan types grid):

```tsx
{/* Target URL for DAST */}
{selectedTypes.has("dast") && (
  <div>
    <label className="block text-sm font-medium text-[#a1a1aa] mb-2">
      Target URL (for DAST)
    </label>
    <input
      type="url"
      value={targetUrl}
      onChange={(e) => setTargetUrl(e.target.value)}
      placeholder="https://example.com"
      disabled={!!isRunning}
      className="w-full px-4 py-2.5 rounded-lg bg-[#141414] border border-[#262626] text-[#ededed] placeholder-[#52525b] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors disabled:opacity-50"
    />
  </div>
)}

{/* Target Host for Network */}
{selectedTypes.has("network") && (
  <div>
    <label className="block text-sm font-medium text-[#a1a1aa] mb-2">
      Target Host (for Network Scan)
    </label>
    <input
      type="text"
      value={targetHost}
      onChange={(e) => setTargetHost(e.target.value)}
      placeholder="192.168.1.1 or hostname"
      disabled={!!isRunning}
      className="w-full px-4 py-2.5 rounded-lg bg-[#141414] border border-[#262626] text-[#ededed] placeholder-[#52525b] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors disabled:opacity-50"
    />
  </div>
)}
```

Update the `handleSubmit` function to pass the new fields:

```typescript
const newScan = await startScan(
  targetPath.trim(),
  Array.from(selectedTypes),
  targetUrl.trim() || undefined,
  targetHost.trim() || undefined,
);
```

- [ ] **Step 3: Add SBOM page link to sidebar**

In `frontend/src/components/sidebar.tsx`, add an SBOM navigation entry alongside existing items:

```tsx
{ href: "/sbom", label: "SBOM", icon: PackageIcon }
```

- [ ] **Step 4: Create SBOM page**

```tsx
// frontend/src/app/sbom/page.tsx
"use client";

import { useState } from "react";
import { Package, Loader2, Download, FolderOpen } from "lucide-react";
import { generateSBOM, exportSBOM } from "@/lib/api";
import type { SBOMDocument } from "@/lib/api";
import { DirectoryPicker } from "@/components/directory-picker";

export default function SBOMPage() {
  const [targetPath, setTargetPath] = useState("");
  const [format, setFormat] = useState<"cyclonedx" | "spdx">("cyclonedx");
  const [loading, setLoading] = useState(false);
  const [sbom, setSbom] = useState<{ sbom_id: string; component_count: number; document: Record<string, unknown> } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pickerOpen, setPickerOpen] = useState(false);

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetPath.trim()) return;

    setLoading(true);
    setError(null);
    setSbom(null);

    try {
      const result = await generateSBOM(targetPath.trim(), format);
      setSbom(result);
    } catch {
      setError("Failed to generate SBOM. Is the backend running?");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = () => {
    if (!sbom) return;
    const blob = new Blob([JSON.stringify(sbom.document, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sbom-${sbom.sbom_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6 max-w-3xl">
      <h1 className="text-2xl font-bold tracking-tight">SBOM Generator</h1>
      <p className="text-sm text-[#a1a1aa]">
        Generate a Software Bill of Materials for any project directory.
      </p>

      <form onSubmit={handleGenerate} className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-[#a1a1aa] mb-2">Target Path</label>
          <div className="flex">
            <input
              type="text"
              value={targetPath}
              onChange={(e) => setTargetPath(e.target.value)}
              placeholder="/path/to/your/project"
              className="flex-1 px-4 py-2.5 rounded-l-lg bg-[#141414] border border-[#262626] border-r-0 text-[#ededed] placeholder-[#52525b] focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 transition-colors"
            />
            <button
              type="button"
              onClick={() => setPickerOpen(true)}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-r-lg bg-[#141414] border border-[#262626] text-[#a1a1aa] hover:bg-[#1a1a1a] hover:text-[#ededed] transition-colors"
            >
              <FolderOpen size={16} />
              <span className="text-sm">Browse</span>
            </button>
          </div>
        </div>

        <DirectoryPicker
          isOpen={pickerOpen}
          onClose={() => setPickerOpen(false)}
          onSelect={(path) => { setTargetPath(path); setPickerOpen(false); }}
          initialPath={targetPath || undefined}
        />

        <div>
          <label className="block text-sm font-medium text-[#a1a1aa] mb-2">Format</label>
          <div className="flex gap-3">
            {(["cyclonedx", "spdx"] as const).map((f) => (
              <label
                key={f}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border cursor-pointer transition-colors ${
                  format === f
                    ? "border-blue-500/40 bg-blue-500/10"
                    : "border-[#262626] bg-[#141414] hover:border-[#404040]"
                }`}
              >
                <input
                  type="radio"
                  name="format"
                  value={f}
                  checked={format === f}
                  onChange={() => setFormat(f)}
                  className="sr-only"
                />
                <span className="text-sm font-medium">{f === "cyclonedx" ? "CycloneDX 1.5" : "SPDX 2.3"}</span>
              </label>
            ))}
          </div>
        </div>

        <button
          type="submit"
          disabled={loading || !targetPath.trim()}
          className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? (
            <>
              <Loader2 size={16} className="animate-spin" />
              Generating...
            </>
          ) : (
            <>
              <Package size={16} />
              Generate SBOM
            </>
          )}
        </button>
      </form>

      {error && (
        <div className="rounded-xl border border-red-500/20 bg-red-500/10 p-4">
          <p className="text-sm text-red-400">{error}</p>
        </div>
      )}

      {sbom && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-medium">SBOM Generated</h3>
              <p className="text-sm text-[#a1a1aa]">
                {sbom.component_count} components found
              </p>
            </div>
            <button
              onClick={handleDownload}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-[#262626] bg-[#141414] text-sm hover:bg-[#1a1a1a] transition-colors"
            >
              <Download size={14} />
              Download JSON
            </button>
          </div>

          <div className="rounded-xl border border-[#262626] bg-[#141414] p-4 max-h-96 overflow-auto">
            <pre className="text-xs text-[#a1a1aa] whitespace-pre-wrap">
              {JSON.stringify(sbom.document, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 5: Commit**

```bash
git add frontend/src/lib/api.ts frontend/src/app/scan/page.tsx frontend/src/components/sidebar.tsx frontend/src/app/sbom/page.tsx
git commit -m "feat: add DAST/network inputs to scan page, SBOM page and API client"
```

---

### Task 8: End-to-End Verification

- [ ] **Step 1: Run all backend tests**

```bash
cd /home/amirb/Documents/securescan/backend && python -m pytest tests/ -v
```

Expected: All tests pass.

- [ ] **Step 2: Verify frontend builds**

```bash
cd /home/amirb/Documents/securescan/frontend && npm run build
```

Expected: Build succeeds with no TypeScript errors.

- [ ] **Step 3: Manual smoke test**

1. Start backend: `cd backend && python -m src.main`
2. Start frontend: `cd frontend && npm run dev`
3. Navigate to scan page, verify DAST and Network scan type checkboxes appear
4. Select DAST, verify Target URL field appears
5. Select Network, verify Target Host field appears
6. Navigate to SBOM page, generate SBOM for a local project
7. Download the generated SBOM JSON

- [ ] **Step 4: Final commit if any fixes needed**

```bash
git add -A && git commit -m "fix: address issues found during verification"
```
