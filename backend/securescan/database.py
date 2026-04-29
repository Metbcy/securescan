import json
from datetime import datetime
from typing import Optional

import aiosqlite

from .config import settings
from .models import (
    Finding,
    FindingComment,
    FindingState,
    FindingWithState,
    SBOMComponent,
    SBOMDocument,
    Scan,
    ScannerSkip,
    ScanStatus,
    ScanSummary,
    ScanType,
    Severity,
    TriageStatus,
)
from .scoring import calculate_risk_score

_db_path: str = settings.database_path


def set_db_path(path: str) -> None:
    global _db_path
    _db_path = path


async def _get_db() -> aiosqlite.Connection:
    db = await aiosqlite.connect(_db_path)
    db.row_factory = aiosqlite.Row
    return db


async def init_db() -> None:
    db = await _get_db()
    try:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout=5000")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target_path TEXT NOT NULL,
                scan_types TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                findings_count INTEGER DEFAULT 0,
                risk_score REAL,
                summary TEXT,
                error TEXT
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                scanner TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                file_path TEXT,
                line_start INTEGER,
                line_end INTEGER,
                rule_id TEXT,
                cwe TEXT,
                remediation TEXT,
                metadata TEXT DEFAULT '{}',
                fingerprint TEXT DEFAULT '',
                FOREIGN KEY (scan_id) REFERENCES scans(id)
            )
        """)
        # Migration: add compliance_tags column if not present
        try:
            await db.execute("ALTER TABLE findings ADD COLUMN compliance_tags TEXT DEFAULT '[]'")
        except Exception:
            pass  # Column already exists

        # Migration: add fingerprint column to existing DBs (forward-only).
        # Empty default lets old rows coexist; the diff classifier (SS4) will
        # recompute the fingerprint on read when it is empty.
        try:
            await db.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT DEFAULT ''")
        except Exception:
            pass  # Column already exists

        # Migration: add target_url and target_host columns to scans
        for col in ["target_url", "target_host"]:
            try:
                await db.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")
            except Exception:
                pass  # Column already exists

        # Migration: add scanners_run + scanners_skipped JSON columns to scans
        # (PG2). Idempotent ALTER TABLE matches the v0.3 fingerprint pattern --
        # forward-only, default '[]' so old rows decode as empty lists.
        for col in ["scanners_run", "scanners_skipped"]:
            try:
                await db.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT DEFAULT '[]'")
            except Exception:
                pass  # Column already exists

        # Triage state + comments (BE-TRIAGE). Fingerprint is the cross-scan
        # primary key -- see fingerprint.py. Orphan rows (rule renamed / file
        # moved) are intentionally allowed; the UI just won't surface them.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS finding_states (
                fingerprint TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                note TEXT,
                updated_at TEXT NOT NULL,
                updated_by TEXT
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_finding_states_status ON finding_states(status)"
        )
        await db.execute("""
            CREATE TABLE IF NOT EXISTS finding_comments (
                id TEXT PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                text TEXT NOT NULL,
                author TEXT,
                created_at TEXT NOT NULL
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_finding_comments_fingerprint ON finding_comments(fingerprint)"
        )
        # Performance: existing get_findings does WHERE scan_id = ? but
        # findings has no scan_id index. Idempotent so it's safe to add now.
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)"
        )

        # SBOM tables
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

        await db.commit()
    finally:
        await db.close()


async def save_scan(scan: Scan) -> None:
    db = await _get_db()
    try:
        await db.execute(
            """INSERT OR REPLACE INTO scans
               (id, target_path, scan_types, status, started_at, completed_at,
                findings_count, risk_score, summary, error, target_url, target_host,
                scanners_run, scanners_skipped)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                scan.id,
                scan.target_path,
                json.dumps([t.value for t in scan.scan_types]),
                scan.status.value,
                scan.started_at.isoformat() if scan.started_at else None,
                scan.completed_at.isoformat() if scan.completed_at else None,
                scan.findings_count,
                scan.risk_score,
                scan.summary,
                scan.error,
                scan.target_url,
                scan.target_host,
                json.dumps(list(scan.scanners_run)),
                json.dumps([s.model_dump() for s in scan.scanners_skipped]),
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def save_findings(findings: list[Finding]) -> None:
    if not findings:
        return
    db = await _get_db()
    try:
        await db.executemany(
            """INSERT OR REPLACE INTO findings
               (id, scan_id, scanner, scan_type, severity, title, description,
                file_path, line_start, line_end, rule_id, cwe, remediation, metadata, compliance_tags, fingerprint)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    f.id,
                    f.scan_id,
                    f.scanner,
                    f.scan_type.value,
                    f.severity.value,
                    f.title,
                    f.description,
                    f.file_path,
                    f.line_start,
                    f.line_end,
                    f.rule_id,
                    f.cwe,
                    f.remediation,
                    json.dumps(f.metadata),
                    json.dumps(f.compliance_tags),
                    f.fingerprint,
                )
                for f in findings
            ],
        )
        await db.commit()
    finally:
        await db.close()


def _row_to_scan(row: aiosqlite.Row) -> Scan:
    keys = row.keys()
    scanners_run: list[str] = []
    scanners_skipped: list[ScannerSkip] = []
    if "scanners_run" in keys and row["scanners_run"]:
        scanners_run = json.loads(row["scanners_run"])
    if "scanners_skipped" in keys and row["scanners_skipped"]:
        scanners_skipped = [
            ScannerSkip(**entry) for entry in json.loads(row["scanners_skipped"])
        ]
    return Scan(
        id=row["id"],
        target_path=row["target_path"],
        scan_types=[ScanType(t) for t in json.loads(row["scan_types"])],
        status=ScanStatus(row["status"]),
        started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
        completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
        findings_count=row["findings_count"],
        risk_score=row["risk_score"],
        summary=row["summary"],
        error=row["error"],
        target_url=row["target_url"] if "target_url" in keys else None,
        target_host=row["target_host"] if "target_host" in keys else None,
        scanners_run=scanners_run,
        scanners_skipped=scanners_skipped,
    )


def _row_to_finding(row: aiosqlite.Row) -> Finding:
    keys = row.keys()
    return Finding(
        id=row["id"],
        scan_id=row["scan_id"],
        scanner=row["scanner"],
        scan_type=ScanType(row["scan_type"]),
        severity=Severity(row["severity"]),
        title=row["title"],
        description=row["description"],
        file_path=row["file_path"],
        line_start=row["line_start"],
        line_end=row["line_end"],
        rule_id=row["rule_id"],
        cwe=row["cwe"],
        remediation=row["remediation"],
        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        compliance_tags=json.loads(row["compliance_tags"]) if row["compliance_tags"] else [],
        fingerprint=(row["fingerprint"] if "fingerprint" in keys and row["fingerprint"] else ""),
    )


async def get_scan(scan_id: str) -> Optional[Scan]:
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_scan(row)
    finally:
        await db.close()


async def get_scans() -> list[Scan]:
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans ORDER BY started_at DESC")
        rows = await cursor.fetchall()
        return [_row_to_scan(row) for row in rows]
    finally:
        await db.close()


async def delete_scan_cascade(scan_id: str) -> bool:
    """Delete a scan and all rows that reference it.

    Removes the row in `scans` plus every `findings` row carrying the
    matching `scan_id`. Both deletes share a single transaction so a
    failure mid-way leaves the DB untouched (no orphan findings).
    Returns True when the scan row existed and was removed, False when
    the id did not match any scan (treated as a no-op by the API layer
    so a second DELETE on the same id can return 404).
    """
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT 1 FROM scans WHERE id = ?", (scan_id,))
        existed = await cursor.fetchone() is not None
        if not existed:
            return False
        await db.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        await db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def get_findings(
    scan_id: str,
    severity: Optional[str] = None,
    scan_type: Optional[str] = None,
    compliance: Optional[str] = None,
) -> list[Finding]:
    db = await _get_db()
    try:
        query = "SELECT * FROM findings WHERE scan_id = ?"
        params: list = [scan_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if scan_type:
            query += " AND scan_type = ?"
            params.append(scan_type)
        if compliance:
            query += " AND compliance_tags LIKE ?"
            params.append(f'%"{compliance}"%')
        query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"
        cursor = await db.execute(query, params)
        rows = await cursor.fetchall()
        return [_row_to_finding(row) for row in rows]
    finally:
        await db.close()


async def get_scan_summary(scan_id: str) -> Optional[ScanSummary]:
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = await cursor.fetchone()
        if scan_row is None:
            return None

        cursor = await db.execute(
            "SELECT * FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        rows = await cursor.fetchall()
        findings = [_row_to_finding(row) for row in rows]

        cursor = await db.execute(
            "SELECT DISTINCT scanner FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        scanners = [row["scanner"] for row in await cursor.fetchall()]

        severity_counts = {s: 0 for s in Severity}
        for f in findings:
            severity_counts[f.severity] += 1

        return ScanSummary(
            total_findings=len(findings),
            critical=severity_counts[Severity.CRITICAL],
            high=severity_counts[Severity.HIGH],
            medium=severity_counts[Severity.MEDIUM],
            low=severity_counts[Severity.LOW],
            info=severity_counts[Severity.INFO],
            risk_score=calculate_risk_score(findings),
            scanners_run=scanners,
        )
    finally:
        await db.close()


# --- Triage state + comments (BE-TRIAGE) ---------------------------------
#
# These rows are keyed on `fingerprint` (sha256 of scanner|rule|file|context|cwe,
# see fingerprint.py), NOT on finding.id. That makes a verdict survive
# rescans -- the same logical issue gets the same fingerprint each time the
# target is rescanned. Orphans (state rows whose fingerprint no longer
# matches any finding) are tolerated and never auto-pruned: a finding can
# disappear because the rule was renamed or the file moved, and we'd rather
# preserve the user's verdict for when it reappears than silently drop it.


def _row_to_finding_state(row: aiosqlite.Row) -> FindingState:
    return FindingState(
        fingerprint=row["fingerprint"],
        status=TriageStatus(row["status"]),
        note=row["note"],
        updated_at=datetime.fromisoformat(row["updated_at"]),
        updated_by=row["updated_by"],
    )


def _row_to_finding_comment(row: aiosqlite.Row) -> FindingComment:
    return FindingComment(
        id=row["id"],
        fingerprint=row["fingerprint"],
        text=row["text"],
        author=row["author"],
        created_at=datetime.fromisoformat(row["created_at"]),
    )


async def upsert_finding_state(state: FindingState) -> None:
    """Create or replace the triage state row for a fingerprint.

    INSERT OR REPLACE is the right semantic here: a user changing their
    verdict ("false_positive" -> "accepted_risk") replaces the prior row,
    no history is kept (use comments for an audit trail).
    """
    db = await _get_db()
    try:
        await db.execute(
            """INSERT OR REPLACE INTO finding_states
               (fingerprint, status, note, updated_at, updated_by)
               VALUES (?, ?, ?, ?, ?)""",
            (
                state.fingerprint,
                state.status.value,
                state.note,
                state.updated_at.isoformat(),
                state.updated_by,
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def get_finding_state(fingerprint: str) -> Optional[FindingState]:
    db = await _get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM finding_states WHERE fingerprint = ?", (fingerprint,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_finding_state(row)
    finally:
        await db.close()


async def get_finding_states_bulk(
    fingerprints: list[str],
) -> dict[str, FindingState]:
    """Bulk lookup keyed by fingerprint. Empty input -> empty dict.

    Used by `get_findings_with_state` to enrich a scan's findings with their
    triage verdicts in a single round-trip (instead of N+1 lookups).
    """
    if not fingerprints:
        return {}
    db = await _get_db()
    try:
        # Deduplicate so the IN-list stays small even when the same
        # fingerprint appears on multiple findings (shouldn't happen within
        # one scan, but cheap defensive code).
        unique = list({fp for fp in fingerprints if fp})
        if not unique:
            return {}
        placeholders = ",".join("?" * len(unique))
        cursor = await db.execute(
            f"SELECT * FROM finding_states WHERE fingerprint IN ({placeholders})",
            unique,
        )
        rows = await cursor.fetchall()
        return {row["fingerprint"]: _row_to_finding_state(row) for row in rows}
    finally:
        await db.close()


async def add_finding_comment(comment: FindingComment) -> None:
    db = await _get_db()
    try:
        await db.execute(
            """INSERT INTO finding_comments
               (id, fingerprint, text, author, created_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                comment.id,
                comment.fingerprint,
                comment.text,
                comment.author,
                comment.created_at.isoformat(),
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def list_finding_comments(fingerprint: str) -> list[FindingComment]:
    """Return comments for a fingerprint, oldest first.

    Ordering is `created_at` ASC so the UI can render a top-to-bottom
    triage thread without reversing client-side. id is the tiebreaker for
    same-instant comments (uuid4, so stable but unordered -- good enough
    for a deterministic test, no semantic meaning).
    """
    db = await _get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM finding_comments WHERE fingerprint = ? "
            "ORDER BY created_at ASC, id ASC",
            (fingerprint,),
        )
        rows = await cursor.fetchall()
        return [_row_to_finding_comment(row) for row in rows]
    finally:
        await db.close()


async def delete_finding_comment(comment_id: str) -> bool:
    """Delete a single comment by id.

    Returns True when a row was removed, False when the id did not exist
    (the API layer turns False into a 404 so a second DELETE on the same
    id is observable).
    """
    db = await _get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM finding_comments WHERE id = ?", (comment_id,)
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_findings_with_state(
    scan_id: str,
    severity: Optional[str] = None,
    scan_type: Optional[str] = None,
    compliance: Optional[str] = None,
) -> list[FindingWithState]:
    """Return a scan's findings enriched with their triage state.

    Same filter signature as `get_findings`. We deliberately call
    `get_findings` and then bulk-load states rather than JOINing in SQL --
    `get_findings` is the single source of truth for the row->Finding
    mapping (severity/compliance ordering, JSON column decoding) and we
    don't want a second copy drifting out of sync.
    """
    findings = await get_findings(
        scan_id, severity=severity, scan_type=scan_type, compliance=compliance
    )
    if not findings:
        return []
    states = await get_finding_states_bulk(
        [f.fingerprint for f in findings if f.fingerprint]
    )
    enriched: list[FindingWithState] = []
    for f in findings:
        state = states.get(f.fingerprint) if f.fingerprint else None
        enriched.append(
            FindingWithState(**f.model_dump(), state=state)
        )
    return enriched


# --- SBOM persistence ---

async def save_sbom(doc: SBOMDocument) -> None:
    db = await _get_db()
    try:
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
    finally:
        await db.close()


async def get_sbom(sbom_id: str) -> Optional[SBOMDocument]:
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM sbom_documents WHERE id = ?", (sbom_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        doc_row = dict(row)
        cursor = await db.execute("SELECT * FROM sbom_components WHERE sbom_id = ?", (sbom_id,))
        comp_rows = await cursor.fetchall()
        components = [SBOMComponent(**dict(c)) for c in comp_rows]
        return SBOMDocument(
            id=doc_row["id"],
            scan_id=doc_row["scan_id"],
            target_path=doc_row["target_path"],
            format=doc_row["format"],
            components=components,
            created_at=datetime.fromisoformat(doc_row["created_at"]),
        )
    finally:
        await db.close()


async def get_all_sboms() -> list[dict]:
    """Return all SBOM documents with component counts (no full component data)."""
    db = await _get_db()
    try:
        cursor = await db.execute(
            """SELECT d.id, d.scan_id, d.target_path, d.format, d.created_at,
                      (SELECT COUNT(*) FROM sbom_components c WHERE c.sbom_id = d.id) AS component_count
               FROM sbom_documents d ORDER BY d.created_at DESC"""
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_sboms_for_scan(scan_id: str) -> list[SBOMDocument]:
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM sbom_documents WHERE scan_id = ?", (scan_id,))
        doc_rows = await cursor.fetchall()
        results = []
        for doc_row in doc_rows:
            doc_row = dict(doc_row)
            cursor = await db.execute("SELECT * FROM sbom_components WHERE sbom_id = ?", (doc_row["id"],))
            comp_rows = await cursor.fetchall()
            components = [SBOMComponent(**dict(c)) for c in comp_rows]
            results.append(SBOMDocument(
                id=doc_row["id"],
                scan_id=doc_row["scan_id"],
                target_path=doc_row["target_path"],
                format=doc_row["format"],
                components=components,
                created_at=datetime.fromisoformat(doc_row["created_at"]),
            ))
        return results
    finally:
        await db.close()
