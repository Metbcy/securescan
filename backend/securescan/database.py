import json
import re
from datetime import datetime

import aiosqlite

from .config import settings
from .models import (
    Finding,
    FindingComment,
    FindingState,
    FindingWithState,
    Notification,
    NotificationSeverity,
    SBOMComponent,
    SBOMDocument,
    Scan,
    ScannerSkip,
    ScanStatus,
    ScanSummary,
    ScanType,
    Severity,
    TriageStatus,
    Webhook,
    WebhookDelivery,
    WebhookEventType,
)
from .scoring import calculate_risk_score

_db_path: str = settings.database_path


# SQLite (and Postgres) identifiers can technically be quoted to allow
# arbitrary characters, but quoting `{col}` inside an f-string still
# wouldn't make user-supplied input safe — quoting can be escaped.
# The only correct fix for dynamic DDL is an identifier ALLOWLIST.
_SQL_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def _safe_ident(name: str) -> str:
    """Validate ``name`` as a safe SQL identifier and return it unchanged.

    Raises ValueError on anything that doesn't match the allowlist.
    Used to gate any DDL f-string in this module so a future refactor
    that reroutes the column source from a literal list to e.g. a
    request body can't introduce SQL injection.
    """
    if not isinstance(name, str) or not _SQL_IDENT_RE.fullmatch(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return name


# Multiple known phrasings of "duplicate column" across SQLite versions.
# As of SQLite 3.x, the message is "duplicate column name: <col>".
# Pin a tuple of known prefixes; if a future SQLite uses a new phrasing,
# the test suite will catch the regression.
_DUPLICATE_COLUMN_PHRASES = (
    "duplicate column name",
    "duplicate column",
)


def _is_duplicate_column(exc: BaseException) -> bool:
    """Return True iff ``exc`` represents 'column already exists'.

    Checks both the message text (current sqlite phrasings) and the
    SQLite extended error code if it's exposed on the exception. Any
    other OperationalError (e.g., a column-type typo, missing table)
    is NOT a duplicate-column situation and must be re-raised by the
    caller so we don't silently swallow real schema corruption.
    """
    msg = str(exc).lower()
    if any(phrase in msg for phrase in _DUPLICATE_COLUMN_PHRASES):
        return True
    # aiosqlite/sqlite3 may expose `sqlite_errorcode` on Python 3.11+.
    # SQLITE_ERROR (1) covers most syntax/constraint failures; we want
    # to be more specific. SQLite uses a generic SQLITE_ERROR for
    # duplicate column rather than a dedicated code, so we rely on
    # the message check above. This branch is just a hook for future
    # versions that might expose a more specific code.
    return False


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
        except aiosqlite.OperationalError as e:
            if not _is_duplicate_column(e):
                raise

        # Migration: add fingerprint column to existing DBs (forward-only).
        # Empty default lets old rows coexist; the diff classifier (SS4) will
        # recompute the fingerprint on read when it is empty.
        try:
            await db.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT DEFAULT ''")
        except aiosqlite.OperationalError as e:
            if not _is_duplicate_column(e):
                raise

        # Migration: add target_url and target_host columns to scans
        for col in ["target_url", "target_host"]:
            safe = _safe_ident(col)
            try:
                await db.execute(f"ALTER TABLE scans ADD COLUMN {safe} TEXT")
            except aiosqlite.OperationalError as e:
                if not _is_duplicate_column(e):
                    raise

        # Migration: add scanners_run + scanners_skipped JSON columns to scans
        # (PG2). Idempotent ALTER TABLE matches the v0.3 fingerprint pattern --
        # forward-only, default '[]' so old rows decode as empty lists.
        for col in ["scanners_run", "scanners_skipped"]:
            safe = _safe_ident(col)
            try:
                await db.execute(f"ALTER TABLE scans ADD COLUMN {safe} TEXT DEFAULT '[]'")
            except aiosqlite.OperationalError as e:
                if not _is_duplicate_column(e):
                    raise

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
        await db.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")

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

        # Hashed API keys with scopes (BE-AUTH-KEYS).
        # `key_hash` is "<salt-hex>$<sha256-hex>"; `prefix` is the
        # display-safe first 16 chars of the full key. `scopes` is a JSON
        # array of strings (e.g. '["read","admin"]'). `revoked_at` NULL
        # means active; the index makes the auth-path "any active key?"
        # check O(log n).
        await db.execute("""
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                prefix TEXT NOT NULL,
                scopes TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_revoked ON api_keys(revoked_at)")

        # In-app notifications (BE-NOTIFY).
        # Single-tenant: no user_id column -- every browser session sees
        # the same bell. The composite (read_at, created_at DESC) index
        # is tuned for the two hot queries: "give me unread, newest
        # first" (the dropdown) and "how many unread?" (the polled
        # badge count). NULL read_at sorts ahead of timestamps in
        # SQLite by default, which is exactly what we want.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                title TEXT NOT NULL,
                body TEXT,
                link TEXT,
                severity TEXT NOT NULL DEFAULT 'info',
                created_at TEXT NOT NULL,
                read_at TEXT
            )
        """)
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_notifications_unread "
            "ON notifications(read_at, created_at DESC)"
        )

        # Outbound webhooks (BE-WEBHOOKS).
        # `secret` is generated server-side at create time and exposed
        # exactly once on the create response; only the hash-equivalent
        # plaintext is kept here because we need it to sign each
        # outbound delivery (HMAC-SHA256). `event_filter` is a JSON
        # array of WebhookEventType values; an empty filter means the
        # subscription matches NO events (deny-by-default).
        await db.execute("""
            CREATE TABLE IF NOT EXISTS webhooks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                secret TEXT NOT NULL,
                event_filter TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            )
        """)

        # Durable delivery queue. Every outbound HTTP attempt is
        # represented by a row that transitions
        # pending -> delivering -> succeeded | failed (with retries
        # bouncing back to pending). On startup any stale `delivering`
        # row (process killed mid-flight) is reset to `pending` by
        # ``reset_stale_delivering_deliveries`` so retry resumes.
        await db.execute("""
            CREATE TABLE IF NOT EXISTS webhook_deliveries (
                id TEXT PRIMARY KEY,
                webhook_id TEXT NOT NULL,
                event TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 0,
                next_attempt_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                response_code INTEGER,
                response_body TEXT,
                FOREIGN KEY (webhook_id) REFERENCES webhooks(id)
            )
        """)
        # Hot path: dispatcher poll = "pending rows whose next_attempt_at
        # has passed". Composite index lines that filter+sort up.
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending "
            "ON webhook_deliveries(status, next_attempt_at)"
        )
        # Per-webhook delivery history (admin UI lists last 100).
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook "
            "ON webhook_deliveries(webhook_id, created_at DESC)"
        )

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
        scanners_skipped = [ScannerSkip(**entry) for entry in json.loads(row["scanners_skipped"])]
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


async def get_scan(scan_id: str) -> Scan | None:
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
    severity: str | None = None,
    scan_type: str | None = None,
    compliance: str | None = None,
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


async def get_scan_summary(scan_id: str) -> ScanSummary | None:
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


async def get_finding_state(fingerprint: str) -> FindingState | None:
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
            "SELECT * FROM finding_comments WHERE fingerprint = ? ORDER BY created_at ASC, id ASC",
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
        cursor = await db.execute("DELETE FROM finding_comments WHERE id = ?", (comment_id,))
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def get_findings_with_state(
    scan_id: str,
    severity: str | None = None,
    scan_type: str | None = None,
    compliance: str | None = None,
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
    states = await get_finding_states_bulk([f.fingerprint for f in findings if f.fingerprint])
    enriched: list[FindingWithState] = []
    for f in findings:
        state = states.get(f.fingerprint) if f.fingerprint else None
        enriched.append(FindingWithState(**f.model_dump(), state=state))
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
                (
                    comp.id,
                    comp.sbom_id,
                    comp.name,
                    comp.version,
                    comp.type,
                    comp.purl,
                    comp.license,
                    comp.supplier,
                ),
            )
        await db.commit()
    finally:
        await db.close()


async def get_sbom(sbom_id: str) -> SBOMDocument | None:
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
            cursor = await db.execute(
                "SELECT * FROM sbom_components WHERE sbom_id = ?", (doc_row["id"],)
            )
            comp_rows = await cursor.fetchall()
            components = [SBOMComponent(**dict(c)) for c in comp_rows]
            results.append(
                SBOMDocument(
                    id=doc_row["id"],
                    scan_id=doc_row["scan_id"],
                    target_path=doc_row["target_path"],
                    format=doc_row["format"],
                    components=components,
                    created_at=datetime.fromisoformat(doc_row["created_at"]),
                )
            )
        return results
    finally:
        await db.close()


# --- Hashed API keys (BE-AUTH-KEYS) --------------------------------------
#
# Keyed on a 10-char base64url id; the full plaintext key is never stored
# (only the salted SHA-256 hash via `api_keys._hash_key`). All callers
# must funnel through these functions so the `scopes` JSON encoding and
# `revoked_at` semantics stay in one place.
#
# `OperationalError` fallbacks on the read paths let dev-mode tests (and
# the auth path on a freshly-cloned repo) survive the brief window
# between process start and `init_db()` when the table doesn't exist
# yet -- treating the DB as "no keys" is the right default there.


async def insert_api_key(
    id: str,
    name: str,
    key_hash: str,
    prefix: str,
    scopes: list[str],
    created_at: datetime,
) -> None:
    """Insert a new api_keys row. Raises ``aiosqlite.IntegrityError`` on
    primary-key collision so the caller can retry with a fresh id."""
    db = await _get_db()
    try:
        await db.execute(
            """INSERT INTO api_keys
               (id, name, key_hash, prefix, scopes, created_at,
                last_used_at, revoked_at)
               VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)""",
            (id, name, key_hash, prefix, json.dumps(scopes), created_at.isoformat()),
        )
        await db.commit()
    finally:
        await db.close()


async def get_api_key_by_id(id: str) -> dict | None:
    """Return the row dict for ``id`` or None when not found."""
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM api_keys WHERE id = ?", (id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)
    except aiosqlite.OperationalError:
        return None
    finally:
        await db.close()


async def list_api_keys(include_revoked: bool = True) -> list[dict]:
    """Return all api_keys rows ordered newest-first.

    `include_revoked=False` is provided for admin UIs that want to hide
    historical entries. The default (True) preserves the audit trail
    so a UI can show "revoked on ..." badges.
    """
    db = await _get_db()
    try:
        if include_revoked:
            cursor = await db.execute("SELECT * FROM api_keys ORDER BY created_at DESC")
        else:
            cursor = await db.execute(
                "SELECT * FROM api_keys WHERE revoked_at IS NULL ORDER BY created_at DESC"
            )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    except aiosqlite.OperationalError:
        return []
    finally:
        await db.close()


async def revoke_api_key(id: str) -> bool:
    """Set `revoked_at` on the row. Returns True iff a row was modified
    (so a second call on the same id returns False - the API layer
    treats that as idempotent and replies 204)."""
    db = await _get_db()
    try:
        cursor = await db.execute(
            "UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            (datetime.utcnow().isoformat(), id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def touch_api_key_last_used(id: str, when: datetime) -> None:
    """Update `last_used_at` on a successful auth.

    Called from the auth hot path on every authenticated request, so
    keep it cheap: a single indexed UPDATE on the primary key.
    """
    db = await _get_db()
    try:
        await db.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (when.isoformat(), id),
        )
        await db.commit()
    except aiosqlite.OperationalError:
        # Table missing - treat as no-op so a misconfigured environment
        # doesn't surface as a 500 to the caller.
        return
    finally:
        await db.close()


async def count_admin_keys_active() -> int:
    """Count unrevoked rows whose scopes JSON contains "admin".

    LIKE '%"admin"%' is safe here because scope tokens are validated
    against `ApiKeyScope` before persistence, so the literal string
    `"admin"` (with quotes) cannot occur as a substring of any other
    scope. Used for both startup safety and lockout protection on
    DELETE.
    """
    db = await _get_db()
    try:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM api_keys WHERE revoked_at IS NULL AND scopes LIKE '%\"admin\"%'"
        )
        row = await cursor.fetchone()
        return int(row[0]) if row else 0
    except aiosqlite.OperationalError:
        return 0
    finally:
        await db.close()


async def has_unrevoked_api_key() -> bool:
    """Return True if at least one non-revoked api_keys row exists.

    Called on every authenticated request to decide whether DB-keyed
    auth is in play. Indexed via `idx_api_keys_revoked` so even a busy
    deployment with thousands of historical keys answers in O(log n).
    """
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT 1 FROM api_keys WHERE revoked_at IS NULL LIMIT 1")
        row = await cursor.fetchone()
        return row is not None
    except aiosqlite.OperationalError:
        return False
    finally:
        await db.close()


# --- In-app notifications (BE-NOTIFY) ------------------------------------
#
# Single-tenant for v0.9.0: notifications are global, not per-user. The
# bell icon in the topbar shows the same unread count to every browser
# session. Multi-user scoping is a future feature; the table layout is
# already shaped so adding `user_id` later is an additive migration.
#
# `created_at` and `read_at` are stored as ISO-8601 strings so they
# compare lexicographically on the indexed (read_at, created_at DESC)
# pair -- matching the two hot queries the API surfaces:
#   * "newest unread first" (dropdown render)
#   * "count(*) where read_at IS NULL" (polled badge)


def _row_to_notification(row: aiosqlite.Row) -> Notification:
    return Notification(
        id=row["id"],
        type=row["type"],
        title=row["title"],
        body=row["body"],
        link=row["link"],
        severity=NotificationSeverity(row["severity"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        read_at=datetime.fromisoformat(row["read_at"]) if row["read_at"] else None,
    )


async def insert_notification(
    *,
    type: str,
    title: str,
    body: str | None = None,
    link: str | None = None,
    severity: NotificationSeverity = NotificationSeverity.INFO,
) -> Notification:
    """Persist a new notification and return the populated row.

    `id` and `created_at` are server-assigned (UUIDv4 + UTC now) so
    callers can't backdate or collide. `read_at` starts NULL.
    """
    notif = Notification(
        type=type,
        title=title,
        body=body,
        link=link,
        severity=severity,
    )
    db = await _get_db()
    try:
        await db.execute(
            """INSERT INTO notifications
               (id, type, title, body, link, severity, created_at, read_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, NULL)""",
            (
                notif.id,
                notif.type,
                notif.title,
                notif.body,
                notif.link,
                notif.severity.value,
                notif.created_at.isoformat(),
            ),
        )
        await db.commit()
    finally:
        await db.close()
    return notif


async def list_notifications(unread_only: bool = False, limit: int = 50) -> list[Notification]:
    """Return notifications, newest first.

    `limit` is hard-capped at 200 in the API layer; this function
    trusts its caller (the cap exists to bound payload size for the
    polled dropdown, not for any safety reason at the DB level).
    """
    db = await _get_db()
    try:
        if unread_only:
            cursor = await db.execute(
                "SELECT * FROM notifications WHERE read_at IS NULL "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        else:
            cursor = await db.execute(
                "SELECT * FROM notifications ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
        rows = await cursor.fetchall()
        return [_row_to_notification(row) for row in rows]
    finally:
        await db.close()


async def get_notification(notification_id: str) -> Notification | None:
    """Look up a single notification by id, or None when missing."""
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM notifications WHERE id = ?", (notification_id,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return _row_to_notification(row)
    finally:
        await db.close()


async def mark_notification_read(notification_id: str) -> bool:
    """Mark one notification read. Returns True iff a row changed.

    `WHERE read_at IS NULL` makes a second call a no-op (rowcount=0)
    so callers can distinguish "marked it just now" from "was already
    read". The API layer uses that distinction to keep the PATCH
    idempotent (200 either way) while still surfacing 404 for an
    unknown id (checked separately).
    """
    db = await _get_db()
    try:
        cursor = await db.execute(
            "UPDATE notifications SET read_at = ? WHERE id = ? AND read_at IS NULL",
            (datetime.utcnow().isoformat(), notification_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def mark_all_notifications_read() -> int:
    """Mark every unread notification read. Returns the count modified.

    A single UPDATE instead of N individual updates so the bell's
    "mark all read" button is one round trip regardless of backlog
    size.
    """
    db = await _get_db()
    try:
        cursor = await db.execute(
            "UPDATE notifications SET read_at = ? WHERE read_at IS NULL",
            (datetime.utcnow().isoformat(),),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


async def count_unread_notifications() -> int:
    """Return the number of unread notifications.

    Polled by the dashboard topbar every 30s -- the
    `idx_notifications_unread` index lets SQLite answer this from the
    index alone (read_at IS NULL is a prefix match).
    """
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT COUNT(*) FROM notifications WHERE read_at IS NULL")
        row = await cursor.fetchone()
        return int(row[0]) if row else 0
    finally:
        await db.close()


async def prune_old_notifications(older_than_days: int = 30) -> int:
    """Delete read notifications older than the threshold.

    Never touches unread rows, even if they are years old -- if the
    user hasn't acknowledged a notification we'd rather keep showing
    it than silently swallow it. Called once at startup (no recurring
    schedule for v0.9.0); a busy deployment can re-run it manually
    by hitting `/ready` (which calls `init_db`) and triggering the
    startup hook on the next reload.

    ISO-8601 strings compare lexicographically, so we subtract days
    in Python and pass the cutoff string directly to SQLite -- avoids
    a per-version reliance on sqlite's date() function.
    """
    from datetime import timedelta

    cutoff = (datetime.utcnow() - timedelta(days=older_than_days)).isoformat()
    db = await _get_db()
    try:
        cursor = await db.execute(
            "DELETE FROM notifications WHERE read_at IS NOT NULL AND read_at < ?",
            (cutoff,),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()


# --- Outbound webhooks (BE-WEBHOOKS) -------------------------------------
#
# Two tables, one queue:
#
# * `webhooks`             - subscriptions. One row per (URL, event_filter)
#                            tuple the operator wants to fan out to.
# * `webhook_deliveries`   - the durable retry queue. Every event that
#                            matches a subscription writes ONE row here
#                            with status='pending'; the dispatcher worker
#                            polls these and transitions them to
#                            delivering -> succeeded | failed (or back
#                            to pending with an updated next_attempt_at
#                            on retry).
#
# Why a row before the HTTP call?
#   Crash safety. If the process is terminated between "scan completed" and
#   "POST /receiver" the row is already on disk in WAL mode; on next
#   startup ``reset_stale_delivering_deliveries`` flips any 'delivering'
#   rows back to 'pending' and the worker resumes. A bare
#   ``asyncio.create_task`` would lose the delivery on restart.


def _row_to_webhook(row: aiosqlite.Row) -> Webhook:
    return Webhook(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        event_filter=[WebhookEventType(e) for e in json.loads(row["event_filter"])],
        enabled=bool(row["enabled"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


def _row_to_delivery(row: aiosqlite.Row) -> WebhookDelivery:
    return WebhookDelivery(
        id=row["id"],
        webhook_id=row["webhook_id"],
        event=row["event"],
        status=row["status"],
        attempt=row["attempt"],
        next_attempt_at=datetime.fromisoformat(row["next_attempt_at"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
        response_code=row["response_code"],
        response_body=row["response_body"],
    )


async def insert_webhook(
    *,
    id: str,
    name: str,
    url: str,
    secret: str,
    event_filter: list[str],
    enabled: bool,
    created_at: datetime,
) -> None:
    db = await _get_db()
    try:
        await db.execute(
            """INSERT INTO webhooks
               (id, name, url, secret, event_filter, enabled, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                id,
                name,
                url,
                secret,
                json.dumps(event_filter),
                1 if enabled else 0,
                created_at.isoformat(),
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def get_webhook_row(webhook_id: str) -> dict | None:
    """Return the raw row dict (including ``secret``) or None.

    Public callers should prefer :func:`get_webhook` which strips the
    secret. The dispatcher needs the secret to sign requests, so it
    reads via this function.
    """
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM webhooks WHERE id = ?", (webhook_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def get_webhook(webhook_id: str) -> Webhook | None:
    row = await get_webhook_row(webhook_id)
    if row is None:
        return None
    return Webhook(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        event_filter=[WebhookEventType(e) for e in json.loads(row["event_filter"])],
        enabled=bool(row["enabled"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


async def list_webhooks(*, only_enabled: bool = False) -> list[Webhook]:
    db = await _get_db()
    try:
        if only_enabled:
            cursor = await db.execute(
                "SELECT * FROM webhooks WHERE enabled = 1 ORDER BY created_at DESC"
            )
        else:
            cursor = await db.execute("SELECT * FROM webhooks ORDER BY created_at DESC")
        rows = await cursor.fetchall()
        return [_row_to_webhook(r) for r in rows]
    finally:
        await db.close()


async def update_webhook(
    webhook_id: str,
    *,
    name: str | None = None,
    url: str | None = None,
    event_filter: list[str] | None = None,
    enabled: bool | None = None,
) -> Webhook | None:
    """Patch a webhook row. Secret is intentionally NOT exposed here.

    Returns the post-update :class:`Webhook` or None if the id was not
    found. No-op when every field is None (still re-fetches so the
    caller sees the current state).
    """
    sets: list[str] = []
    params: list = []
    if name is not None:
        sets.append("name = ?")
        params.append(name)
    if url is not None:
        sets.append("url = ?")
        params.append(url)
    if event_filter is not None:
        sets.append("event_filter = ?")
        params.append(json.dumps(event_filter))
    if enabled is not None:
        sets.append("enabled = ?")
        params.append(1 if enabled else 0)
    if not sets:
        return await get_webhook(webhook_id)
    params.append(webhook_id)
    db = await _get_db()
    try:
        cursor = await db.execute(f"UPDATE webhooks SET {', '.join(sets)} WHERE id = ?", params)
        await db.commit()
        if cursor.rowcount == 0:
            return None
    finally:
        await db.close()
    return await get_webhook(webhook_id)


async def delete_webhook(webhook_id: str) -> bool:
    """Delete a webhook AND cascade-drop its delivery history.

    SQLite does not enforce foreign keys by default in our connection,
    so we issue both deletes ourselves inside one transaction.
    Returns True iff the webhook row existed and was removed.
    """
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT 1 FROM webhooks WHERE id = ?", (webhook_id,))
        existed = await cursor.fetchone() is not None
        if not existed:
            return False
        await db.execute(
            "DELETE FROM webhook_deliveries WHERE webhook_id = ?",
            (webhook_id,),
        )
        await db.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,))
        await db.commit()
        return True
    finally:
        await db.close()


async def insert_webhook_delivery(
    *,
    id: str,
    webhook_id: str,
    event: str,
    payload: str,
    next_attempt_at: datetime,
    created_at: datetime,
) -> None:
    """Persist a 'pending' delivery row -- the durability anchor.

    Always writes status='pending', attempt=0; the worker advances
    state from there via ``mark_delivery_delivering`` and
    ``update_delivery_status``.
    """
    db = await _get_db()
    try:
        await db.execute(
            """INSERT INTO webhook_deliveries
               (id, webhook_id, event, payload, status, attempt,
                next_attempt_at, created_at, updated_at,
                response_code, response_body)
               VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, ?, NULL, NULL)""",
            (
                id,
                webhook_id,
                event,
                payload,
                next_attempt_at.isoformat(),
                created_at.isoformat(),
                created_at.isoformat(),
            ),
        )
        await db.commit()
    finally:
        await db.close()


async def list_pending_deliveries(*, limit: int = 20) -> list[dict]:
    """Return up to ``limit`` rows ready to dispatch (oldest first).

    "Ready" = status='pending' AND next_attempt_at <= now. Ordered by
    created_at then next_attempt_at so retries of an old delivery jump
    ahead of brand-new deliveries (FIFO over the original event time).
    The dispatcher applies a per-webhook FIFO guard on top of this.
    """
    now_iso = datetime.utcnow().isoformat()
    db = await _get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM webhook_deliveries "
            "WHERE status = 'pending' AND next_attempt_at <= ? "
            "ORDER BY created_at ASC, next_attempt_at ASC "
            "LIMIT ?",
            (now_iso, limit),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        await db.close()


async def get_webhook_delivery(delivery_id: str) -> dict | None:
    db = await _get_db()
    try:
        cursor = await db.execute("SELECT * FROM webhook_deliveries WHERE id = ?", (delivery_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None
    finally:
        await db.close()


async def list_deliveries_for_webhook(
    webhook_id: str, *, limit: int = 100
) -> list[WebhookDelivery]:
    """Last ``limit`` deliveries for a webhook, newest-first."""
    db = await _get_db()
    try:
        cursor = await db.execute(
            "SELECT * FROM webhook_deliveries WHERE webhook_id = ? "
            "ORDER BY created_at DESC LIMIT ?",
            (webhook_id, limit),
        )
        rows = await cursor.fetchall()
        return [_row_to_delivery(r) for r in rows]
    finally:
        await db.close()


async def mark_delivery_delivering(delivery_id: str) -> bool:
    """Atomically claim a pending row (status='delivering').

    Returns True iff this call performed the transition (the row was
    still 'pending'). Used as a soft lock so two concurrent dispatcher
    coroutines will not double-deliver -- the second one sees rowcount=0
    and bails. Critical even with the in-process FIFO guard because a
    row could appear in the poll batch a second time if the first
    dispatch was scheduled but has not flipped status yet.
    """
    now_iso = datetime.utcnow().isoformat()
    db = await _get_db()
    try:
        cursor = await db.execute(
            "UPDATE webhook_deliveries "
            "SET status = 'delivering', updated_at = ? "
            "WHERE id = ? AND status = 'pending'",
            (now_iso, delivery_id),
        )
        await db.commit()
        return cursor.rowcount > 0
    finally:
        await db.close()


async def update_delivery_status(
    delivery_id: str,
    *,
    status: str,
    attempt: int | None = None,
    next_attempt_at: datetime | None = None,
    response_code: int | None = None,
    response_body: str | None = None,
) -> None:
    """Update a delivery row after a dispatch attempt.

    Always bumps `updated_at`. `attempt` and `next_attempt_at` are only
    written when not None (e.g. on terminal status they stay at their
    last value, which is what the audit log wants).
    """
    sets = ["status = ?", "updated_at = ?"]
    params: list = [status, datetime.utcnow().isoformat()]
    if attempt is not None:
        sets.append("attempt = ?")
        params.append(attempt)
    if next_attempt_at is not None:
        sets.append("next_attempt_at = ?")
        params.append(next_attempt_at.isoformat())
    if response_code is not None:
        sets.append("response_code = ?")
        params.append(response_code)
    if response_body is not None:
        sets.append("response_body = ?")
        # Spec caps the stored body at 2000 chars; enforce here so a
        # forgetful caller cannot bloat the table with a 50MB error page.
        params.append(response_body[:2000])
    params.append(delivery_id)
    db = await _get_db()
    try:
        await db.execute(
            f"UPDATE webhook_deliveries SET {', '.join(sets)} WHERE id = ?",
            params,
        )
        await db.commit()
    finally:
        await db.close()


async def reset_stale_delivering_deliveries() -> int:
    """Flip any 'delivering' rows back to 'pending' so retry resumes.

    Called once at startup. A row in 'delivering' with no live worker
    is the signature of a process restart mid-dispatch -- the receiver
    may or may not have processed the request, but at-least-once
    delivery means we re-send and let the receiver dedupe via
    timestamp + signature. Returns the count of rows reset (useful in
    tests).
    """
    now_iso = datetime.utcnow().isoformat()
    db = await _get_db()
    try:
        cursor = await db.execute(
            "UPDATE webhook_deliveries "
            "SET status = 'pending', next_attempt_at = ?, updated_at = ? "
            "WHERE status = 'delivering'",
            (now_iso, now_iso),
        )
        await db.commit()
        return cursor.rowcount
    finally:
        await db.close()
