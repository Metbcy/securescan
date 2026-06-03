"""Initial schema -- all tables and indexes as of the current release.

This migration is the full schema for fresh installs. Pre-existing databases
created before the migration system existed are detected via introspection and
have this version recorded without re-running the CREATE TABLE statements.
"""

import aiosqlite

VERSION = 1
DESCRIPTION = "Initial schema"


async def up(conn: aiosqlite.Connection) -> None:
    await conn.execute("""
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
            error TEXT,
            target_url TEXT,
            target_host TEXT,
            scanners_run TEXT DEFAULT '[]',
            scanners_skipped TEXT DEFAULT '[]'
        )
    """)
    await conn.execute("""
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
            compliance_tags TEXT DEFAULT '[]',
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_states (
            fingerprint TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            note TEXT,
            updated_at TEXT NOT NULL,
            updated_by TEXT
        )
    """)
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_finding_states_status ON finding_states(status)"
    )
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS finding_comments (
            id TEXT PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            text TEXT NOT NULL,
            author TEXT,
            created_at TEXT NOT NULL
        )
    """)
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_finding_comments_fingerprint ON finding_comments(fingerprint)"
    )
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS sbom_documents (
            id TEXT PRIMARY KEY,
            scan_id TEXT,
            target_path TEXT NOT NULL,
            format TEXT NOT NULL DEFAULT 'cyclonedx',
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)
    await conn.execute("""
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
    await conn.execute("""
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
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_revoked ON api_keys(revoked_at)")
    await conn.execute("""
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
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_notifications_unread "
        "ON notifications(read_at, created_at DESC)"
    )
    await conn.execute("""
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
    await conn.execute("""
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
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_pending "
        "ON webhook_deliveries(status, next_attempt_at)"
    )
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_webhook "
        "ON webhook_deliveries(webhook_id, created_at DESC)"
    )


async def down(conn: aiosqlite.Connection) -> None:
    for table in (
        "webhook_deliveries",
        "webhooks",
        "notifications",
        "api_keys",
        "sbom_components",
        "sbom_documents",
        "finding_comments",
        "finding_states",
        "findings",
        "scans",
    ):
        await conn.execute(f"DROP TABLE IF EXISTS {table}")  # noqa: S608
