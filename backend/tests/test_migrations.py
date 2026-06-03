"""Tests for the tracked migration system."""

from __future__ import annotations

import aiosqlite
import pytest

from securescan.migrations import run_migrations

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXPECTED_TABLES = {
    "scans",
    "findings",
    "finding_states",
    "finding_comments",
    "sbom_documents",
    "sbom_components",
    "api_keys",
    "notifications",
    "notification_settings",
    "webhooks",
    "webhook_deliveries",
    "schedules",
    "schedule_runs",
    "schema_version",
}

EXPECTED_SCANS_COLS = {
    "id",
    "target_path",
    "scan_types",
    "status",
    "started_at",
    "completed_at",
    "findings_count",
    "risk_score",
    "summary",
    "error",
    "target_url",
    "target_host",
    "scanners_run",
    "scanners_skipped",
}

EXPECTED_FINDINGS_COLS = {
    "id",
    "scan_id",
    "scanner",
    "scan_type",
    "severity",
    "title",
    "description",
    "file_path",
    "line_start",
    "line_end",
    "rule_id",
    "cwe",
    "remediation",
    "metadata",
    "fingerprint",
    "compliance_tags",
}


async def _get_tables(db: aiosqlite.Connection) -> set[str]:
    async with db.execute("SELECT name FROM sqlite_master WHERE type='table'") as cur:
        rows = await cur.fetchall()
    return {row[0] for row in rows}


async def _get_cols(db: aiosqlite.Connection, table: str) -> set[str]:
    async with db.execute(f"PRAGMA table_info({table})") as cur:  # noqa: S608
        rows = await cur.fetchall()
    return {row[1] for row in rows}


async def _get_max_version(db: aiosqlite.Connection) -> int:
    async with db.execute("SELECT MAX(version) FROM schema_version") as cur:
        row = await cur.fetchone()
    return row[0] if row and row[0] is not None else 0


def _all_migration_versions() -> list[int]:
    """Versions of every migration module shipped in the package, sorted asc.

    Computed from the modules themselves so adding a new migration
    (e.g. issue #6 added VERSION=7 with 6 reserved for an unrelated
    feature) does not require updating every assertion.
    """
    from securescan.migrations import _load_all_migrations

    return [m.VERSION for m in _load_all_migrations()]


async def _build_legacy_db(db: aiosqlite.Connection) -> None:
    """Simulate a pre-migration-system database (scans + findings only, no extra columns)."""
    await db.execute("""
        CREATE TABLE scans (
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
        CREATE TABLE findings (
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
            metadata TEXT DEFAULT '{}'
        )
    """)
    await db.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fresh_db_all_tables_present(tmp_path):
    """run_migrations on an empty DB creates all tables."""
    db_path = str(tmp_path / "fresh.db")
    async with aiosqlite.connect(db_path) as db:
        await run_migrations(db)
        tables = await _get_tables(db)

    assert EXPECTED_TABLES.issubset(tables)


@pytest.mark.asyncio
async def test_fresh_db_max_version(tmp_path):
    """After migrating a fresh DB the max recorded version equals the migration count."""
    db_path = str(tmp_path / "fresh.db")
    async with aiosqlite.connect(db_path) as db:
        await run_migrations(db)
        max_v = await _get_max_version(db)

    assert max_v == max(_all_migration_versions())


@pytest.mark.asyncio
async def test_fresh_db_full_column_set(tmp_path):
    """Fresh DB has all columns including those added by ALTER TABLE migrations."""
    db_path = str(tmp_path / "fresh.db")
    async with aiosqlite.connect(db_path) as db:
        await run_migrations(db)
        scans_cols = await _get_cols(db, "scans")
        findings_cols = await _get_cols(db, "findings")

    assert EXPECTED_SCANS_COLS.issubset(scans_cols)
    assert EXPECTED_FINDINGS_COLS.issubset(findings_cols)


@pytest.mark.asyncio
async def test_forward_migration_from_v1(tmp_path):
    """A DB with only initial schema (no extra columns) reaches full schema after run_migrations."""
    db_path = str(tmp_path / "v1.db")
    async with aiosqlite.connect(db_path) as db:
        # Create base tables only (no extra columns, no schema_version)
        await db.execute("""
            CREATE TABLE scans (
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
            CREATE TABLE findings (
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
                metadata TEXT DEFAULT '{}'
            )
        """)
        await db.commit()

        await run_migrations(db)
        tables = await _get_tables(db)
        scans_cols = await _get_cols(db, "scans")
        findings_cols = await _get_cols(db, "findings")
        max_v = await _get_max_version(db)

    assert EXPECTED_TABLES.issubset(tables)
    assert EXPECTED_SCANS_COLS.issubset(scans_cols)
    assert EXPECTED_FINDINGS_COLS.issubset(findings_cols)
    assert max_v == max(_all_migration_versions())


@pytest.mark.asyncio
async def test_idempotency(tmp_path):
    """Running run_migrations twice produces no errors and no duplicate work."""
    db_path = str(tmp_path / "idem.db")
    async with aiosqlite.connect(db_path) as db:
        await run_migrations(db)
        v_after_first = await _get_max_version(db)

        await run_migrations(db)
        v_after_second = await _get_max_version(db)

        async with db.execute("SELECT COUNT(*) FROM schema_version") as cur:
            row = await cur.fetchone()
        count = row[0]

    expected_max = max(_all_migration_versions())
    expected_count = len(_all_migration_versions())
    assert v_after_first == v_after_second == expected_max
    assert count == expected_count  # exactly one row per migration version


@pytest.mark.asyncio
async def test_preexisting_legacy_db(tmp_path):
    """A DB created by the old in-place ALTER TABLE approach is detected and upgraded."""
    db_path = str(tmp_path / "legacy.db")
    async with aiosqlite.connect(db_path) as db:
        await _build_legacy_db(db)

        await run_migrations(db)
        tables = await _get_tables(db)
        scans_cols = await _get_cols(db, "scans")
        findings_cols = await _get_cols(db, "findings")
        max_v = await _get_max_version(db)

    assert EXPECTED_TABLES.issubset(tables)
    assert EXPECTED_SCANS_COLS.issubset(scans_cols)
    assert EXPECTED_FINDINGS_COLS.issubset(findings_cols)
    assert max_v == max(_all_migration_versions())


@pytest.mark.asyncio
async def test_preexisting_db_no_schema_version_created(tmp_path):
    """Pre-existing DB does not get re-created tables; existing rows survive."""
    db_path = str(tmp_path / "existing.db")
    async with aiosqlite.connect(db_path) as db:
        await _build_legacy_db(db)
        await db.execute(
            "INSERT INTO scans (id, target_path, scan_types, status) VALUES ('s1', '/tmp', '[]', 'pending')"
        )
        await db.commit()

        await run_migrations(db)

        async with db.execute("SELECT id FROM scans WHERE id='s1'") as cur:
            row = await cur.fetchone()

    assert row is not None, "Pre-existing row must survive migration"


@pytest.mark.asyncio
async def test_schema_version_table_records_all_versions(tmp_path):
    """schema_version contains one row per migration after fresh install."""
    db_path = str(tmp_path / "sv.db")
    async with aiosqlite.connect(db_path) as db:
        await run_migrations(db)
        async with db.execute("SELECT version FROM schema_version ORDER BY version") as cur:
            rows = await cur.fetchall()
    versions = [r[0] for r in rows]
    assert versions == sorted(_all_migration_versions())
