"""Tracked schema migrations for SecureScan.

Each migration file in this package is named NNN_description.py and exposes:
  VERSION: int
  DESCRIPTION: str
  up(conn: aiosqlite.Connection) -> None   (async)
  down(conn: aiosqlite.Connection) -> None (async)

run_migrations() is the public entry point called by database.init_db().
"""
from __future__ import annotations

import importlib.util
import os
from datetime import datetime, timezone

import aiosqlite

_MIGRATIONS_DIR = os.path.dirname(__file__)


def _load_all_migrations() -> list:
    """Load all NNN_*.py migration modules sorted by VERSION."""
    files = sorted(
        f for f in os.listdir(_MIGRATIONS_DIR)
        if f[0].isdigit() and f.endswith(".py")
    )
    modules = []
    for fname in files:
        fpath = os.path.join(_MIGRATIONS_DIR, fname)
        spec = importlib.util.spec_from_file_location(fname[:-3], fpath)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        modules.append(mod)
    return sorted(modules, key=lambda m: m.VERSION)


async def _get_recorded_versions(conn: aiosqlite.Connection) -> set[int]:
    async with conn.execute("SELECT version FROM schema_version") as cur:
        rows = await cur.fetchall()
    return {row[0] for row in rows}


_MIGRATION_1_TABLES = frozenset({
    "scans", "findings", "finding_states", "finding_comments",
    "sbom_documents", "sbom_components", "api_keys",
    "notifications", "webhooks", "webhook_deliveries",
})


async def _introspect_applied_versions(conn: aiosqlite.Connection) -> set[int]:
    """Detect which migration versions are effectively applied on a pre-existing DB.

    Used when schema_version table is empty but tables already exist -- i.e.,
    a database created before the migration system was introduced.
    """
    applied: set[int] = set()

    async with conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ) as cur:
        all_tables = {row[0] for row in await cur.fetchall()}

    if not all_tables:
        return applied  # truly empty DB

    # Version 1 requires ALL tables from 001_initial_schema to be present.
    # If any are missing, migration 001 must run (it uses CREATE TABLE IF NOT
    # EXISTS so existing tables are preserved; missing ones are created).
    if not _MIGRATION_1_TABLES.issubset(all_tables):
        return applied

    applied.add(1)

    async with conn.execute("PRAGMA table_info(findings)") as cur:
        findings_cols = {row[1] for row in await cur.fetchall()}
    if "compliance_tags" in findings_cols:
        applied.add(2)
    if "fingerprint" in findings_cols:
        applied.add(3)

    async with conn.execute("PRAGMA table_info(scans)") as cur:
        scans_cols = {row[1] for row in await cur.fetchall()}
    if "target_url" in scans_cols:
        applied.add(4)
    if "scanners_run" in scans_cols:
        applied.add(5)

    return applied


async def run_migrations(conn: aiosqlite.Connection) -> None:
    """Apply all pending migrations in order.

    Safe to call on both fresh databases and pre-existing ones:
    - Fresh DB: runs every migration from 001 onward.
    - Pre-existing DB (no schema_version table): introspects the live schema to
      determine which migrations are already applied, records them, then runs
      any remaining ones.
    - Already-migrated DB: skips versions already recorded in schema_version.
    """
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    """)
    await conn.commit()

    recorded = await _get_recorded_versions(conn)

    if not recorded:
        introspected = await _introspect_applied_versions(conn)
        if introspected:
            now = datetime.now(timezone.utc).isoformat()
            for v in sorted(introspected):
                await conn.execute(
                    "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (v, now),
                )
            await conn.commit()
            recorded = introspected

    for migration in _load_all_migrations():
        if migration.VERSION in recorded:
            continue
        await migration.up(conn)
        await conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
            (migration.VERSION, datetime.now(timezone.utc).isoformat()),
        )
        await conn.commit()
