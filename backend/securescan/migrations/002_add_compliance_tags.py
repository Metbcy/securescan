"""Add compliance_tags column to findings.

Idempotent: skipped if the column already exists (e.g., fresh install via
migration 001 which includes the column in the CREATE TABLE statement).
"""
import aiosqlite

VERSION = 2
DESCRIPTION = "Add compliance_tags to findings"


async def up(conn: aiosqlite.Connection) -> None:
    async with conn.execute("PRAGMA table_info(findings)") as cur:
        cols = {row[1] for row in await cur.fetchall()}
    if "compliance_tags" in cols:
        return
    await conn.execute("ALTER TABLE findings ADD COLUMN compliance_tags TEXT DEFAULT '[]'")


async def down(conn: aiosqlite.Connection) -> None:
    # SQLite does not support DROP COLUMN in older versions; this is a no-op.
    pass
