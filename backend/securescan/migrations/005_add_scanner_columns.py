"""Add scanners_run and scanners_skipped JSON columns to scans.

Default '[]' so old rows decode as empty lists.

Idempotent: skipped per column if already present.
"""
import aiosqlite

VERSION = 5
DESCRIPTION = "Add scanners_run and scanners_skipped to scans"


async def up(conn: aiosqlite.Connection) -> None:
    async with conn.execute("PRAGMA table_info(scans)") as cur:
        cols = {row[1] for row in await cur.fetchall()}
    for col in ("scanners_run", "scanners_skipped"):
        if col not in cols:
            await conn.execute(  # noqa: S608
                f"ALTER TABLE scans ADD COLUMN {col} TEXT DEFAULT '[]'"
            )


async def down(conn: aiosqlite.Connection) -> None:
    pass
