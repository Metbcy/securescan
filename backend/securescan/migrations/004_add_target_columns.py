"""Add target_url and target_host columns to scans.

Idempotent: skipped per column if already present.
"""
import aiosqlite

VERSION = 4
DESCRIPTION = "Add target_url and target_host to scans"


async def up(conn: aiosqlite.Connection) -> None:
    async with conn.execute("PRAGMA table_info(scans)") as cur:
        cols = {row[1] for row in await cur.fetchall()}
    for col in ("target_url", "target_host"):
        if col not in cols:
            await conn.execute(f"ALTER TABLE scans ADD COLUMN {col} TEXT")  # noqa: S608


async def down(conn: aiosqlite.Connection) -> None:
    pass
