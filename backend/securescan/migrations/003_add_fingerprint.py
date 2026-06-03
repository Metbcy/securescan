"""Add fingerprint column to findings.

Empty default lets old rows coexist; the diff classifier recomputes the
fingerprint on read when it is empty.

Idempotent: skipped if the column already exists.
"""

import aiosqlite

VERSION = 3
DESCRIPTION = "Add fingerprint to findings"


async def up(conn: aiosqlite.Connection) -> None:
    async with conn.execute("PRAGMA table_info(findings)") as cur:
        cols = {row[1] for row in await cur.fetchall()}
    if "fingerprint" in cols:
        return
    await conn.execute("ALTER TABLE findings ADD COLUMN fingerprint TEXT DEFAULT ''")


async def down(conn: aiosqlite.Connection) -> None:
    pass
