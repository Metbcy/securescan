"""Per-event-type notification threshold settings (issue #6).

Adds a `notification_settings` table holding one row per notification
event type with a configurable minimum severity threshold. Rows are NOT
seeded by this migration; the application layer applies defaults when
no row exists for an event type so upgrades are no-ops.

Defaults (defined in the application layer, see
`securescan.database.NOTIFICATION_DEFAULTS`):

* scan.complete   -> medium  (approximates today's "any finding fires"
                              behavior; pre-issue-6 the bell rang for
                              any non-zero findings_count, including
                              info/low. medium was chosen as the
                              sensible default per the issue brief.)
* scan.failed     -> info    (always notify; matches today)
* scanner.failed  -> info    (always notify; matches today)

Idempotent: skipped on re-apply via CREATE TABLE IF NOT EXISTS.
"""

import aiosqlite

VERSION = 7
DESCRIPTION = "Add notification_settings table for per-event-type thresholds"


async def up(conn: aiosqlite.Connection) -> None:
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS notification_settings (
            event_type TEXT PRIMARY KEY,
            min_severity TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)


async def down(conn: aiosqlite.Connection) -> None:
    await conn.execute("DROP TABLE IF EXISTS notification_settings")
