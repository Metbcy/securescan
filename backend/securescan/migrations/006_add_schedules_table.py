"""Add schedules and schedule_runs tables.

schedules: cron-driven scan schedules (name, target, types, expression,
           last_run, enabled).
schedule_runs: cross-reference rows created each time a schedule fires
               (schedule_id -> scan_id).

Idempotent: both tables use CREATE TABLE IF NOT EXISTS.
"""

import aiosqlite

VERSION = 6
DESCRIPTION = "Add schedules and schedule_runs tables"


async def up(conn: aiosqlite.Connection) -> None:
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS schedules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            target_path TEXT NOT NULL,
            scan_types TEXT NOT NULL DEFAULT '["code","dependency"]',
            cron_expression TEXT NOT NULL,
            last_run TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    """)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS schedule_runs (
            id TEXT PRIMARY KEY,
            schedule_id TEXT NOT NULL,
            scan_id TEXT,
            triggered_at TEXT NOT NULL,
            FOREIGN KEY (schedule_id) REFERENCES schedules(id)
        )
    """)
    await conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_schedule_runs_schedule "
        "ON schedule_runs(schedule_id, triggered_at DESC)"
    )


async def down(conn: aiosqlite.Connection) -> None:
    await conn.execute("DROP TABLE IF EXISTS schedule_runs")
    await conn.execute("DROP TABLE IF EXISTS schedules")
