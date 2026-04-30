"""``securescan history`` command — show recent scan rows from the DB.

The command function below is registered on the root Typer app by
:mod:`securescan.cli.__init__`.
"""

import asyncio

from rich.table import Table

from ..database import get_scans, init_db
from ._shared import console


def history():
    """Show recent scan history from the database."""

    async def _history():
        await init_db()
        return await get_scans()

    scans = asyncio.run(_history())

    if not scans:
        console.print("[dim]No scan history found.[/dim]")
        return

    table = Table(title="Scan History")
    table.add_column("ID", width=8)
    table.add_column("Target", min_width=20)
    table.add_column("Status")
    table.add_column("Findings")
    table.add_column("Risk Score")
    table.add_column("Date")

    for s in scans:
        date_str = s.started_at.strftime("%Y-%m-%d %H:%M") if s.started_at else "—"
        table.add_row(
            s.id[:8],
            s.target_path[:30],
            s.status.value,
            str(s.findings_count),
            f"{s.risk_score:.1f}" if s.risk_score is not None else "—",
            date_str,
        )

    console.print(table)
