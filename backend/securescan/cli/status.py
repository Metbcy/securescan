"""``securescan status`` command — show installed-scanner availability.

The command function below is registered on the root Typer app by
:mod:`securescan.cli.__init__`.
"""

import asyncio

from rich.table import Table

from ..scanners import ALL_SCANNERS
from ._shared import console


def status():
    """Show which scanners are installed and available."""

    async def _check():
        statuses = []
        for scanner in ALL_SCANNERS:
            available, message = await scanner.check_or_warn()
            statuses.append((scanner.name, scanner.scan_type.value, available, message))
        return statuses

    results = asyncio.run(_check())

    table = Table(title="Scanner Status")
    table.add_column("Scanner", style="bold")
    table.add_column("Type")
    table.add_column("Available")
    table.add_column("Details")

    for name, stype, available, message in results:
        icon = "[green]✓[/green]" if available else "[red]✗[/red]"
        table.add_row(name, stype, icon, message)

    console.print(table)
