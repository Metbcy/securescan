"""``securescan serve`` command — start the SecureScan API server.

The command function below is registered on the root Typer app by
:mod:`securescan.cli.__init__`.
"""

import typer

from ._shared import console


def serve(
    host: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
):
    """Start the SecureScan API server."""
    import uvicorn

    console.print(f"[bold]🚀 Starting SecureScan API on {host}:{port}[/bold]")
    uvicorn.run("securescan.main:app", host=host, port=port, reload=False)
