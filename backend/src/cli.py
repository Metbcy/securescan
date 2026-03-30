import asyncio
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .config import settings
from .database import (
    get_findings,
    get_scan_summary,
    get_scans,
    init_db,
    save_findings,
    save_scan,
)
from .models import (
    Finding,
    Scan,
    ScanStatus,
    ScanType,
    Severity,
)
from .scanners import ALL_SCANNERS, get_scanners_for_types
from .scoring import build_summary
from .ai import AIEnricher

app = typer.Typer(name="securescan", help="AI-powered security scanning CLI")
console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


async def _run_scan_async(
    target_path: str,
    scan_types: list[ScanType],
) -> tuple[Scan, list[Finding]]:
    await init_db()

    scan = Scan(target_path=target_path, scan_types=scan_types)
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now()
    await save_scan(scan)

    scanners = get_scanners_for_types(scan_types)
    all_findings: list[Finding] = []
    scanners_run: list[str] = []

    for scanner in scanners:
        available = await scanner.is_available()
        if not available:
            console.print(f"  [dim]⏭ {scanner.name} not available, skipping[/dim]")
            continue
        console.print(f"  [cyan]▶ Running {scanner.name}...[/cyan]")
        results = await scanner.scan(target_path, scan.id)
        all_findings.extend(results)
        scanners_run.append(scanner.name)
        console.print(f"  [green]✓ {scanner.name}: {len(results)} finding(s)[/green]")

    await save_findings(all_findings)

    summary = build_summary(all_findings, scanners_run)
    scan.findings_count = summary.total_findings
    scan.risk_score = summary.risk_score

    # AI enrichment (optional)
    enricher = AIEnricher()
    if enricher.is_available:
        console.print("  [cyan]▶ Running AI enrichment...[/cyan]")
        await enricher.enrich_findings(all_findings)
        ai_summary = await enricher.generate_summary(all_findings, summary)
        scan.summary = ai_summary
        console.print("  [green]✓ AI enrichment complete[/green]")

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now()
    await save_scan(scan)

    return scan, all_findings


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("\n[green]No findings! 🎉[/green]")
        return

    table = Table(title="Findings", show_lines=True)
    table.add_column("Severity", width=10)
    table.add_column("Scanner", width=10)
    table.add_column("Title", min_width=30)
    table.add_column("File", width=30)
    table.add_column("Line", width=6)

    for f in findings:
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.scanner,
            f.title[:60],
            (f.file_path or "")[:30],
            str(f.line_start or ""),
        )

    console.print(table)


def _print_summary(scan: Scan, findings: list[Finding]) -> None:
    severity_counts = {}
    for sev in Severity:
        severity_counts[sev] = sum(1 for f in findings if f.severity == sev)

    table = Table(title="Scan Summary")
    table.add_column("Metric", style="bold")
    table.add_column("Value")

    table.add_row("Target", scan.target_path)
    table.add_row("Status", scan.status.value)
    table.add_row("Total Findings", str(len(findings)))
    table.add_row("[bold red]Critical[/bold red]", str(severity_counts[Severity.CRITICAL]))
    table.add_row("[red]High[/red]", str(severity_counts[Severity.HIGH]))
    table.add_row("[yellow]Medium[/yellow]", str(severity_counts[Severity.MEDIUM]))
    table.add_row("[blue]Low[/blue]", str(severity_counts[Severity.LOW]))
    table.add_row("[dim]Info[/dim]", str(severity_counts[Severity.INFO]))
    table.add_row("Risk Score", f"{scan.risk_score:.1f}" if scan.risk_score is not None else "N/A")

    console.print(table)


@app.command()
def scan(
    target_path: str = typer.Argument(..., help="Path to scan"),
    scan_type: Optional[list[ScanType]] = typer.Option(
        None, "--type", "-t", help="Scan type(s) to run"
    ),
):
    """Run a security scan on the target path."""
    types = scan_type if scan_type else [ScanType.CODE, ScanType.DEPENDENCY, ScanType.IAC, ScanType.BASELINE]
    console.print(f"\n[bold]🔍 SecureScan — scanning {target_path}[/bold]\n")

    result_scan, findings = asyncio.run(_run_scan_async(target_path, types))

    console.print()
    _print_findings(findings)
    console.print()
    _print_summary(result_scan, findings)

    if result_scan.summary:
        console.print(f"\n[bold cyan]AI Summary:[/bold cyan] {result_scan.summary}\n")


@app.command()
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


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
):
    """Start the SecureScan API server."""
    import uvicorn

    console.print(f"[bold]🚀 Starting SecureScan API on {host}:{port}[/bold]")
    uvicorn.run("src.main:app", host=host, port=port, reload=False)


@app.command()
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


if __name__ == "__main__":
    app()
