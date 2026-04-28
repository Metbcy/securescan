import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .baseline import filter_against_baseline
from .compliance import ComplianceMapper
from .config import settings
from .reports import ReportGenerator
from .database import (
    get_findings,
    get_scan_summary,
    get_scans,
    init_db,
    save_findings,
    save_scan,
)
from .dedup import deduplicate_findings
from .exporters import findings_to_sarif, findings_to_csv, findings_to_junit
from .models import (
    Finding,
    Scan,
    ScanStatus,
    ScanType,
    Severity,
)
from .scanners import ALL_SCANNERS, get_scanners_for_types
from .scoring import build_summary
from .threshold import count_at_or_above
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

SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def should_run_ai(*, explicit_ai: bool, explicit_no_ai: bool, ci_env: str) -> bool:
    """Decide whether AI enrichment should run for a given invocation.

    Truth table:

    * ``--ai``       wins        -> True
    * ``--no-ai``    wins        -> False
    * ``CI`` env in {"true","1"} -> False  (deterministic by default in CI)
    * otherwise                  -> True   (legacy default outside CI)

    ``ci_env`` is the raw string value of the ``CI`` environment variable
    (or empty string when unset). Pure-functional so tests don't need to
    mutate ``os.environ``.
    """
    if explicit_ai:
        return True
    if explicit_no_ai:
        return False
    if (ci_env or "").lower() in ("true", "1"):
        return False
    return True


async def _run_scan_async(
    target_path: str,
    scan_types: list[ScanType],
    enable_ai: bool = True,
) -> tuple[Scan, list[Finding]]:
    await init_db()

    scan = Scan(target_path=target_path, scan_types=scan_types)
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now()
    await save_scan(scan)

    scanners = get_scanners_for_types(scan_types)
    all_findings: list[Finding] = []
    scanners_run: list[str] = []

    # Filter to available scanners
    available_scanners = []
    for scanner in scanners:
        available = await scanner.is_available()
        if not available:
            console.print(f"  [dim]⏭ {scanner.name} not available, skipping[/dim]")
            continue
        available_scanners.append(scanner)

    # Run scanners in parallel
    if available_scanners:
        scanner_names = [s.name for s in available_scanners]
        console.print(f"  [cyan]▶ Running scanners in parallel: {', '.join(scanner_names)}[/cyan]")

        async def _run_one(scanner):
            results = await scanner.scan(target_path, scan.id)
            return scanner.name, results

        tasks = [_run_one(s) for s in available_scanners]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                console.print(f"  [red]✗ Scanner error: {result}[/red]")
                continue
            name, findings = result
            all_findings.extend(findings)
            scanners_run.append(name)
            console.print(f"  [green]✓ {name}: {len(findings)} finding(s)[/green]")

    # Deduplicate findings
    all_findings = deduplicate_findings(all_findings)

    # Compliance tagging
    compliance_data_dir = Path(settings.compliance_data_dir)
    if compliance_data_dir.exists():
        mapper = ComplianceMapper(compliance_data_dir)
        mapper.tag_findings(all_findings)
        tagged_count = sum(1 for f in all_findings if f.compliance_tags)
        console.print(f"  [green]✓ Compliance: tagged {tagged_count}/{len(all_findings)} findings[/green]")

    summary = build_summary(all_findings, scanners_run)
    scan.findings_count = summary.total_findings
    scan.risk_score = summary.risk_score

    # AI enrichment (optional)
    if enable_ai:
        enricher = AIEnricher()
        if enricher.is_available:
            console.print("  [cyan]▶ Running AI enrichment...[/cyan]")
            await enricher.enrich_findings(all_findings)
            ai_summary = await enricher.generate_summary(all_findings, summary)
            scan.summary = ai_summary
            console.print("  [green]✓ AI enrichment complete[/green]")

    # Save findings AFTER AI enrichment so remediation text is persisted
    await save_findings(all_findings)

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
    fail_on_severity: Optional[str] = typer.Option(
        None, "--fail-on-severity", help="Exit with code 1 if any finding at or above this severity (critical, high, medium, low)"
    ),
    fail_on_count: Optional[int] = typer.Option(
        None, "--fail-on-count", help="Exit with code 1 if total findings exceed this count"
    ),
    output: str = typer.Option(
        "table", "--output", "-o", help="Output format: table, json, sarif, csv, junit"
    ),
    output_file: Optional[str] = typer.Option(
        None, "--output-file", help="Write output to file instead of stdout"
    ),
    no_ai: bool = typer.Option(
        False, "--no-ai", help="Skip AI enrichment for fully deterministic runs"
    ),
    ai: bool = typer.Option(
        False, "--ai", help="Force AI enrichment even when CI=true is detected"
    ),
    baseline: Optional[Path] = typer.Option(
        None,
        "--baseline",
        help="Path to a baseline JSON file; findings whose fingerprint matches are suppressed",
    ),
):
    """Run a security scan on the target path."""
    if no_ai and ai:
        console.print("[red]--ai and --no-ai are mutually exclusive[/red]")
        raise typer.Exit(code=2)

    types = scan_type if scan_type else [ScanType.CODE, ScanType.DEPENDENCY, ScanType.IAC, ScanType.BASELINE]
    console.print(f"\n[bold]🔍 SecureScan — scanning {target_path}[/bold]\n")

    ci_env = os.environ.get("CI", "")
    enable_ai = should_run_ai(explicit_ai=ai, explicit_no_ai=no_ai, ci_env=ci_env)
    if not enable_ai and (ci_env or "").lower() in ("true", "1") and not no_ai and not ai:
        print(
            "CI detected, skipping AI enrichment for determinism (use --ai to override)",
            file=sys.stderr,
        )

    result_scan, findings = asyncio.run(_run_scan_async(target_path, types, enable_ai=enable_ai))

    # Baseline suppression (post-scan, pre-render)
    if baseline is not None:
        findings, suppressed = filter_against_baseline(findings, baseline)
        if suppressed:
            print(
                f"Suppressed {suppressed} findings via baseline {baseline}",
                file=sys.stderr,
            )

    # Format output
    output_content = None
    if output == "table":
        console.print()
        _print_findings(findings)
        console.print()
        _print_summary(result_scan, findings)
        if result_scan.summary:
            console.print(f"\n[bold cyan]AI Summary:[/bold cyan] {result_scan.summary}\n")
    elif output == "json":
        output_content = json.dumps([f.model_dump(mode="json") for f in findings], indent=2, default=str)
    elif output == "sarif":
        output_content = json.dumps(findings_to_sarif(findings, result_scan), indent=2, default=str)
    elif output == "csv":
        output_content = findings_to_csv(findings)
    elif output == "junit":
        output_content = findings_to_junit(findings, result_scan)
    elif output == "report-html":
        compliance_coverage = []
        compliance_data_dir = Path(settings.compliance_data_dir)
        if compliance_data_dir.exists():
            mapper = ComplianceMapper(compliance_data_dir)
            compliance_coverage = mapper.get_coverage(findings)
        summary_obj = build_summary(findings, [])
        generator = ReportGenerator(Path(settings.report_template_dir))
        output_content = generator.generate_html(result_scan, findings, summary_obj, compliance_coverage)
    elif output == "report-pdf":
        compliance_coverage = []
        compliance_data_dir = Path(settings.compliance_data_dir)
        if compliance_data_dir.exists():
            mapper = ComplianceMapper(compliance_data_dir)
            compliance_coverage = mapper.get_coverage(findings)
        summary_obj = build_summary(findings, [])
        generator = ReportGenerator(Path(settings.report_template_dir))
        pdf_bytes = generator.generate_pdf(result_scan, findings, summary_obj, compliance_coverage)
        if output_file:
            Path(output_file).write_bytes(pdf_bytes)
            console.print(f"[green]PDF report written to {output_file}[/green]")
        else:
            console.print("[red]PDF output requires --output-file[/red]")
        output_content = None
    else:
        console.print(f"[red]Unknown output format: {output}[/red]")
        raise typer.Exit(code=1)

    if output_content is not None:
        if output_file:
            Path(output_file).write_text(output_content)
            console.print(f"[green]Output written to {output_file}[/green]")
        else:
            console.print(output_content)

    # Check failure thresholds
    if fail_on_severity:
        severity_threshold = fail_on_severity.lower()
        threshold_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        threshold_sev = threshold_map.get(severity_threshold)
        if threshold_sev is None:
            console.print(f"[red]Invalid severity: {fail_on_severity}. Use critical, high, medium, or low.[/red]")
            raise typer.Exit(code=1)
        offending = count_at_or_above(findings, threshold_sev)
        if offending > 0:
            console.print(
                f"[bold red]✗ Failing: found {offending} finding(s) at or above threshold '{severity_threshold}'[/bold red]"
            )
            raise typer.Exit(code=1)

    if fail_on_count is not None and len(findings) > fail_on_count:
        console.print(f"[bold red]✗ Failing: {len(findings)} findings exceed threshold of {fail_on_count}[/bold red]")
        raise typer.Exit(code=1)


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
