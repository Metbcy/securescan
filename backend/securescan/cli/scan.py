"""``securescan scan`` command.

Single-snapshot scan: runs all (or selected) scanners against
``target_path``, persists the result row + findings to the local DB,
and emits findings in the requested format.

The command function below is registered on the root Typer app by
:mod:`securescan.cli.__init__`.
"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import typer
from rich.table import Table

from ..ai import AIEnricher
from ..compliance import ComplianceMapper
from ..config import settings
from ..database import (
    init_db,
    save_findings,
    save_scan,
)
from ..dedup import deduplicate_findings
from ..exporters import (
    findings_to_csv,
    findings_to_json,
    findings_to_junit,
    findings_to_sarif,
)
from ..fingerprint import populate_fingerprints
from ..models import (
    Finding,
    Scan,
    ScannerSkip,
    ScanStatus,
    ScanType,
    Severity,
)
from ..ordering import sort_findings_canonical
from ..pipeline import apply_pipeline
from ..reports import ReportGenerator
from ..scanners import get_scanners_for_types
from ..scoring import build_summary
from ..threshold import count_at_or_above
from . import _shared
from ._shared import (
    SEVERITY_COLORS,
    console,
    should_run_ai,
)


async def _run_scan_async(
    target_path: str,
    scan_types: list[ScanType],
    enable_ai: bool = True,
    *,
    scanner_kwargs: dict | None = None,
) -> tuple[Scan, list[Finding]]:
    await init_db()

    scan = Scan(target_path=target_path, scan_types=scan_types)
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now()
    await save_scan(scan)

    scanners = get_scanners_for_types(scan_types)
    all_findings: list[Finding] = []
    scanners_run: list[str] = []

    # Filter to available scanners. Track skipped ones with their install_hint
    # so the dashboard / `report` command can surface why a category produced
    # zero findings (PG2: closes UX gap #2).
    available_scanners = []
    scanners_skipped: list[ScannerSkip] = []
    for scanner in scanners:
        available = await scanner.is_available()
        if not available:
            install_hint = getattr(scanner, "install_hint", None)
            scanners_skipped.append(
                ScannerSkip(
                    name=scanner.name,
                    reason="not installed" if install_hint else "unavailable",
                    install_hint=install_hint,
                )
            )
            console.print(f"  [dim]⏭ {scanner.name} not available, skipping[/dim]")
            continue
        available_scanners.append(scanner)

    # Run scanners in parallel
    if available_scanners:
        scanner_names = [s.name for s in available_scanners]
        console.print(f"  [cyan]▶ Running scanners in parallel: {', '.join(scanner_names)}[/cyan]")

        kwargs = scanner_kwargs or {}

        async def _run_one(scanner):
            results = await scanner.scan(target_path, scan.id, **kwargs)
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
        console.print(
            f"  [green]✓ Compliance: tagged {tagged_count}/{len(all_findings)} findings[/green]"
        )

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

    # Save findings AFTER AI enrichment so remediation text is persisted.
    # Populate fingerprints first so the diff classifier (SS4) and PR-comment
    # renderer (SS7) get a stable identity for every persisted finding.
    populate_fingerprints(all_findings)
    await save_findings(all_findings)

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now()
    scan.scanners_run = sorted(scanners_run)
    scan.scanners_skipped = sorted(scanners_skipped, key=lambda s: s.name)
    await save_scan(scan)

    return scan, all_findings


def _print_findings(findings: list[Finding], *, show_suppressed: bool = False) -> None:
    if not show_suppressed:
        findings = [
            f
            for f in findings
            if not (
                isinstance(getattr(f, "metadata", None), dict) and f.metadata.get("suppressed_by")
            )
        ]

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
        title = f.title[:60]
        if show_suppressed:
            metadata = getattr(f, "metadata", None)
            if isinstance(metadata, dict):
                reason = metadata.get("suppressed_by")
                if isinstance(reason, str) and reason:
                    title = f"[SUPPRESSED:{reason}] {title}"[:80]
        table.add_row(
            f"[{color}]{f.severity.value.upper()}[/{color}]",
            f.scanner,
            title,
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


def scan(
    target_path: str = typer.Argument(..., help="Path to scan"),
    scan_type: list[ScanType] | None = typer.Option(
        None, "--type", "-t", help="Scan type(s) to run"
    ),
    fail_on_severity: str | None = typer.Option(
        None,
        "--fail-on-severity",
        help="Exit with code 1 if any finding at or above this severity (critical, high, medium, low)",
    ),
    fail_on_count: int | None = typer.Option(
        None, "--fail-on-count", help="Exit with code 1 if total findings exceed this count"
    ),
    output: str = typer.Option(
        "table",
        "--output",
        "-o",
        help=(
            "Output format: table, json, sarif, csv, junit, "
            "report-html, report-pdf. The github-review payload is "
            "NOT supported here -- inline review comments need a "
            "PR base+head diff context to anchor against; use "
            "`securescan diff` or `securescan compare` for that. "
            "Note: `report-pdf` requires the [pdf] extra "
            "(`pip install 'securescan[pdf]'`); the container image "
            "ships it pre-installed."
        ),
    ),
    output_file: str | None = typer.Option(
        None, "--output-file", help="Write output to file instead of stdout"
    ),
    no_ai: bool = typer.Option(
        False, "--no-ai", help="Skip AI enrichment for fully deterministic runs"
    ),
    ai: bool = typer.Option(
        False, "--ai", help="Force AI enrichment even when CI=true is detected"
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help="Path to a baseline JSON file; findings whose fingerprint matches are suppressed",
    ),
    show_suppressed: bool | None = typer.Option(
        None,
        "--show-suppressed/--hide-suppressed",
        help=(
            "Include suppressed findings in output, marked with "
            "[SUPPRESSED:<reason>] prefix where supported. Default: "
            "auto -- shown on a TTY (table/text formats) so devs see "
            "what CI would hide; hidden when piped or in non-text "
            "formats (json/sarif/csv/junit). Use --hide-suppressed to "
            "force hiding even on a TTY."
        ),
    ),
    no_suppress: bool = typer.Option(
        False,
        "--no-suppress",
        help=(
            "Disable all suppression mechanisms (config, inline "
            "comments, baseline). Use to debug what would otherwise "
            "be hidden. Wired through to SuppressionContext; the "
            "scan-time application is owned by the wire-cli-flow "
            "integration (TS10)."
        ),
    ),
    baseline_host_probes: bool = typer.Option(
        False,
        "--baseline-host-probes",
        help=(
            "Force the baseline scanner to run host-wide probes "
            "(/etc/ssh/sshd_config, /etc/passwd, kernel sysctls, "
            "firewall, etc.) regardless of target_path. Default: "
            "off -- baseline honors target_path and only goes "
            "host-wide when target is `/` or empty. Use this when "
            "you want host-scope findings alongside a project "
            "directory scan."
        ),
    ),
):
    """Run a security scan on the target path."""
    if no_ai and ai:
        console.print("[red]--ai and --no-ai are mutually exclusive[/red]")
        raise typer.Exit(code=2)

    if output == "github-review":
        # ``github-review`` anchors inline comments at diff positions
        # in a PR's unified diff (base..head). ``scan`` has no
        # base+head context -- it's a single-snapshot command -- so
        # there is nothing to anchor against. Fail fast and point the
        # user at the right subcommand instead of silently emitting a
        # degenerate payload that pushes every finding into the body
        # fallback.
        typer.echo(
            "scan: --output github-review is not supported on `scan`. "
            "Inline PR review comments need a base+head commit pair to "
            "anchor against; run `securescan diff` or "
            "`securescan compare` instead.",
            err=True,
        )
        raise typer.Exit(code=2)

    types = (
        scan_type
        if scan_type
        else [ScanType.CODE, ScanType.DEPENDENCY, ScanType.IAC, ScanType.BASELINE]
    )
    console.print(f"\n[bold]🔍 SecureScan — scanning {target_path}[/bold]\n")

    # TS10: load + path-resolve .securescan.yml ONCE up front. The same
    # config object feeds (a) the AI gate via ``config_ai``, (b) the
    # Semgrep custom-rule plumbing via ``scanner_kwargs``, and (c) the
    # post-scan ``apply_pipeline`` (severity overrides + suppression).
    # A single load avoids re-walking the filesystem and guarantees all
    # three observers see the same effective config for the run.
    resolved_config, found_config_path = _shared._load_resolved_config(target_path)
    if found_config_path is not None:
        print(
            f"loaded config from {found_config_path}",
            file=sys.stderr,
        )

    ci_env = os.environ.get("CI", "")
    enable_ai = should_run_ai(
        explicit_ai=ai,
        explicit_no_ai=no_ai,
        ci_env=ci_env,
        config_ai=resolved_config.ai,
    )
    if (
        not enable_ai
        and (ci_env or "").lower() in ("true", "1")
        and not no_ai
        and not ai
        and resolved_config.ai is None
    ):
        print(
            "CI detected, skipping AI enrichment for determinism (use --ai to override)",
            file=sys.stderr,
        )

    scanner_kwargs: dict = {}
    if resolved_config.semgrep_rules:
        scanner_kwargs["semgrep_rules"] = resolved_config.semgrep_rules
    if baseline_host_probes:
        # Plumbed through ``_run_scan_async`` -> every scanner's
        # ``scan(**kwargs)``; only the BaselineScanner reads it,
        # the rest swallow it via their accept-all signature.
        scanner_kwargs["baseline_host_probes"] = True

    result_scan, findings = asyncio.run(
        _run_scan_async(
            target_path,
            types,
            enable_ai=enable_ai,
            scanner_kwargs=scanner_kwargs,
        )
    )

    # TS10: replace the standalone filter_against_baseline call with the
    # unified pipeline. ``apply_pipeline`` does the same baseline-
    # fingerprint suppression *plus* config-ignored rules, inline ignore
    # comments, severity overrides and the audit-trail metadata stamps
    # in a single, idempotent pass. ``--no-suppress`` propagates here as
    # the CLI kill switch.
    pipeline = apply_pipeline(
        findings,
        target_path=Path(target_path),
        baseline_path=baseline,
        no_suppress=no_suppress,
        config=resolved_config,
    )
    if pipeline.suppressed:
        # Mirror the pre-TS10 ``filter_against_baseline`` stderr line so
        # CI logs that grep for "Suppressed" still find the count, but
        # report the union across all three suppression sources now.
        print(
            f"Suppressed {len(pipeline.suppressed)} finding(s) (inline + config + baseline)",
            file=sys.stderr,
        )
    if pipeline.severity_overrides_applied:
        print(
            f"Applied {pipeline.severity_overrides_applied} severity override(s) from config",
            file=sys.stderr,
        )

    # ``findings`` carries kept + suppressed so renderers see both and
    # the ``[SUPPRESSED:<reason>]`` metadata stamps survive into output.
    findings = pipeline.kept + pipeline.suppressed

    # Canonicalize finding order so every output format (table, json,
    # sarif, csv, junit, report-html) is byte-identical for re-runs of
    # the same logical scan.
    findings = sort_findings_canonical(findings)

    # Resolve the show_suppressed default once per invocation. TS6
    # contract: TTY default for table/text on, off for everything else;
    # explicit flag overrides. After TS10 the suppressed findings carry
    # the ``metadata['suppressed_by']`` stamp produced by the pipeline,
    # so renderers can both filter and label them.
    effective_show_suppressed = _shared._default_show_suppressed(
        explicit=show_suppressed, output_format=output
    )

    # Format output
    output_content = None
    if output == "table":
        console.print()
        _print_findings(findings, show_suppressed=effective_show_suppressed)
        console.print()
        _print_summary(result_scan, findings)
        if result_scan.summary:
            console.print(f"\n[bold cyan]AI Summary:[/bold cyan] {result_scan.summary}\n")
    elif output == "json":
        output_content = findings_to_json(findings, show_suppressed=effective_show_suppressed)
    elif output == "sarif":
        output_content = json.dumps(
            findings_to_sarif(
                findings,
                result_scan,
                show_suppressed=effective_show_suppressed,
            ),
            indent=2,
            default=str,
        )
    elif output == "csv":
        output_content = findings_to_csv(findings, show_suppressed=effective_show_suppressed)
    elif output == "junit":
        output_content = findings_to_junit(
            findings,
            result_scan,
            show_suppressed=effective_show_suppressed,
        )
    elif output == "report-html":
        compliance_coverage = []
        compliance_data_dir = Path(settings.compliance_data_dir)
        if compliance_data_dir.exists():
            mapper = ComplianceMapper(compliance_data_dir)
            compliance_coverage = mapper.get_coverage(findings)
        summary_obj = build_summary(findings, [])
        generator = ReportGenerator(Path(settings.report_template_dir))
        output_content = generator.generate_html(
            result_scan, findings, summary_obj, compliance_coverage
        )
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

    # TS10: gates count only the kept findings. Suppression is the
    # "explicitly tolerated" lane; failing CI on a finding the user
    # silenced via .securescan.yml / inline / baseline would defeat
    # the purpose of those mechanisms.
    gate_findings = pipeline.kept

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
            console.print(
                f"[red]Invalid severity: {fail_on_severity}. Use critical, high, medium, or low.[/red]"
            )
            raise typer.Exit(code=1)
        offending = count_at_or_above(gate_findings, threshold_sev)
        if offending > 0:
            console.print(
                f"[bold red]✗ Failing: found {offending} finding(s) at or above threshold '{severity_threshold}'[/bold red]"
            )
            raise typer.Exit(code=1)

    if fail_on_count is not None and len(gate_findings) > fail_on_count:
        console.print(
            f"[bold red]✗ Failing: {len(gate_findings)} findings exceed threshold of {fail_on_count}[/bold red]"
        )
        raise typer.Exit(code=1)
