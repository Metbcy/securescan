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

from .baseline_writer import write_baseline as _write_baseline_file
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
from .diff import ChangeSet, classify, load_findings_json
from .exporters import findings_to_sarif, findings_to_csv, findings_to_junit
from .fingerprint import populate_fingerprints
from .git_ops import (
    GitOpError,
    checkout as git_checkout,
    current_ref as git_current_ref,
    is_clean as git_is_clean,
    is_git_repo,
    rev_parse as git_rev_parse,
)
from .models import (
    Finding,
    Scan,
    ScanStatus,
    ScanType,
    Severity,
)
from .render_pr_comment import render_pr_comment
from .scanners import ALL_SCANNERS, get_scanners_for_types
from .scoring import build_summary
from .threshold import count_at_or_above
from .ai import AIEnricher
from .ordering import sort_findings_canonical

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


def diff_should_run_ai(*, explicit_ai: bool, explicit_no_ai: bool) -> bool:
    """AI gate for ``securescan diff``. Differs from the regular ``scan``
    command's ``should_run_ai`` in one way: AI is **off by default**
    even outside CI, because diff mode is fundamentally a CI/automation
    use case (PR comments must be byte-identical across re-runs to
    enable upsert) and every diff caller we've seen wants determinism.
    The user has to opt back in with ``--ai`` explicitly.

    Truth table:

    * ``--no-ai``  -> False
    * ``--ai``     -> True
    * neither      -> False  (the diff-mode default)

    Flag mutex (``--ai && --no-ai``) is rejected at the CLI layer
    before this helper is consulted.
    """
    if explicit_no_ai:
        return False
    return explicit_ai


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

    # Save findings AFTER AI enrichment so remediation text is persisted.
    # Populate fingerprints first so the diff classifier (SS4) and PR-comment
    # renderer (SS7) get a stable identity for every persisted finding.
    populate_fingerprints(all_findings)
    await save_findings(all_findings)

    scan.status = ScanStatus.COMPLETED
    scan.completed_at = datetime.now()
    await save_scan(scan)

    return scan, all_findings


async def _run_scan_for_diff(
    target_path: str,
    scan_types: list[ScanType],
    *,
    enable_ai: bool,
) -> list[Finding]:
    """Lightweight scan helper used by the ``diff`` subcommand.

    Differences vs. ``_run_scan_async``:

    * No DB I/O. We deliberately do not write a row to the ``scans`` /
      ``findings`` tables for either side of a diff -- a diff invocation
      is short-lived analysis, not a persisted scan, and CI runs would
      otherwise create two stray history rows per PR push.
    * No risk-score / summary computation -- the diff cares about
      finding *identity* (fingerprint), not aggregate scoring.
    * No compliance tagging -- compliance metadata isn't part of the
      fingerprint and doesn't change classification.

    Otherwise the scanner orchestration is identical: filter to the
    requested scan types, drop unavailable scanners, run the rest in
    parallel, dedupe the union, populate fingerprints. AI enrichment is
    opt-in via ``enable_ai`` (the diff CLI defaults this to False --
    see ``diff_should_run_ai``).
    """
    scan_id = str(__import__("uuid").uuid4())
    scanners = get_scanners_for_types(scan_types)
    all_findings: list[Finding] = []

    available_scanners = []
    for scanner in scanners:
        try:
            if await scanner.is_available():
                available_scanners.append(scanner)
        except Exception:
            continue

    if available_scanners:
        async def _run_one(s):
            return await s.scan(target_path, scan_id)

        results = await asyncio.gather(
            *(_run_one(s) for s in available_scanners),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Exception):
                continue
            all_findings.extend(result)

    all_findings = deduplicate_findings(all_findings)

    if enable_ai:
        enricher = AIEnricher()
        if enricher.is_available:
            await enricher.enrich_findings(all_findings)

    populate_fingerprints(all_findings)
    return all_findings


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

    # Canonicalize finding order so every output format (table, json,
    # sarif, csv, junit, report-html) is byte-identical for re-runs of
    # the same logical scan.
    findings = sort_findings_canonical(findings)

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


_SEVERITY_THRESHOLD_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _render_diff_text(cs: ChangeSet) -> str:
    """Render a ``ChangeSet`` as plain-text suitable for a human terminal.

    Format is intentionally minimal so it fits on a single screen for
    typical PR-sized diffs:

        SecureScan diff: <N> new, <M> fixed, <K> unchanged

        New findings:
          [CRITICAL] <title> (<file>:<line>)
          ...

    No ANSI colour, no Markdown, no emojis. The PR-comment renderer
    handles the GitHub case; this is the local-development case.
    """
    lines: list[str] = [
        f"SecureScan diff: {len(cs.new)} new, {len(cs.fixed)} fixed, "
        f"{len(cs.unchanged)} unchanged"
    ]
    if not cs.new and not cs.fixed:
        lines.append("")
        lines.append("No new or fixed findings.")
        return "\n".join(lines) + "\n"

    if cs.new:
        lines.append("")
        lines.append("New findings:")
        severity_order = (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        )
        for sev in severity_order:
            for f in cs.new:
                if f.severity != sev:
                    continue
                loc = ""
                if f.file_path:
                    loc = f" ({f.file_path}"
                    if f.line_start:
                        loc += f":{f.line_start}"
                    loc += ")"
                lines.append(f"  [{sev.value.upper()}] {f.title}{loc}")

    if cs.fixed:
        lines.append("")
        lines.append(f"Fixed findings: {len(cs.fixed)}")

    return "\n".join(lines) + "\n"


def _render_diff_sarif(
    cs: ChangeSet,
    *,
    target_path: str,
    scan_types: list[ScanType],
    base_ref: str | None,
    head_ref: str | None,
) -> dict:
    """Render the NEW findings of a changeset as a SARIF document.

    Decision: SARIF for diff mode is **NEW only**. Fixed findings are
    not security alerts; emitting them would generate spurious
    "resolved alert" noise on the GitHub Security tab. The
    ``invocations[].properties`` block records ``diffMode: true`` plus
    the base / head refs so a downstream consumer can tell this isn't a
    full scan upload.
    """
    diff_scan = Scan(
        target_path=target_path,
        scan_types=scan_types or [ScanType.CODE],
        status=ScanStatus.COMPLETED,
    )
    sarif = findings_to_sarif(cs.new, diff_scan)
    try:
        run = sarif["runs"][0]
        invocation = run["invocations"][0]
        props = invocation.setdefault("properties", {})
        props["diffMode"] = True
        if base_ref:
            props["baseRef"] = base_ref
        if head_ref:
            props["headRef"] = head_ref
    except (KeyError, IndexError):
        pass
    return sarif


def _resolve_default_output(explicit: str | None) -> str:
    """Choose the default ``--output`` value.

    When the user passed ``--output`` explicitly we take it verbatim.
    Otherwise: if stdout is a TTY (a human at a terminal), default to
    ``text``; otherwise default to ``github-pr-comment`` (the CI / pipe
    case, which is the wedge use case for the diff command).
    """
    if explicit:
        return explicit
    return "text" if sys.stdout.isatty() else "github-pr-comment"


@app.command()
def diff(
    target_path: str = typer.Argument(".", help="Path to the project to diff."),
    base_ref: Optional[str] = typer.Option(
        None,
        "--base-ref",
        help=(
            "Git ref for the 'before' side (e.g. main, abc123). Required "
            "unless --base-snapshot/--head-snapshot are used."
        ),
    ),
    head_ref: Optional[str] = typer.Option(
        None,
        "--head-ref",
        help="Git ref for the 'after' side. Defaults to HEAD.",
    ),
    base_snapshot: Optional[Path] = typer.Option(
        None,
        "--base-snapshot",
        help=(
            "Path to a JSON file with the 'before' findings (skips the "
            "base scan, useful in CI where it's already done)."
        ),
    ),
    head_snapshot: Optional[Path] = typer.Option(
        None,
        "--head-snapshot",
        help="Path to a JSON file with the 'after' findings.",
    ),
    scan_types: list[str] = typer.Option(
        ["code"],
        "--type",
        help="Scan types to run on each side (repeatable).",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        help=(
            "Output format: github-pr-comment | sarif | json | text. "
            "Default: github-pr-comment when stdout is piped, text on a TTY."
        ),
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        help="Write rendered output to a file instead of stdout.",
    ),
    fail_on_severity: Optional[str] = typer.Option(
        None,
        "--fail-on-severity",
        help="Exit non-zero if NEW findings >= this severity.",
    ),
    repo: Optional[str] = typer.Option(
        None,
        "--repo",
        envvar="GITHUB_REPOSITORY",
        help="owner/repo for github-pr-comment links.",
    ),
    sha: Optional[str] = typer.Option(
        None,
        "--sha",
        envvar="GITHUB_SHA",
        help="Commit sha for github-pr-comment links.",
    ),
    baseline: Optional[Path] = typer.Option(
        None,
        "--baseline",
        help=(
            "Suppress findings present in this baseline JSON file "
            "(applied to BOTH sides)."
        ),
    ),
    no_ai: bool = typer.Option(False, "--no-ai"),
    ai: bool = typer.Option(False, "--ai"),
):
    """Diff two scan snapshots; emit only NEW findings (and counts of fixed/unchanged).

    Two modes:

    - ``--base-ref`` / ``--head-ref``: securescan handles the git
      checkouts and runs scanners on each side. Working tree must be
      clean. Original ref is always restored on exit (even on error).
    - ``--base-snapshot`` / ``--head-snapshot``: provide pre-scanned
      JSON outputs (CI fast path; no git needed). The GitHub Action
      uses this mode after pre-scanning base and head separately.

    AI enrichment is **off by default in diff mode** -- the diff is the
    canonical CI/automation surface and PR-comment bodies must be
    byte-identical across re-runs to enable comment upsert. Pass
    ``--ai`` to opt back in.

    Default ``--output`` is ``github-pr-comment`` when stdout is piped
    (the CI case) and ``text`` when stdout is a TTY (the local case).
    """
    if no_ai and ai:
        typer.echo("diff: --ai and --no-ai are mutually exclusive", err=True)
        raise typer.Exit(code=2)

    have_ref_inputs = base_ref is not None or head_ref is not None
    have_snap_inputs = base_snapshot is not None or head_snapshot is not None

    if have_ref_inputs and have_snap_inputs:
        typer.echo(
            "diff: choose either --base-ref/--head-ref OR "
            "--base-snapshot/--head-snapshot, not both",
            err=True,
        )
        raise typer.Exit(code=2)

    if not have_ref_inputs and not have_snap_inputs:
        typer.echo(
            "diff: must provide either --base-ref (with optional --head-ref) "
            "or --base-snapshot AND --head-snapshot",
            err=True,
        )
        raise typer.Exit(code=2)

    if have_snap_inputs and (base_snapshot is None or head_snapshot is None):
        typer.echo(
            "diff: snapshot mode requires BOTH --base-snapshot AND --head-snapshot",
            err=True,
        )
        raise typer.Exit(code=2)

    if have_ref_inputs and base_ref is None:
        typer.echo(
            "diff: ref mode requires --base-ref (--head-ref defaults to HEAD)",
            err=True,
        )
        raise typer.Exit(code=2)

    output_format = _resolve_default_output(output)
    if output_format not in {"github-pr-comment", "sarif", "json", "text"}:
        typer.echo(
            f"diff: unknown --output {output_format!r}. "
            "Choose github-pr-comment | sarif | json | text.",
            err=True,
        )
        raise typer.Exit(code=2)

    parsed_types: list[ScanType] = []
    for raw_type in scan_types:
        try:
            parsed_types.append(ScanType(raw_type))
        except ValueError:
            typer.echo(
                f"diff: unknown --type {raw_type!r}. "
                f"Valid: {', '.join(t.value for t in ScanType)}",
                err=True,
            )
            raise typer.Exit(code=2)

    enable_ai = diff_should_run_ai(explicit_ai=ai, explicit_no_ai=no_ai)

    resolved_head_sha: str | None = None

    if have_snap_inputs:
        try:
            base_findings = load_findings_json(base_snapshot)
            head_findings = load_findings_json(head_snapshot)
        except (OSError, json.JSONDecodeError) as exc:
            typer.echo(f"diff: failed to load snapshot: {exc}", err=True)
            raise typer.Exit(code=2)
    else:
        target = Path(target_path).resolve()
        if not is_git_repo(target):
            typer.echo(
                f"diff: {target} is not inside a git working tree",
                err=True,
            )
            raise typer.Exit(code=2)

        try:
            if not git_is_clean(target):
                typer.echo(
                    "diff: working tree has uncommitted changes; "
                    "commit, stash, or clean before running diff in ref mode",
                    err=True,
                )
                raise typer.Exit(code=2)
            original_ref = git_current_ref(target)
        except GitOpError as exc:
            typer.echo(f"diff: {exc}", err=True)
            raise typer.Exit(code=2)

        h_ref = head_ref or "HEAD"
        try:
            resolved_head_sha = git_rev_parse(target, h_ref)
            base_resolved_sha = git_rev_parse(target, base_ref)
        except GitOpError as exc:
            typer.echo(f"diff: {exc}", err=True)
            raise typer.Exit(code=2)

        try:
            try:
                git_checkout(target, base_resolved_sha)
                base_findings = asyncio.run(
                    _run_scan_for_diff(
                        str(target), parsed_types, enable_ai=enable_ai
                    )
                )
                git_checkout(target, resolved_head_sha)
                head_findings = asyncio.run(
                    _run_scan_for_diff(
                        str(target), parsed_types, enable_ai=enable_ai
                    )
                )
            except GitOpError as exc:
                typer.echo(f"diff: {exc}", err=True)
                raise typer.Exit(code=1)
        finally:
            try:
                git_checkout(target, original_ref)
            except GitOpError as exc:
                typer.echo(
                    f"diff: warning: could not restore original ref "
                    f"{original_ref}: {exc}",
                    err=True,
                )

    if sha is None and resolved_head_sha:
        sha = resolved_head_sha

    if baseline is not None:
        base_findings, base_suppressed = filter_against_baseline(
            base_findings, baseline
        )
        head_findings, head_suppressed = filter_against_baseline(
            head_findings, baseline
        )
        if base_suppressed or head_suppressed:
            typer.echo(
                f"diff: baseline suppressed {base_suppressed} base / "
                f"{head_suppressed} head finding(s)",
                err=True,
            )

    populate_fingerprints(base_findings)
    populate_fingerprints(head_findings)

    cs = classify(base_findings, head_findings)

    if output_format == "github-pr-comment":
        body = render_pr_comment(cs, repo=repo, sha=sha)
    elif output_format == "sarif":
        body = json.dumps(
            _render_diff_sarif(
                cs,
                target_path=target_path,
                scan_types=parsed_types,
                base_ref=base_ref,
                head_ref=head_ref or resolved_head_sha,
            ),
            indent=2,
            default=str,
        )
    elif output_format == "json":
        body = json.dumps(
            {
                "new": [f.model_dump(mode="json") for f in cs.new],
                "fixed": [f.model_dump(mode="json") for f in cs.fixed],
                "unchanged_count": len(cs.unchanged),
            },
            indent=2,
            default=str,
        )
    else:
        body = _render_diff_text(cs)

    if output_file is not None:
        Path(output_file).write_text(body)
    else:
        typer.echo(body, nl=False)

    if fail_on_severity:
        threshold_sev = _SEVERITY_THRESHOLD_MAP.get(fail_on_severity.lower())
        if threshold_sev is None:
            typer.echo(
                f"diff: invalid --fail-on-severity {fail_on_severity!r}. "
                "Use critical, high, medium, low, or info.",
                err=True,
            )
            raise typer.Exit(code=2)
        offending = count_at_or_above(cs.new, threshold_sev)
        if offending > 0:
            raise typer.Exit(code=1)

    raise typer.Exit(code=0)


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
    uvicorn.run("securescan.main:app", host=host, port=port, reload=False)


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


@app.command()
def baseline(
    target_path: str = typer.Argument(".", help="Path to scan."),
    output_file: Path = typer.Option(
        Path(".securescan/baseline.json"),
        "--output-file",
        "-o",
        help="Where to write the baseline JSON. Default: <repo>/.securescan/baseline.json",
    ),
    scan_types: list[ScanType] = typer.Option([ScanType.CODE], "--type"),
    no_ai: bool = typer.Option(
        True,
        "--no-ai/--ai",
        help="Default: skip AI enrichment for deterministic baselines.",
    ),
):
    """Write a canonicalized baseline JSON of the current scan results.

    The baseline is what ``securescan compare`` and ``securescan diff
    --baseline`` consume. Output is byte-deterministic: same input ->
    same bytes, so checking the baseline into git yields readable
    diffs over time rather than churn from wall-clock or unstable
    ordering.

    AI enrichment is **off by default** in baseline mode (the opposite
    of ``securescan scan``): a baseline is the canonical "what was the
    posture at time T" artifact, and AI summaries / remediation text
    are non-deterministic, so leaving them out keeps re-running
    ``securescan baseline`` against the same tree producing the same
    bytes. Pass ``--ai`` to opt back in.
    """
    enable_ai = not no_ai

    findings = asyncio.run(
        _run_scan_for_diff(
            target_path,
            list(scan_types),
            enable_ai=enable_ai,
        )
    )

    populate_fingerprints(findings)

    bytes_written = _write_baseline_file(
        findings,
        target_path=Path(target_path),
        scan_types=list(scan_types),
        output_file=Path(output_file),
    )

    print(
        f"Wrote baseline to {output_file} "
        f"({len(findings)} findings, {bytes_written} bytes)",
        file=sys.stderr,
    )
    raise typer.Exit(code=0)


if __name__ == "__main__":
    app()
