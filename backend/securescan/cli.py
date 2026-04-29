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
from .exporters import (
    findings_to_csv,
    findings_to_json,
    findings_to_junit,
    findings_to_sarif,
)
from .fingerprint import populate_fingerprints
from .git_ops import (
    GitOpError,
    checkout as git_checkout,
    current_ref as git_current_ref,
    diff_text as git_diff_text,
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
from .render_review import render_review_json
from .scanners import ALL_SCANNERS, get_scanners_for_types
from .scoring import build_summary
from .threshold import count_at_or_above
from .ai import AIEnricher
from .config_file import SecureScanConfig, load_config
from .config_lint import LintReport, lint_config
from .ordering import sort_findings_canonical
from .pipeline import apply_pipeline

app = typer.Typer(name="securescan", help="AI-powered security scanning CLI")
config_app = typer.Typer(
    help="Manage .securescan.yml configuration.",
    no_args_is_help=True,
)
app.add_typer(config_app, name="config")
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


def should_run_ai(
    *,
    explicit_ai: bool,
    explicit_no_ai: bool,
    ci_env: str,
    config_ai: bool | None = None,
) -> bool:
    """Decide whether AI enrichment should run for a given invocation.

    Truth table (highest precedence first):

    * ``--ai``       wins                -> True
    * ``--no-ai``    wins                -> False
    * ``config_ai`` is not None          -> bool value (config wins)
    * ``CI`` env in {"true","1"}         -> False  (deterministic in CI)
    * otherwise                          -> True   (legacy default off-CI)

    ``ci_env`` is the raw string value of the ``CI`` environment
    variable (or empty string when unset). Pure-functional so tests
    don't need to mutate ``os.environ``.

    ``config_ai`` is the resolved ``ai`` field of ``.securescan.yml``
    (``None`` when the key is absent or no config file was found).
    Setting ``ai: false`` in the repo config force-disables AI even
    outside CI; setting ``ai: true`` force-enables it even on CI.
    Explicit CLI flags still win over both.
    """
    if explicit_ai:
        return True
    if explicit_no_ai:
        return False
    if config_ai is not None:
        return config_ai
    if (ci_env or "").lower() in ("true", "1"):
        return False
    return True


def diff_should_run_ai(
    *,
    explicit_ai: bool,
    explicit_no_ai: bool,
    config_ai: bool | None = None,
) -> bool:
    """AI gate for ``securescan diff`` / ``compare``. Differs from
    ``should_run_ai`` only in the default arm: AI is **off by default**
    in diff/compare mode even outside CI, because both are fundamentally
    CI/automation surfaces (PR comments must be byte-identical across
    re-runs to enable upsert). The user opts back in with ``--ai``.

    Truth table (highest precedence first):

    * ``--ai``                    -> True
    * ``--no-ai``                 -> False
    * ``config_ai`` is not None   -> bool value (config wins)
    * neither                     -> False  (the diff-mode default)

    Flag mutex (``--ai && --no-ai``) is rejected at the CLI layer
    before this helper is consulted.
    """
    if explicit_ai:
        return True
    if explicit_no_ai:
        return False
    if config_ai is not None:
        return config_ai
    return False


def _load_resolved_config(target_path: str) -> tuple[SecureScanConfig, Path | None]:
    """Load and path-resolve the ``.securescan.yml`` for ``target_path``.

    Used by every CLI subcommand that needs the config *before* the
    scanner pass (for the AI gate and for forwarding ``semgrep_rules``
    to the Semgrep scanner). The result is then re-used by
    :func:`apply_pipeline` via its ``config=`` parameter so we don't
    walk the filesystem twice per invocation.

    Returns ``(resolved_config, found_path)``. When no config file is
    present, ``found_path`` is ``None`` and the returned config is the
    default :class:`SecureScanConfig` resolved against
    ``target_path.resolve()`` (semgrep_rules will be empty in that
    case so the resolution base doesn't matter, but we use the
    target path for predictability).
    """
    target = Path(target_path)
    cfg, found = load_config(start_dir=target)
    base = found.parent if found is not None else target.resolve()
    return cfg.resolve_paths(base), found


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
    scanner_kwargs: dict | None = None,
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
    see ``diff_should_run_ai``). ``scanner_kwargs`` is forwarded to
    every scanner's ``scan()`` call (used by TS10 to plumb
    ``semgrep_rules`` from ``.securescan.yml``); unknown keys are
    swallowed by each scanner's ``**kwargs`` accept-all signature.
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
        kwargs = scanner_kwargs or {}

        async def _run_one(s):
            return await s.scan(target_path, scan_id, **kwargs)

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


def _print_findings(
    findings: list[Finding], *, show_suppressed: bool = False
) -> None:
    if not show_suppressed:
        findings = [
            f for f in findings
            if not (isinstance(getattr(f, "metadata", None), dict)
                    and f.metadata.get("suppressed_by"))
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
        "table",
        "--output",
        "-o",
        help=(
            "Output format: table, json, sarif, csv, junit, "
            "report-html, report-pdf. The github-review payload is "
            "NOT supported here -- inline review comments need a "
            "PR base+head diff context to anchor against; use "
            "`securescan diff` or `securescan compare` for that."
        ),
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
    show_suppressed: Optional[bool] = typer.Option(
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

    types = scan_type if scan_type else [ScanType.CODE, ScanType.DEPENDENCY, ScanType.IAC, ScanType.BASELINE]
    console.print(f"\n[bold]🔍 SecureScan — scanning {target_path}[/bold]\n")

    # TS10: load + path-resolve .securescan.yml ONCE up front. The same
    # config object feeds (a) the AI gate via ``config_ai``, (b) the
    # Semgrep custom-rule plumbing via ``scanner_kwargs``, and (c) the
    # post-scan ``apply_pipeline`` (severity overrides + suppression).
    # A single load avoids re-walking the filesystem and guarantees all
    # three observers see the same effective config for the run.
    resolved_config, found_config_path = _load_resolved_config(target_path)
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
            f"Suppressed {len(pipeline.suppressed)} finding(s) "
            f"(inline + config + baseline)",
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
    effective_show_suppressed = _default_show_suppressed(
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
        output_content = findings_to_json(
            findings, show_suppressed=effective_show_suppressed
        )
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
        output_content = findings_to_csv(
            findings, show_suppressed=effective_show_suppressed
        )
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
            console.print(f"[red]Invalid severity: {fail_on_severity}. Use critical, high, medium, or low.[/red]")
            raise typer.Exit(code=1)
        offending = count_at_or_above(gate_findings, threshold_sev)
        if offending > 0:
            console.print(
                f"[bold red]✗ Failing: found {offending} finding(s) at or above threshold '{severity_threshold}'[/bold red]"
            )
            raise typer.Exit(code=1)

    if fail_on_count is not None and len(gate_findings) > fail_on_count:
        console.print(f"[bold red]✗ Failing: {len(gate_findings)} findings exceed threshold of {fail_on_count}[/bold red]")
        raise typer.Exit(code=1)


_SEVERITY_THRESHOLD_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _render_diff_text(cs: ChangeSet, *, show_suppressed: bool = False) -> str:
    """Render a ``ChangeSet`` as plain-text suitable for a human terminal.

    Format is intentionally minimal so it fits on a single screen for
    typical PR-sized diffs:

        SecureScan diff: <N> new, <M> fixed, <K> unchanged

        New findings:
          [CRITICAL] <title> (<file>:<line>)
          ...

    No ANSI colour, no Markdown, no emojis. The PR-comment renderer
    handles the GitHub case; this is the local-development case.

    When ``show_suppressed`` is True, suppressed findings are included
    in the listing with a ``[SUPPRESSED:<reason>]`` prefix on the
    title; the leading-line counts ("N new, M fixed") reflect the
    pre-filter totals so the developer sees the full picture. When
    False (the CI / pipe default), suppressed findings are filtered
    out entirely and the counts reflect only what is shown.
    """
    new_findings = list(cs.new)
    fixed_findings = list(cs.fixed)
    if not show_suppressed:
        new_findings = [
            f for f in new_findings
            if not (isinstance(getattr(f, "metadata", None), dict)
                    and f.metadata.get("suppressed_by"))
        ]
        fixed_findings = [
            f for f in fixed_findings
            if not (isinstance(getattr(f, "metadata", None), dict)
                    and f.metadata.get("suppressed_by"))
        ]

    lines: list[str] = [
        f"SecureScan diff: {len(new_findings)} new, {len(fixed_findings)} fixed, "
        f"{len(cs.unchanged)} unchanged"
    ]
    if not new_findings and not fixed_findings:
        lines.append("")
        lines.append("No new or fixed findings.")
        return "\n".join(lines) + "\n"

    if new_findings:
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
            for f in new_findings:
                if f.severity != sev:
                    continue
                loc = ""
                if f.file_path:
                    loc = f" ({f.file_path}"
                    if f.line_start:
                        loc += f":{f.line_start}"
                    loc += ")"
                prefix = ""
                if show_suppressed:
                    metadata = getattr(f, "metadata", None)
                    if isinstance(metadata, dict):
                        reason = metadata.get("suppressed_by")
                        if isinstance(reason, str) and reason:
                            prefix = f"[SUPPRESSED:{reason}] "
                lines.append(f"  [{sev.value.upper()}] {prefix}{f.title}{loc}")

    if fixed_findings:
        lines.append("")
        lines.append(f"Fixed findings: {len(fixed_findings)}")

    return "\n".join(lines) + "\n"


def _render_compare_text(cs: ChangeSet, *, show_suppressed: bool = False) -> str:
    """Render a ``ChangeSet`` as plain-text for ``securescan compare``.

    Counterpart of ``_render_diff_text`` with compare-mode wording:
    ``DISAPPEARED`` instead of ``fixed``, ``still present`` instead of
    ``unchanged``. Same minimal single-screen format, no Markdown, no
    ANSI, no emojis.

    ``show_suppressed`` semantics match :func:`_render_diff_text`:
    True includes suppressed findings prefixed with
    ``[SUPPRESSED:<reason>]``; False (default for non-TTY / CI)
    filters them out and the counts reflect only the visible subset.
    """
    new_findings = list(cs.new)
    fixed_findings = list(cs.fixed)
    if not show_suppressed:
        new_findings = [
            f for f in new_findings
            if not (isinstance(getattr(f, "metadata", None), dict)
                    and f.metadata.get("suppressed_by"))
        ]
        fixed_findings = [
            f for f in fixed_findings
            if not (isinstance(getattr(f, "metadata", None), dict)
                    and f.metadata.get("suppressed_by"))
        ]

    lines: list[str] = [
        f"SecureScan compare: {len(new_findings)} new since baseline, "
        f"{len(fixed_findings)} disappeared, {len(cs.unchanged)} still present"
    ]
    if not new_findings and not fixed_findings:
        lines.append("")
        lines.append("No drift since baseline.")
        return "\n".join(lines) + "\n"

    severity_order = (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    )

    def _render_bucket(bucket: list[Finding]) -> None:
        for sev in severity_order:
            for f in bucket:
                if f.severity != sev:
                    continue
                loc = ""
                if f.file_path:
                    loc = f" ({f.file_path}"
                    if f.line_start:
                        loc += f":{f.line_start}"
                    loc += ")"
                prefix = ""
                if show_suppressed:
                    metadata = getattr(f, "metadata", None)
                    if isinstance(metadata, dict):
                        reason = metadata.get("suppressed_by")
                        if isinstance(reason, str) and reason:
                            prefix = f"[SUPPRESSED:{reason}] "
                lines.append(f"  [{sev.value.upper()}] {prefix}{f.title}{loc}")

    if new_findings:
        lines.append("")
        lines.append("New since baseline:")
        _render_bucket(new_findings)

    if fixed_findings:
        lines.append("")
        lines.append("Disappeared from baseline (drift?):")
        _render_bucket(fixed_findings)

    return "\n".join(lines) + "\n"


def _render_diff_sarif(
    cs: ChangeSet,
    *,
    target_path: str,
    scan_types: list[ScanType],
    base_ref: str | None,
    head_ref: str | None,
    show_suppressed: bool = False,
) -> dict:
    """Render the NEW findings of a changeset as a SARIF document.

    Decision: SARIF for diff mode is **NEW only**. Fixed findings are
    not security alerts; emitting them would generate spurious
    "resolved alert" noise on the GitHub Security tab. The
    ``invocations[].properties`` block records ``diffMode: true`` plus
    the base / head refs so a downstream consumer can tell this isn't a
    full scan upload.

    ``show_suppressed`` is forwarded to :func:`findings_to_sarif`:
    default False filters suppressed findings out of the SARIF, True
    includes them with a per-result ``properties.suppressed_by``
    field. SARIF's ``suppressions`` array is intentionally not used --
    inline properties travel with the result and don't require the
    consumer to cross-reference a separate top-level array.
    """
    diff_scan = Scan(
        target_path=target_path,
        scan_types=scan_types or [ScanType.CODE],
        status=ScanStatus.COMPLETED,
    )
    sarif = findings_to_sarif(cs.new, diff_scan, show_suppressed=show_suppressed)
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


_REVIEW_EVENTS: tuple[str, ...] = ("COMMENT", "REQUEST_CHANGES", "APPROVE")


def _validate_review_event(event: str, *, subcommand: str) -> str:
    """Validate ``--review-event`` against the GitHub Reviews API enum.

    Pure validator (no side effects). Returns the value verbatim on
    success; on failure echoes a helpful stderr line and raises
    :class:`typer.Exit`. Centralised so both ``diff`` and ``compare``
    surface the same error wording when a user typos the event name.
    """
    if event not in _REVIEW_EVENTS:
        typer.echo(
            f"{subcommand}: invalid --review-event {event!r}. "
            f"Choose {' | '.join(_REVIEW_EVENTS)}.",
            err=True,
        )
        raise typer.Exit(code=2)
    return event


def _require_github_review_inputs(
    *,
    subcommand: str,
    repo: str | None,
    sha: str | None,
    base_sha: str | None,
) -> None:
    """Gate the ``--output github-review`` path on its required inputs.

    The Reviews API call needs ``repo``, ``sha`` (the head commit the
    review is anchored to), and ``base_sha`` (the commit the diff is
    computed against, so :mod:`securescan.diff_position` can resolve
    line numbers to diff positions). Each is independently required;
    we surface ALL missing ones in a single message rather than the
    user iterating one at a time.

    Env fallbacks (``GITHUB_REPOSITORY`` / ``GITHUB_SHA``) are wired
    via typer's ``envvar=`` on the option itself, so by the time we
    get here the value is either explicit-or-env or genuinely
    missing.
    """
    missing: list[str] = []
    if not repo:
        missing.append("--repo (or GITHUB_REPOSITORY)")
    if not sha:
        missing.append("--sha (or GITHUB_SHA)")
    if not base_sha:
        missing.append("--base-sha")
    if missing:
        typer.echo(
            f"{subcommand}: --output github-review requires "
            + ", ".join(missing)
            + ".",
            err=True,
        )
        raise typer.Exit(code=2)


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


def _default_show_suppressed(
    *, explicit: bool | None, output_format: str
) -> bool:
    """Resolve the effective ``show_suppressed`` value for a renderer call.

    When ``explicit`` is non-``None``, the user passed
    ``--show-suppressed`` or ``--hide-suppressed`` and that value wins
    verbatim. Otherwise the default depends on the output format and
    whether stdout is a TTY:

    - Text output (``text`` / ``table``) on a TTY -> ``True``. The dev
      is at a terminal running ``securescan diff`` locally; they need
      to see what would be silenced in CI so they can audit it.
    - Everything else (``github-pr-comment``, ``sarif``, ``json``,
      ``csv``, ``junit``, or text on a non-TTY pipe) -> ``False``.
      CI / piped output stays clean by default; the explicit flag
      turns it back on for audits.

    Pure function. Same inputs (and same ``sys.stdout.isatty()``
    state) -> same output.
    """
    if explicit is not None:
        return explicit
    if output_format in {"text", "table"} and sys.stdout.isatty():
        return True
    return False


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
            "Output format: github-pr-comment | github-review | sarif "
            "| json | text. Default: github-pr-comment when stdout is "
            "piped, text on a TTY. ``github-review`` emits the GitHub "
            "Reviews API JSON the action's post-review.sh POSTs."
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
        help=(
            "owner/repo for github-pr-comment links AND the "
            "github-review payload. Falls back to $GITHUB_REPOSITORY."
        ),
    ),
    sha: Optional[str] = typer.Option(
        None,
        "--sha",
        envvar="GITHUB_SHA",
        help=(
            "Commit sha for github-pr-comment links AND the "
            "github-review ``commit_id`` (the head sha the review is "
            "anchored to). Falls back to $GITHUB_SHA."
        ),
    ),
    base_sha: Optional[str] = typer.Option(
        None,
        "--base-sha",
        help=(
            "Base commit sha for github-review's `git diff` "
            "resolution. In ref-mode auto-resolved from --base-ref "
            "via `git rev-parse`; in snapshot-mode required (or "
            "set $GITHUB_BASE_REF, which we resolve via git)."
        ),
    ),
    review_event: str = typer.Option(
        "COMMENT",
        "--review-event",
        help=(
            "GitHub Reviews API event for --output github-review: "
            "COMMENT | REQUEST_CHANGES | APPROVE. Default COMMENT."
        ),
    ),
    no_suggestions: bool = typer.Option(
        False,
        "--no-suggestions",
        help=(
            "Drop GitHub `suggestion` fences from inline review "
            "comments (compact output). Default: suggestions on."
        ),
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
    show_suppressed: Optional[bool] = typer.Option(
        None,
        "--show-suppressed/--hide-suppressed",
        help=(
            "Include suppressed findings in output, marked with "
            "[SUPPRESSED:<reason>] prefix where supported. Default: "
            "auto -- shown on a TTY (text format) so devs see what CI "
            "would hide; hidden when piped or in non-text formats "
            "(github-pr-comment / sarif / json). Use --hide-suppressed "
            "to force hiding even on a TTY."
        ),
    ),
    no_suppress: bool = typer.Option(
        False,
        "--no-suppress",
        help=(
            "Disable all suppression mechanisms (config, inline "
            "comments, baseline). Use to debug what would otherwise "
            "be hidden. Wired through to SuppressionContext; the "
            "diff-time application is owned by TS10."
        ),
    ),
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
    if output_format not in {"github-pr-comment", "github-review", "sarif", "json", "text"}:
        typer.echo(
            f"diff: unknown --output {output_format!r}. "
            "Choose github-pr-comment | github-review | sarif | json | text.",
            err=True,
        )
        raise typer.Exit(code=2)

    # Validate --review-event up-front (before any git work / scan)
    # so a typo on the new --output github-review path fails fast.
    if output_format == "github-review":
        _validate_review_event(review_event, subcommand="diff")

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

    # TS10: load + path-resolve .securescan.yml ONCE up front, before
    # the scanner pass. Same instance feeds (a) the AI gate via
    # ``config_ai``, (b) the Semgrep custom-rule plumbing via
    # ``scanner_kwargs``, and (c) the post-scan ``apply_pipeline``
    # invocations on each side of the diff.
    resolved_config, found_config_path = _load_resolved_config(target_path)
    if found_config_path is not None:
        typer.echo(f"diff: loaded config from {found_config_path}", err=True)

    enable_ai = diff_should_run_ai(
        explicit_ai=ai,
        explicit_no_ai=no_ai,
        config_ai=resolved_config.ai,
    )

    scanner_kwargs: dict = {}
    if resolved_config.semgrep_rules:
        scanner_kwargs["semgrep_rules"] = resolved_config.semgrep_rules

    resolved_head_sha: str | None = None
    resolved_base_sha: str | None = None

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
            resolved_base_sha = base_resolved_sha
        except GitOpError as exc:
            typer.echo(f"diff: {exc}", err=True)
            raise typer.Exit(code=2)

        try:
            try:
                git_checkout(target, base_resolved_sha)
                base_findings = asyncio.run(
                    _run_scan_for_diff(
                        str(target),
                        parsed_types,
                        enable_ai=enable_ai,
                        scanner_kwargs=scanner_kwargs,
                    )
                )
                git_checkout(target, resolved_head_sha)
                head_findings = asyncio.run(
                    _run_scan_for_diff(
                        str(target),
                        parsed_types,
                        enable_ai=enable_ai,
                        scanner_kwargs=scanner_kwargs,
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
    if base_sha is None and resolved_base_sha:
        base_sha = resolved_base_sha
    # Snapshot-mode fallback: GITHUB_BASE_REF (the action ships it as
    # the PR's base ref name, e.g. ``main``); resolve it via git when
    # the target is a real repo. We don't apply this in ref-mode
    # because ref-mode already pinned ``--base-ref``.
    if base_sha is None and have_snap_inputs:
        env_base_ref = os.environ.get("GITHUB_BASE_REF") or ""
        if env_base_ref:
            target = Path(target_path).resolve()
            if is_git_repo(target):
                try:
                    base_sha = git_rev_parse(target, env_base_ref)
                except GitOpError:
                    pass

    # TS10: apply the pipeline to BOTH sides of the diff. Config and
    # baseline rules apply uniformly across both; running them
    # symmetrically is what lets the fingerprint-based classifier
    # ("new" / "fixed" / "unchanged") downstream stay agnostic of
    # suppression. In snapshot mode the inputs may already carry
    # ``suppressed_by`` stamps from a previous run -- the pipeline is
    # idempotent (TS3 contract) so we re-apply anyway, which lets a
    # config change since the snapshot was generated take effect.
    base_pipeline = apply_pipeline(
        base_findings,
        target_path=Path(target_path),
        baseline_path=baseline,
        no_suppress=no_suppress,
        config=resolved_config,
    )
    head_pipeline = apply_pipeline(
        head_findings,
        target_path=Path(target_path),
        baseline_path=baseline,
        no_suppress=no_suppress,
        config=resolved_config,
    )
    if base_pipeline.suppressed or head_pipeline.suppressed:
        typer.echo(
            f"diff: suppressed "
            f"{len(base_pipeline.suppressed)} base / "
            f"{len(head_pipeline.suppressed)} head finding(s) "
            "(inline + config + baseline)",
            err=True,
        )

    # Feed kept + suppressed to the classifier so the suppression
    # stamps survive into the ChangeSet; the renderers then filter on
    # ``show_suppressed``. Failure-gate counts only the kept side
    # below.
    base_findings = base_pipeline.kept + base_pipeline.suppressed
    head_findings = head_pipeline.kept + head_pipeline.suppressed

    cs = classify(base_findings, head_findings)

    # TS10: the show_suppressed flag is now backed by real
    # ``metadata['suppressed_by']`` stamps from the pipeline above, so
    # the renderer's filter / label paths actually have something to
    # filter / label.
    effective_show_suppressed = _default_show_suppressed(
        explicit=show_suppressed, output_format=output_format
    )

    if output_format == "github-pr-comment":
        body = render_pr_comment(
            cs,
            repo=repo,
            sha=sha,
            show_suppressed=effective_show_suppressed,
        )
    elif output_format == "github-review":
        # The Reviews API needs ``commit_id`` (head sha) and a
        # base..head unified diff for position resolution. We
        # require all three of repo + sha + base-sha up front;
        # without them the payload is either invalid or anchors
        # every finding in the body fallback (silent degradation).
        _require_github_review_inputs(
            subcommand="diff",
            repo=repo,
            sha=sha,
            base_sha=base_sha,
        )
        target = Path(target_path).resolve()
        if not is_git_repo(target):
            typer.echo(
                f"diff: --output github-review requires a git "
                f"working tree at {target}; got a non-git path. "
                f"Either run against a real repo or switch "
                f"--output to github-pr-comment / sarif / json / text.",
                err=True,
            )
            raise typer.Exit(code=2)
        try:
            diff_unified = git_diff_text(target, base_sha, sha)
        except GitOpError as exc:
            typer.echo(f"diff: {exc}", err=True)
            raise typer.Exit(code=2)
        body = render_review_json(
            changeset=cs,
            commit_id=sha,
            diff_text=diff_unified,
            mode="diff",
            event=review_event,
            repo=repo,
            include_suggestions=not no_suggestions,
        )
    elif output_format == "sarif":
        body = json.dumps(
            _render_diff_sarif(
                cs,
                target_path=target_path,
                scan_types=parsed_types,
                base_ref=base_ref,
                head_ref=head_ref or resolved_head_sha,
                show_suppressed=effective_show_suppressed,
            ),
            indent=2,
            default=str,
        )
    elif output_format == "json":
        if effective_show_suppressed:
            new_list = list(cs.new)
            fixed_list = list(cs.fixed)
            unchanged_count = len(cs.unchanged)
        else:
            new_list = [
                f for f in cs.new
                if not (isinstance(getattr(f, "metadata", None), dict)
                        and f.metadata.get("suppressed_by"))
            ]
            fixed_list = [
                f for f in cs.fixed
                if not (isinstance(getattr(f, "metadata", None), dict)
                        and f.metadata.get("suppressed_by"))
            ]
            # TS10: ``classify`` now operates on kept+suppressed (so the
            # ``suppressed_by`` audit stamps survive into the ChangeSet).
            # Keep the JSON output consumer-facing-consistent: when
            # show_suppressed=False, ``unchanged_count`` reflects only
            # the user-visible unchanged findings, mirroring the
            # filtered ``new`` / ``fixed`` lists.
            unchanged_count = sum(
                1 for f in cs.unchanged
                if not (isinstance(getattr(f, "metadata", None), dict)
                        and f.metadata.get("suppressed_by"))
            )
        body = json.dumps(
            {
                "new": [f.model_dump(mode="json") for f in new_list],
                "fixed": [f.model_dump(mode="json") for f in fixed_list],
                "unchanged_count": unchanged_count,
            },
            indent=2,
            default=str,
        )
    else:
        body = _render_diff_text(cs, show_suppressed=effective_show_suppressed)

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
        # TS10: gate counts only non-suppressed new findings. A finding
        # the user has explicitly silenced via .securescan.yml / inline /
        # baseline is not allowed to fail CI.
        gate_new = [
            f for f in cs.new
            if not (
                isinstance(getattr(f, "metadata", None), dict)
                and f.metadata.get("suppressed_by")
            )
        ]
        offending = count_at_or_above(gate_new, threshold_sev)
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


_SEVERITY_RANK_FOR_LINT: dict[str, int] = {
    "error": 0,
    "warning": 1,
    "info": 2,
}


def _print_lint_report(report: LintReport) -> None:
    """Render lint issues to stderr, grouped by severity.

    Errors first, then warnings, then info -- mirrors how compilers
    surface diagnostics. The summary line is the last thing on stderr
    so a reader skimming the tail still sees the totals.
    """

    grouped = sorted(
        report.issues,
        key=lambda issue: _SEVERITY_RANK_FOR_LINT.get(issue.severity, 99),
    )
    for issue in grouped:
        location = issue.location if issue.location else "-"
        print(f"{issue.severity}: {location}: {issue.message}", file=sys.stderr)

    n_errors = len(report.errors())
    n_warnings = len(report.warnings())
    n_info = len(report.info())

    def _plural(n: int, singular: str, plural: str) -> str:
        return f"{n} {singular if n == 1 else plural}"

    summary_label = "Config invalid" if report.has_errors else "Config valid"
    summary = (
        f"{summary_label}: "
        f"{_plural(n_errors, 'error', 'errors')}, "
        f"{_plural(n_warnings, 'warning', 'warnings')}, "
        f"{_plural(n_info, 'info issue', 'info issues')}."
    )
    print(summary, file=sys.stderr)


@config_app.command("validate")
def config_validate(
    config_path: Optional[Path] = typer.Argument(
        None,
        help=(
            "Path to the config file. Defaults to walking up from the "
            "current directory."
        ),
    ),
):
    """Lint the .securescan.yml configuration file.

    Catches typos in severity_overrides keys, missing semgrep_rules
    paths, ignore-vs-override collisions, and other semantic mistakes
    that the typed loader can't see. Warnings and info issues do not
    fail the exit code; only errors do.
    """

    if config_path is None:
        _, found_path = load_config()
        if found_path is None:
            print(
                "no .securescan.yml in this directory tree",
                file=sys.stderr,
            )
            raise typer.Exit(code=2)
        target = found_path
    else:
        target = config_path

    report = lint_config(target)
    _print_lint_report(report)

    if report.has_errors:
        raise typer.Exit(code=1)
@app.command()
def compare(
    target_path: str = typer.Argument(".", help="Path to scan."),
    baseline_path: Path = typer.Argument(
        ...,
        help=(
            "Path to a baseline findings JSON (from `securescan baseline` "
            "or `securescan scan --output json`)."
        ),
    ),
    scan_types: list[str] = typer.Option(
        ["code"],
        "--type",
        help="Scan types to run (repeatable).",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        help=(
            "Output format: github-pr-comment | github-review | sarif "
            "| json | text. Defaults to text on TTY, github-pr-comment "
            "when piped. ``github-review`` emits the GitHub Reviews "
            "API JSON the action's post-review.sh POSTs."
        ),
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        help="Write rendered output to a file instead of stdout.",
    ),
    repo: Optional[str] = typer.Option(
        None,
        "--repo",
        envvar="GITHUB_REPOSITORY",
        help=(
            "owner/repo for github-pr-comment links AND the "
            "github-review payload. Falls back to $GITHUB_REPOSITORY."
        ),
    ),
    sha: Optional[str] = typer.Option(
        None,
        "--sha",
        envvar="GITHUB_SHA",
        help=(
            "Commit sha for github-pr-comment links AND the "
            "github-review ``commit_id`` (the head sha the review is "
            "anchored to). Falls back to $GITHUB_SHA."
        ),
    ),
    base_sha: Optional[str] = typer.Option(
        None,
        "--base-sha",
        help=(
            "Base commit sha for github-review's `git diff` "
            "resolution. REQUIRED for compare's github-review path: "
            "we don't track which commit the baseline was scanned "
            "at (a v0.5 enhancement), so the user must assert it."
        ),
    ),
    review_event: str = typer.Option(
        "COMMENT",
        "--review-event",
        help=(
            "GitHub Reviews API event for --output github-review: "
            "COMMENT | REQUEST_CHANGES | APPROVE. Default COMMENT."
        ),
    ),
    no_suggestions: bool = typer.Option(
        False,
        "--no-suggestions",
        help=(
            "Drop GitHub `suggestion` fences from inline review "
            "comments (compact output). Default: suggestions on."
        ),
    ),
    no_ai: bool = typer.Option(False, "--no-ai"),
    ai: bool = typer.Option(False, "--ai"),
    show_suppressed: Optional[bool] = typer.Option(
        None,
        "--show-suppressed/--hide-suppressed",
        help=(
            "Include suppressed findings in output, marked with "
            "[SUPPRESSED:<reason>] prefix where supported. Default: "
            "auto -- shown on a TTY (text format) so devs see what CI "
            "would hide; hidden when piped or in non-text formats "
            "(github-pr-comment / sarif / json). Use --hide-suppressed "
            "to force hiding even on a TTY."
        ),
    ),
    no_suppress: bool = typer.Option(
        False,
        "--no-suppress",
        help=(
            "Disable all suppression mechanisms (config, inline "
            "comments, baseline). Use to debug what would otherwise "
            "be hidden. Wired through to SuppressionContext; the "
            "compare-time application is owned by TS10."
        ),
    ),
):
    """Compare current scan against a baseline; report what's NEW and what
    DISAPPEARED (drift).

    Like ``diff``, but instead of two refs you provide a saved baseline
    JSON file. New findings = present now, absent from baseline.
    Disappeared findings = present in baseline, absent now (probably
    fixed; could be silently suppressed via .securescan.yml or inline
    ignores). Both are worth flagging.

    PR-comment output uses the ``<!-- securescan:compare -->`` marker
    so it lives in its own upsert lane and doesn't collide with the
    ``securescan diff`` comment on the same PR.

    SARIF output emits NEW findings only. SARIF describes findings IN
    a scan, not their absence, so DISAPPEARED findings don't have a
    natural SARIF representation. Use json or github-pr-comment output
    if you need to surface drift.

    AI enrichment is off by default in compare mode (same rationale as
    ``diff``: PR-comment bodies must be byte-identical across re-runs
    to enable upsert). Pass ``--ai`` to opt back in.

    Pipeline scope: ``compare`` applies the current ``.securescan.yml``
    (severity overrides, ``ignored_rules``, inline ``# securescan:
    ignore`` directives) to the FRESH scan only. The baseline JSON is
    NOT re-filtered -- a baseline is what it is at write time, and
    re-running today's config against yesterday's baseline would
    silently rewrite history. If you want the baseline normalized to
    today's config, regenerate it with ``securescan baseline``.
    """
    if no_ai and ai:
        typer.echo("compare: --ai and --no-ai are mutually exclusive", err=True)
        raise typer.Exit(code=2)

    if not Path(baseline_path).exists():
        typer.echo(
            f"compare: baseline file not found: {baseline_path}\n"
            "compare: hint: generate one with `securescan baseline` or "
            "`securescan scan --output json --output-file baseline.json`",
            err=True,
        )
        raise typer.Exit(code=2)

    output_format = _resolve_default_output(output)
    if output_format not in {"github-pr-comment", "github-review", "sarif", "json", "text"}:
        typer.echo(
            f"compare: unknown --output {output_format!r}. "
            "Choose github-pr-comment | github-review | sarif | json | text.",
            err=True,
        )
        raise typer.Exit(code=2)

    if output_format == "github-review":
        _validate_review_event(review_event, subcommand="compare")

    parsed_types: list[ScanType] = []
    for raw_type in scan_types:
        try:
            parsed_types.append(ScanType(raw_type))
        except ValueError:
            typer.echo(
                f"compare: unknown --type {raw_type!r}. "
                f"Valid: {', '.join(t.value for t in ScanType)}",
                err=True,
            )
            raise typer.Exit(code=2)

    # TS10: load + path-resolve .securescan.yml ONCE up front. Same
    # instance feeds (a) the AI gate, (b) the Semgrep custom-rule
    # plumbing for the fresh scan, and (c) the post-scan
    # ``apply_pipeline`` on the FRESH side only.
    #
    # Compare deliberately does NOT re-filter the baseline JSON: the
    # baseline is a frozen artifact (it is what it is at write time --
    # see the ``securescan baseline`` command's docstring for the
    # determinism contract). Re-running today's config against
    # yesterday's baseline would silently rewrite history.
    resolved_config, found_config_path = _load_resolved_config(target_path)
    if found_config_path is not None:
        typer.echo(f"compare: loaded config from {found_config_path}", err=True)

    enable_ai = diff_should_run_ai(
        explicit_ai=ai,
        explicit_no_ai=no_ai,
        config_ai=resolved_config.ai,
    )

    scanner_kwargs: dict = {}
    if resolved_config.semgrep_rules:
        scanner_kwargs["semgrep_rules"] = resolved_config.semgrep_rules

    try:
        baseline_findings = load_findings_json(baseline_path)
    except (OSError, json.JSONDecodeError) as exc:
        typer.echo(f"compare: failed to load baseline: {exc}", err=True)
        raise typer.Exit(code=2)

    fresh_findings = asyncio.run(
        _run_scan_for_diff(
            target_path,
            parsed_types,
            enable_ai=enable_ai,
            scanner_kwargs=scanner_kwargs,
        )
    )

    populate_fingerprints(baseline_findings)

    # TS10: apply pipeline to FRESH side only (see comment above for the
    # baseline-is-frozen rationale).
    fresh_pipeline = apply_pipeline(
        fresh_findings,
        target_path=Path(target_path),
        baseline_path=None,  # baseline_path arg is for fingerprint-suppression; here the baseline is already the comparison axis
        no_suppress=no_suppress,
        config=resolved_config,
    )
    if fresh_pipeline.suppressed:
        typer.echo(
            f"compare: suppressed {len(fresh_pipeline.suppressed)} "
            "fresh finding(s) (inline + config)",
            err=True,
        )
    fresh_findings = fresh_pipeline.kept + fresh_pipeline.suppressed

    cs = classify(baseline_findings, fresh_findings)

    # TS10: show_suppressed is now backed by real
    # ``metadata['suppressed_by']`` stamps from the fresh-side pipeline
    # above; renderers can both filter (CI default) and label (TTY
    # default) accordingly.
    effective_show_suppressed = _default_show_suppressed(
        explicit=show_suppressed, output_format=output_format
    )

    if output_format == "github-pr-comment":
        body = render_pr_comment(
            cs,
            repo=repo,
            sha=sha,
            mode="compare",
            show_suppressed=effective_show_suppressed,
        )
    elif output_format == "github-review":
        # ``compare`` doesn't track the baseline's commit-id (the
        # baseline JSON is a frozen artifact; recording the sha it
        # was scanned at is a v0.5 enhancement). So --base-sha is
        # not auto-resolvable here -- we trust the user's assertion
        # of "what commit the baseline corresponds to".
        _require_github_review_inputs(
            subcommand="compare",
            repo=repo,
            sha=sha,
            base_sha=base_sha,
        )
        target = Path(target_path).resolve()
        if not is_git_repo(target):
            typer.echo(
                f"compare: --output github-review requires a git "
                f"working tree at {target}; got a non-git path. "
                f"Either run against a real repo or switch "
                f"--output to github-pr-comment / sarif / json / text.",
                err=True,
            )
            raise typer.Exit(code=2)
        try:
            diff_unified = git_diff_text(target, base_sha, sha)
        except GitOpError as exc:
            typer.echo(f"compare: {exc}", err=True)
            raise typer.Exit(code=2)
        body = render_review_json(
            changeset=cs,
            commit_id=sha,
            diff_text=diff_unified,
            mode="compare",
            event=review_event,
            repo=repo,
            include_suggestions=not no_suggestions,
        )
    elif output_format == "sarif":
        body = json.dumps(
            _render_diff_sarif(
                cs,
                target_path=target_path,
                scan_types=parsed_types,
                base_ref=None,
                head_ref=None,
                show_suppressed=effective_show_suppressed,
            ),
            indent=2,
            default=str,
        )
    elif output_format == "json":
        if effective_show_suppressed:
            new_list = list(cs.new)
            disappeared_list = list(cs.fixed)
            unchanged_count = len(cs.unchanged)
        else:
            new_list = [
                f for f in cs.new
                if not (isinstance(getattr(f, "metadata", None), dict)
                        and f.metadata.get("suppressed_by"))
            ]
            disappeared_list = [
                f for f in cs.fixed
                if not (isinstance(getattr(f, "metadata", None), dict)
                        and f.metadata.get("suppressed_by"))
            ]
            # TS10: see the matching note in ``diff`` -- when the fresh
            # side carries ``suppressed_by`` stamps, keep the JSON
            # ``unchanged_count`` aligned with the (filtered) ``new`` /
            # ``disappeared`` lists so consumers don't have to re-do
            # the filter themselves.
            unchanged_count = sum(
                1 for f in cs.unchanged
                if not (isinstance(getattr(f, "metadata", None), dict)
                        and f.metadata.get("suppressed_by"))
            )
        body = json.dumps(
            {
                "new": [f.model_dump(mode="json") for f in new_list],
                "disappeared": [f.model_dump(mode="json") for f in disappeared_list],
                "unchanged_count": unchanged_count,
            },
            indent=2,
            default=str,
        )
    else:
        body = _render_compare_text(cs, show_suppressed=effective_show_suppressed)

    if output_file is not None:
        Path(output_file).write_text(body)
    else:
        typer.echo(body, nl=False)

    raise typer.Exit(code=0)

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
