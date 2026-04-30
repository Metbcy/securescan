"""``securescan baseline`` command.

Write a canonicalized baseline JSON capturing the current scan results;
the baseline is what ``securescan compare`` and ``securescan diff
--baseline`` consume.

The command function below is registered on the root Typer app by
:mod:`securescan.cli.__init__`.
"""

import asyncio
import sys
from pathlib import Path

import typer

from ..baseline_writer import write_baseline as _write_baseline_file
from ..fingerprint import populate_fingerprints
from ..models import ScanType
from . import _shared


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
        _shared._run_scan_for_diff(
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
        f"Wrote baseline to {output_file} ({len(findings)} findings, {bytes_written} bytes)",
        file=sys.stderr,
    )
    raise typer.Exit(code=0)
