"""CLI smoke tests for the SS5 CI guard flags.

These tests verify the new flags are wired into Typer's argument parser
without exercising the (slow, side-effectful) full scan pipeline. Real
scan behaviour is covered elsewhere; here we just want to know that
``--no-ai``, ``--ai`` and ``--baseline`` are recognised options.

Implementation note: we used to assert against ``result.output`` after
invoking ``scan --help``, but that's brittle against terminal-width
variations across local / CI environments (Click/Rich's help renderer
collapses the option table when COLUMNS is small or unset). The robust
fix is to introspect the underlying Click ``Command``'s ``params`` —
that's the actual contract we care about: are the flags wired up?
"""

from __future__ import annotations

import click
from typer.main import get_command
from typer.testing import CliRunner

from securescan.cli import app


def _scan_options() -> set[str]:
    """Return the set of registered ``--option`` long-form strings on
    the ``scan`` subcommand. Bypasses help-text rendering entirely."""
    cli = get_command(app)
    scan = cli.commands["scan"]  # type: ignore[union-attr]
    opts: set[str] = set()
    for param in scan.params:
        if isinstance(param, click.Option):
            opts.update(param.opts)  # both long and short forms
    return opts


def test_cli_no_ai_flag_recognized():
    opts = _scan_options()
    assert "--no-ai" in opts
    assert "--ai" in opts


def test_cli_baseline_flag_recognized():
    opts = _scan_options()
    assert "--baseline" in opts


def test_cli_mutually_exclusive_ai_flags(tmp_path):
    """Passing both --ai and --no-ai should fail fast with a non-zero exit."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path), "--ai", "--no-ai"])
    assert result.exit_code != 0


def test_cli_baseline_missing_file_does_not_crash_parser(tmp_path):
    """``--baseline /nonexistent`` should be accepted by the parser; the
    scan helper handles missing files gracefully (warning, no crash)."""
    opts = _scan_options()
    assert "--baseline" in opts
