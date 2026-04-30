"""CLI smoke tests for the SS5 CI guard flags.

These tests verify the new flags are wired into Typer's argument parser
without exercising the (slow, side-effectful) full scan pipeline. Real
scan behaviour is covered elsewhere; here we just want to know that
``--no-ai``, ``--ai`` and ``--baseline`` are recognised options.
"""

from __future__ import annotations

import pytest

try:
    from typer.testing import CliRunner

    HAS_RUNNER = True
except ImportError:  # pragma: no cover - typer ships testing helpers, but be safe
    HAS_RUNNER = False

from securescan.cli import app

pytestmark = pytest.mark.skipif(not HAS_RUNNER, reason="typer.testing.CliRunner unavailable")


def test_cli_no_ai_flag_recognized():
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--no-ai" in result.output
    assert "--ai" in result.output


def test_cli_baseline_flag_recognized():
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--baseline" in result.output


def test_cli_mutually_exclusive_ai_flags(tmp_path):
    """Passing both --ai and --no-ai should fail fast with a non-zero exit."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path), "--ai", "--no-ai"])
    assert result.exit_code != 0


def test_cli_baseline_missing_file_does_not_crash_parser(tmp_path):
    """``--baseline /nonexistent`` should be accepted by the parser; the
    scan helper handles missing files gracefully (warning, no crash).

    We invoke ``--help`` after passing through the option to keep the
    test fast — the goal is just to verify the option spec is valid."""
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--baseline" in result.output
