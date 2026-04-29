"""Tests for the ``securescan config validate`` CLI subcommand.

These exercise the user-facing surface: subcommand registration, exit
codes, stderr/stdout split, and the walk-up-vs-explicit-path branch.
The pure linter is covered in ``test_config_lint.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

try:
    from typer.testing import CliRunner
    HAS_RUNNER = True
except ImportError:  # pragma: no cover - typer ships testing helpers
    HAS_RUNNER = False

from securescan.cli import app

pytestmark = pytest.mark.skipif(
    not HAS_RUNNER, reason="typer.testing.CliRunner unavailable"
)


def _isolated_root(tmp_path: Path) -> Path:
    """Stop the walk-up at this directory by faking a ``.git`` marker."""
    (tmp_path / ".git").mkdir()
    return tmp_path


def _write_config(directory: Path, body: str, name: str = ".securescan.yml") -> Path:
    path = directory / name
    path.write_text(body, encoding="utf-8")
    return path


def test_config_validate_command_registered():
    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate", "--help"])
    assert result.exit_code == 0, result.output
    assert "validate" in result.output.lower()


def test_config_validate_no_file_in_tree_exits_2(tmp_path, monkeypatch):
    root = _isolated_root(tmp_path)
    monkeypatch.chdir(root)

    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate"])

    assert result.exit_code == 2
    assert "no .securescan.yml" in result.stderr


def test_config_validate_valid_file_exits_0(tmp_path):
    cfg = _write_config(
        tmp_path,
        """
severity_overrides:
  SEMGREP-XYZ: medium
ignored_rules:
  - python.lang.security.audit.x
""",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate", str(cfg)])

    assert result.exit_code == 0, result.stderr
    assert "Config valid" in result.stderr


def test_config_validate_invalid_file_exits_1(tmp_path):
    cfg = _write_config(
        tmp_path,
        """
severity_overrides:
  RULE-A: not-a-real-severity
""",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate", str(cfg)])

    assert result.exit_code == 1
    assert "error" in result.stderr.lower()


def test_config_validate_warnings_only_exits_0(tmp_path):
    cfg = _write_config(
        tmp_path,
        """
severity_overrides:
  RULE-COLLISION: medium
ignored_rules:
  - RULE-COLLISION
""",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate", str(cfg)])

    assert result.exit_code == 0, result.stderr
    assert "warning" in result.stderr.lower()


def test_config_validate_explicit_path_does_not_walk_up(tmp_path, monkeypatch):
    """When the user pins an explicit path we lint that file even if a
    different config exists higher in the tree."""

    parent = _isolated_root(tmp_path)
    _write_config(
        parent,
        """
semgrep_rules:
  - /nonexistent/some-rules.yml
""",
    )

    child = parent / "child"
    child.mkdir()
    explicit = _write_config(
        child,
        """
severity_overrides:
  SEMGREP-OK: medium
""",
        name="pinned.yml",
    )

    monkeypatch.chdir(child)

    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate", str(explicit)])

    # The pinned file is fine. The walk-up file would have errored.
    assert result.exit_code == 0, result.stderr
    assert "some-rules.yml" not in result.stderr


def test_config_validate_prints_to_stderr(tmp_path):
    cfg = _write_config(
        tmp_path,
        """
severity_overrides:
  RULE-A: not-a-real-severity
""",
    )

    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate", str(cfg)])

    assert "error" in result.stderr.lower()
    assert result.stdout == ""


def test_config_validate_summary_line_present(tmp_path):
    cfg = _write_config(tmp_path, "severity_overrides: {}\n")

    runner = CliRunner()
    result = runner.invoke(app, ["config", "validate", str(cfg)])

    assert result.exit_code == 0
    assert "Config valid" in result.stderr
    assert "0 errors" in result.stderr
    assert "0 warnings" in result.stderr
