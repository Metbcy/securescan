"""Tests for the scanner-tool discovery helper.

Regression for the v0.10.0 bug where `is_available()` in scanners
relied on `shutil.which()`, which only searches the system PATH —
missing tools installed in the venv that the backend itself runs out
of (e.g., `pip install bandit` inside `./venv` while uvicorn launches
via `./venv/bin/python`).
"""
import os
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from securescan.scanners.discovery import find_tool, tool_command_or_module


def test_find_tool_uses_path():
    """A binary on PATH is resolved via shutil.which (existing behavior)."""
    # `python` itself is always on PATH inside the venv.
    result = find_tool("python")
    if result is not None:
        assert os.path.isfile(result)


def test_find_tool_falls_back_to_venv_bin(tmp_path, monkeypatch):
    """When PATH doesn't contain the tool but it lives next to
    sys.executable, find_tool finds it. This is the bug fix: tools
    installed via `pip install X` inside the running venv are
    discoverable even though PATH doesn't include `./venv/bin/`."""
    fake_python = tmp_path / "python"
    fake_python.write_text("#!/bin/sh\nexec true\n")
    fake_python.chmod(0o755)

    fake_tool = tmp_path / "fake-scanner-only-here"
    fake_tool.write_text("#!/bin/sh\nexec true\n")
    fake_tool.chmod(0o755)

    # Empty PATH so shutil.which can't find anything.
    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(sys, "executable", str(fake_python))

    result = find_tool("fake-scanner-only-here")
    assert result == str(fake_tool)


def test_find_tool_does_not_resolve_symlinks(tmp_path, monkeypatch):
    """Regression: an early version of find_tool used Path.resolve(),
    which followed the venv's `python` → `/usr/bin/python3` symlink chain
    all the way to /usr/bin and missed the venv's own bin/. This test
    builds a venv-shaped layout and asserts find_tool stays in the
    venv directory.
    """
    venv_bin = tmp_path / "venv" / "bin"
    venv_bin.mkdir(parents=True)

    real_python = tmp_path / "real_python"
    real_python.write_text("#!/bin/sh\n")
    real_python.chmod(0o755)

    venv_python = venv_bin / "python"
    venv_python.symlink_to(real_python)  # mirror real venv layout

    fake_tool = venv_bin / "venv-only-tool"
    fake_tool.write_text("#!/bin/sh\n")
    fake_tool.chmod(0o755)

    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(sys, "executable", str(venv_python))

    result = find_tool("venv-only-tool")
    assert result == str(fake_tool), (
        f"expected {fake_tool}, got {result} — discovery resolved past the "
        f"symlink and missed the venv bin/"
    )


def test_find_tool_returns_none_for_nonexistent():
    assert find_tool("definitely-not-installed-anywhere-xyz") is None


def test_tool_command_or_module_prefers_binary(tmp_path, monkeypatch):
    """If the binary exists, prefer it over `python -m <module>`."""
    fake_python = tmp_path / "python"
    fake_python.write_text("")
    fake_python.chmod(0o755)
    fake_tool = tmp_path / "json"  # 'json' is also a stdlib module
    fake_tool.write_text("")
    fake_tool.chmod(0o755)

    monkeypatch.setenv("PATH", "")
    monkeypatch.setattr(sys, "executable", str(fake_python))

    result = tool_command_or_module("json")
    assert result == [str(fake_tool)]


def test_tool_command_or_module_falls_back_to_python_dash_m(monkeypatch):
    """When binary missing but module importable, return python -m form."""
    monkeypatch.setenv("PATH", "")
    # `json` is a stdlib module so importlib.util.find_spec finds it.
    result = tool_command_or_module("not-a-real-binary", module="json")
    assert result == [sys.executable, "-m", "json"]


def test_tool_command_or_module_returns_none_when_neither(monkeypatch):
    monkeypatch.setenv("PATH", "")
    result = tool_command_or_module("not-real", module="not-real-either")
    assert result is None
