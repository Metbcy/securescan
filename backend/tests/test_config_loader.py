"""Tests for :mod:`securescan.config_loader`.

Each test uses ``monkeypatch`` so HOME, XDG_CONFIG_HOME, and the keys
under test are scoped to the test — nothing leaks into the rest of the
suite.
"""
from __future__ import annotations

import os
from pathlib import Path

from securescan.config_loader import load_user_env


def _write_env(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


def test_load_user_env_xdg(tmp_path, monkeypatch):
    """When XDG_CONFIG_HOME is set, $XDG/securescan/.env is loaded."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("FOO", raising=False)
    env_file = tmp_path / "securescan" / ".env"
    _write_env(env_file, "FOO=bar\n")

    loaded = load_user_env()

    assert loaded == env_file
    assert os.environ["FOO"] == "bar"


def test_load_user_env_home_fallback(tmp_path, monkeypatch):
    """With XDG unset, ``~/.config/securescan/.env`` is loaded."""
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("FOO_HOME", raising=False)
    env_file = tmp_path / ".config" / "securescan" / ".env"
    _write_env(env_file, "FOO_HOME=fromhome\n")

    loaded = load_user_env()

    assert loaded == env_file
    assert os.environ["FOO_HOME"] == "fromhome"


def test_load_user_env_missing(tmp_path, monkeypatch):
    """No file anywhere → ``None`` and no exception."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))

    assert load_user_env() is None


def test_load_user_env_does_not_override_shell(tmp_path, monkeypatch):
    """Real shell env wins over the file (override=False)."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("FOO_PRECEDENCE", "shell")
    env_file = tmp_path / "securescan" / ".env"
    _write_env(env_file, "FOO_PRECEDENCE=file\n")

    loaded = load_user_env()

    assert loaded == env_file
    assert os.environ["FOO_PRECEDENCE"] == "shell"
