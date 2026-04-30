"""Tests for SemgrepScanner honoring user-supplied rule packs.

These tests do *not* invoke the real ``semgrep`` binary. Instead they
mock :func:`asyncio.create_subprocess_exec` and assert the constructed
argv, which is exactly what we need to verify: that the scanner threads
``config.semgrep_rules`` (delivered through ``**kwargs``) into the
right ``--config`` flags.
"""
from __future__ import annotations

import asyncio
import os

import pytest

from securescan.scanners import semgrep as semgrep_module
from securescan.scanners.semgrep import SemgrepScanner


class _FakeProc:
    """Minimal stand-in for ``asyncio.subprocess.Process``.

    ``SemgrepScanner.scan`` calls ``await proc.communicate()`` inside an
    ``asyncio.wait_for`` and json-decodes the stdout, so ``communicate``
    returns valid (empty-results) JSON to keep the happy-path code
    flowing through to a clean ``return findings``.
    """

    def __init__(self, stdout: bytes = b'{"results": []}', stderr: bytes = b"") -> None:
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, self._stderr


@pytest.fixture
def captured_argv(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Replace ``asyncio.create_subprocess_exec`` with a recorder.

    Returns a list that will be populated with the argv of every
    invocation. The scanner module imports ``asyncio`` at module scope
    and calls ``asyncio.create_subprocess_exec(...)``, so we patch that
    attribute on the imported module.
    """

    calls: list[list[str]] = []

    async def fake_create_subprocess_exec(*args, **_kwargs):
        calls.append(list(args))
        return _FakeProc()

    monkeypatch.setattr(
        semgrep_module.asyncio,
        "create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    return calls


# ---------------------------------------------------------------------------
# Default behavior: no custom rules => --config auto
# ---------------------------------------------------------------------------


def test_no_custom_rules_uses_config_auto(captured_argv, tmp_path):
    scanner = SemgrepScanner()
    asyncio.run(scanner.scan(str(tmp_path), scan_id="t", semgrep_rules=None))

    assert len(captured_argv) == 1
    argv = captured_argv[0]
    # exactly one --config and it points to auto
    assert argv.count("--config") == 1
    idx = argv.index("--config")
    assert argv[idx + 1] == "auto"


def test_no_kwargs_keeps_default_behavior(captured_argv, tmp_path):
    """Omitting ``semgrep_rules`` entirely is the same as passing None."""
    scanner = SemgrepScanner()
    asyncio.run(scanner.scan(str(tmp_path), scan_id="t"))

    argv = captured_argv[0]
    assert argv.count("--config") == 1
    assert argv[argv.index("--config") + 1] == "auto"


def test_empty_custom_rules_list_uses_config_auto(captured_argv, tmp_path):
    """An empty list is the same as None — backward compat."""
    scanner = SemgrepScanner()
    asyncio.run(scanner.scan(str(tmp_path), scan_id="t", semgrep_rules=[]))

    argv = captured_argv[0]
    assert argv.count("--config") == 1
    assert argv[argv.index("--config") + 1] == "auto"


# ---------------------------------------------------------------------------
# Custom rules => --config <path> (one flag per pack, no auto fallback)
# ---------------------------------------------------------------------------


def test_single_custom_rule_uses_config_path(captured_argv, tmp_path):
    rule_file = tmp_path / "rules.yml"
    rule_file.write_text("rules: []\n")

    scanner = SemgrepScanner()
    asyncio.run(scanner.scan(str(tmp_path), scan_id="t", semgrep_rules=[rule_file]))

    argv = captured_argv[0]
    assert argv.count("--config") == 1
    assert str(rule_file) in argv
    # critical: NO auto fallback
    assert "auto" not in argv


def test_multiple_custom_rules_uses_repeated_config_flags(captured_argv, tmp_path):
    a = tmp_path / "a.yml"
    a.write_text("rules: []\n")
    b = tmp_path / "b"
    b.mkdir()

    scanner = SemgrepScanner()
    asyncio.run(scanner.scan(str(tmp_path), scan_id="t", semgrep_rules=[a, b]))

    argv = captured_argv[0]
    # both paths threaded through
    assert str(a) in argv
    assert str(b) in argv
    # neither auto fallback nor implicit registry
    assert "auto" not in argv


def test_custom_rules_uses_repeated_config_flag_does_not_combine(
    captured_argv, tmp_path
):
    """Each rule pack must get its own ``--config`` flag.

    The opposite would be a single ``--config a.yml,b.yml`` token — we
    explicitly want two separate flags so Semgrep treats each as an
    independent rule source.
    """

    a = tmp_path / "a.yml"
    a.write_text("rules: []\n")
    b = tmp_path / "b.yml"
    b.write_text("rules: []\n")

    scanner = SemgrepScanner()
    asyncio.run(scanner.scan(str(tmp_path), scan_id="t", semgrep_rules=[a, b]))

    argv = captured_argv[0]
    # two distinct --config tokens
    assert argv.count("--config") == 2
    # each followed by its own path (no comma-joined value sneaking through)
    config_indices = [i for i, tok in enumerate(argv) if tok == "--config"]
    paths_after_config = {argv[i + 1] for i in config_indices}
    assert paths_after_config == {str(a), str(b)}
    # double-check no value contains a comma (the failure mode we're guarding)
    assert all("," not in argv[i + 1] for i in config_indices)


# ---------------------------------------------------------------------------
# Validation: missing paths fail fast
# ---------------------------------------------------------------------------


def test_missing_rule_path_raises_file_not_found(captured_argv, tmp_path):
    bogus = tmp_path / "does_not_exist.yml"

    scanner = SemgrepScanner()
    with pytest.raises(FileNotFoundError) as exc_info:
        asyncio.run(scanner.scan(str(tmp_path), scan_id="t", semgrep_rules=[bogus]))

    msg = str(exc_info.value)
    assert str(bogus) in msg
    # error must hint at the config-file resolution rule
    assert ".securescan.yml" in msg or "config" in msg.lower()
    # subprocess must not have been invoked — fail fast, not silent fallback
    assert captured_argv == []


def test_directory_rule_path_is_accepted(captured_argv, tmp_path):
    """Semgrep accepts directories as ``--config`` targets.

    A directory must not trigger ``FileNotFoundError`` and must be
    forwarded verbatim into argv.
    """

    rules_dir = tmp_path / "myrules"
    rules_dir.mkdir()

    scanner = SemgrepScanner()
    asyncio.run(scanner.scan(str(tmp_path), scan_id="t", semgrep_rules=[rules_dir]))

    argv = captured_argv[0]
    assert str(rules_dir) in argv
    assert argv.count("--config") == 1


# ---------------------------------------------------------------------------
# kwargs threading through BaseScanner interface
# ---------------------------------------------------------------------------


def test_kwargs_path_works_through_base_scanner_interface(captured_argv, tmp_path):
    """``BaseScanner.scan(target, scan_id, **kwargs)`` is the public surface.

    TS10 will eventually wire the loaded ``SecureScanConfig.semgrep_rules``
    into this kwarg, so we verify it travels through cleanly.
    """

    rule_file = tmp_path / "team-rules.yml"
    rule_file.write_text("rules: []\n")

    scanner: SemgrepScanner = SemgrepScanner()
    # exact call shape TS10 will use
    asyncio.run(
        scanner.scan(str(tmp_path), scan_id="test", semgrep_rules=[rule_file])
    )

    argv = captured_argv[0]
    assert "--config" in argv
    assert str(rule_file) in argv
    assert "auto" not in argv


# ---------------------------------------------------------------------------
# Argv shape sanity check (regression guard for backward-compat)
# ---------------------------------------------------------------------------


def test_argv_starts_with_semgrep_scan_json(captured_argv, tmp_path):
    """Guard the unchanged prefix: ``<resolved-semgrep-path> scan --json ...``.

    v0.10.1+: argv[0] is now the absolute path (resolved via
    `find_tool`) so the same backend that runs out of a venv finds
    pip-installed semgrep. The structural prefix `[bin, "scan", "--json"]`
    is unchanged.
    """

    scanner = SemgrepScanner()
    asyncio.run(scanner.scan(str(tmp_path), scan_id="t"))

    argv = captured_argv[0]
    assert os.path.basename(argv[0]) == "semgrep"
    assert argv[1:3] == ["scan", "--json"]
    # target_path is the last positional
    assert argv[-1] == str(tmp_path)


def test_target_path_is_last_with_custom_rules(captured_argv, tmp_path):
    rule_file = tmp_path / "rules.yml"
    rule_file.write_text("rules: []\n")

    scanner = SemgrepScanner()
    asyncio.run(
        scanner.scan(str(tmp_path), scan_id="t", semgrep_rules=[rule_file])
    )

    argv = captured_argv[0]
    assert argv[-1] == str(tmp_path)
    assert os.path.basename(argv[0]) == "semgrep"
    assert argv[1:3] == ["scan", "--json"]
