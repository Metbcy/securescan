"""Tests for the v0.11.0 pre-commit hook integration.

Covers:

* The new ``--staged`` flag on ``scan``
* The ``_resolve_staged_files`` helper (git happy / sad paths,
  deletions, missing files)
* The post-scan path-filter that drops findings outside the staged set
* The ``.pre-commit-hooks.yaml`` shape
* The ``pre-commit-securescan`` console-script registration

The full scan pipeline is heavy and is exercised elsewhere; here we
stub ``_run_scan_async`` so each test stays fast and deterministic.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from unittest import mock

import click
import pytest
import tomllib
import typer
import yaml
from typer.main import get_command
from typer.testing import CliRunner

from securescan.cli import app
from securescan.cli import scan as _scan_module
from securescan.cli.scan import _filter_findings_to_paths, _resolve_staged_files
from securescan.models import Finding, Scan, ScanStatus, ScanType, Severity

REPO_ROOT = Path(__file__).resolve().parents[2]


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run a git command in ``repo`` with deterministic identity."""
    env = {
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "PATH": shutil.os.environ.get("PATH", ""),
        "HOME": shutil.os.environ.get("HOME", ""),
    }
    return subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _init_repo(tmp_path: Path) -> Path:
    """Initialise a fresh git repo with one committed file (so the
    ``--cached`` index has a HEAD to diff against)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "README.md").write_text("seed\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "seed")
    return repo


def _make_finding(scan_id: str, path: str) -> Finding:
    """Construct a minimal Finding rooted at ``path``."""
    return Finding(
        scan_id=scan_id,
        scanner="stub",
        scan_type=ScanType.CODE,
        severity=Severity.LOW,
        title="stub",
        description="stub",
        file_path=path,
    )


# ---------------------------------------------------------------------------
# Flag wiring
# ---------------------------------------------------------------------------


def test_staged_flag_registered_on_scan_command():
    cli = get_command(app)
    scan_cmd = cli.commands["scan"]  # type: ignore[union-attr]
    opts: set[str] = set()
    for param in scan_cmd.params:
        if isinstance(param, click.Option):
            opts.update(param.opts)
    assert "--staged" in opts


# ---------------------------------------------------------------------------
# _resolve_staged_files
# ---------------------------------------------------------------------------


def test_resolve_staged_files_returns_added_modified(tmp_path: Path):
    repo = _init_repo(tmp_path)
    (repo / "a.py").write_text("x = 1\n")
    (repo / "b.py").write_text("y = 2\n")
    _git(repo, "add", "a.py", "b.py")

    paths = _resolve_staged_files(repo)
    names = sorted(p.name for p in paths)
    assert names == ["a.py", "b.py"]
    for p in paths:
        assert p.is_absolute()


def test_resolve_staged_files_empty_when_nothing_staged(tmp_path: Path):
    repo = _init_repo(tmp_path)
    assert _resolve_staged_files(repo) == []


def test_resolve_staged_files_skips_deletions(tmp_path: Path):
    repo = _init_repo(tmp_path)
    (repo / "doomed.py").write_text("z = 3\n")
    _git(repo, "add", "doomed.py")
    _git(repo, "commit", "-q", "-m", "add doomed")
    _git(repo, "rm", "-q", "doomed.py")

    # Stage a sibling at the same time so the index is non-empty.
    (repo / "kept.py").write_text("k = 4\n")
    _git(repo, "add", "kept.py")

    paths = _resolve_staged_files(repo)
    names = [p.name for p in paths]
    assert "doomed.py" not in names
    assert "kept.py" in names


def test_resolve_staged_files_outside_repo_raises(tmp_path: Path):
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    with pytest.raises(typer.BadParameter):
        _resolve_staged_files(not_a_repo)


# ---------------------------------------------------------------------------
# _filter_findings_to_paths
# ---------------------------------------------------------------------------


def test_filter_findings_to_paths_keeps_in_set(tmp_path: Path):
    f1 = tmp_path / "in.py"
    f2 = tmp_path / "out.py"
    f1.write_text("")
    f2.write_text("")
    findings = [
        _make_finding("s", str(f1)),
        _make_finding("s", str(f2)),
        _make_finding("s", str(f1)),
    ]
    kept = _filter_findings_to_paths(findings, {f1.resolve()})
    assert len(kept) == 2
    assert all(Path(f.file_path).resolve() == f1.resolve() for f in kept)


def test_filter_findings_to_paths_drops_pathless():
    pathless = Finding(
        scan_id="s",
        scanner="baseline",
        scan_type=ScanType.BASELINE,
        severity=Severity.LOW,
        title="host",
        description="host",
        file_path=None,
    )
    kept = _filter_findings_to_paths([pathless], {Path("/anything")})
    assert kept == []


def test_filter_findings_to_paths_empty_allowed_returns_empty(tmp_path: Path):
    findings = [_make_finding("s", str(tmp_path / "x.py"))]
    assert _filter_findings_to_paths(findings, set()) == []


# ---------------------------------------------------------------------------
# scan --staged end-to-end (with stubbed pipeline)
# ---------------------------------------------------------------------------


def _stub_run_scan_async_factory(findings_per_call: list[Finding]):
    """Return an async stub that mimics ``_run_scan_async``."""

    async def _stub(target_path, scan_types, *, enable_ai=True, scanner_kwargs=None):
        scan = Scan(target_path=str(target_path), scan_types=list(scan_types))
        scan.status = ScanStatus.COMPLETED
        # The real impl rewrites scan_id on findings before save; for
        # tests we just hand them back so the caller sees the IDs they
        # constructed against.
        for f in findings_per_call:
            f.scan_id = scan.id
        return scan, list(findings_per_call)

    return _stub


def test_staged_no_files_exits_clean(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    runner = CliRunner()
    monkeypatch.chdir(repo)

    # _run_scan_async should never be called for an empty stage; if it
    # is, blow up loudly so the test catches it.
    monkeypatch.setattr(
        _scan_module,
        "_run_scan_async",
        mock.Mock(side_effect=AssertionError("scan should not run for empty stage")),
    )

    result = runner.invoke(app, ["scan", str(repo), "--staged", "--no-ai"])
    assert result.exit_code == 0, result.output
    assert "No staged files" in result.output


def test_staged_filters_to_only_staged_files(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    staged = repo / "staged.py"
    unstaged = repo / "unstaged.py"
    staged.write_text("a = 1\n")
    unstaged.write_text("b = 2\n")
    _git(repo, "add", "staged.py")
    # ``unstaged.py`` deliberately NOT added to the index.

    findings = [
        _make_finding("ignored", str(staged.resolve())),
        _make_finding("ignored", str(unstaged.resolve())),
    ]
    monkeypatch.setattr(
        _scan_module,
        "_run_scan_async",
        _stub_run_scan_async_factory(findings),
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", str(repo), "--staged", "--no-ai", "--output", "json"],
    )
    assert result.exit_code == 0, result.output
    # JSON output goes through the console; check that the staged
    # filename appears and the unstaged one doesn't.
    assert "staged.py" in result.output
    assert "unstaged.py" not in result.output


def test_staged_outside_git_repo_errors(tmp_path: Path, monkeypatch):
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()

    # Stub _run_scan_async so a leak past the git check is obvious.
    monkeypatch.setattr(
        _scan_module,
        "_run_scan_async",
        mock.Mock(side_effect=AssertionError("scan should not run outside repo")),
    )

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(not_a_repo), "--staged", "--no-ai"])
    assert result.exit_code != 0
    # typer.BadParameter renders to stderr/output; tolerate either.
    combined = result.output + (result.stderr if result.stderr_bytes else "")
    assert "git" in combined.lower() or "staged" in combined.lower()


def test_staged_skips_deleted_files(tmp_path: Path, monkeypatch):
    repo = _init_repo(tmp_path)
    (repo / "doomed.py").write_text("z = 3\n")
    _git(repo, "add", "doomed.py")
    _git(repo, "commit", "-q", "-m", "add doomed")
    _git(repo, "rm", "-q", "doomed.py")
    (repo / "kept.py").write_text("k = 4\n")
    _git(repo, "add", "kept.py")

    captured = {}

    async def _capture(target_path, scan_types, *, enable_ai=True, scanner_kwargs=None):
        captured["target"] = str(target_path)
        scan = Scan(target_path=str(target_path), scan_types=list(scan_types))
        scan.status = ScanStatus.COMPLETED
        # Simulate scanner trying to read both — but our resolver
        # should have already excluded ``doomed.py`` from the staged
        # set, so the post-filter drops a finding for it.
        return scan, [
            _make_finding(scan.id, str((repo / "kept.py").resolve())),
            _make_finding(scan.id, str((repo / "doomed.py").resolve())),
        ]

    monkeypatch.setattr(_scan_module, "_run_scan_async", _capture)

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", str(repo), "--staged", "--no-ai", "--output", "json"],
    )
    assert result.exit_code == 0, result.output
    assert "kept.py" in result.output
    assert "doomed.py" not in result.output
    # The narrowed common-parent target should be the repo root (or a
    # subdir of it); never the absent file.
    assert "doomed.py" not in captured["target"]


# ---------------------------------------------------------------------------
# .pre-commit-hooks.yaml + console-script registration
# ---------------------------------------------------------------------------


def test_pre_commit_hooks_yaml_validates():
    hooks_path = REPO_ROOT / ".pre-commit-hooks.yaml"
    assert hooks_path.exists(), f"missing {hooks_path}"
    data = yaml.safe_load(hooks_path.read_text())
    assert isinstance(data, list) and data, "expected non-empty list of hooks"
    hook = data[0]
    for key in ("id", "name", "entry", "language"):
        assert key in hook, f"missing required key: {key}"
    assert hook["id"] == "securescan"
    assert hook["entry"] == "pre-commit-securescan"
    assert hook["language"] == "python"
    assert hook.get("pass_filenames") is False
    assert "pre-commit" in hook.get("stages", [])


def test_pre_commit_console_script_registered():
    pyproject = REPO_ROOT / "backend" / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text())
    scripts = data["project"]["scripts"]
    assert scripts.get("pre-commit-securescan") == "securescan.cli.staged:main"
    assert scripts.get("securescan") == "securescan.cli:app"


def test_pre_commit_securescan_smoke(tmp_path: Path):
    """End-to-end smoke: invoke the installed console script in a
    fresh git repo and confirm it exits 0 without crashing.

    Skips if the venv that ran the test suite didn't install the
    script (e.g. running the tests off a stale checkout)."""
    bin_dir = Path(sys.executable).parent
    script = bin_dir / "pre-commit-securescan"
    if not script.exists():
        pytest.skip(f"console script not installed at {script}")

    repo = _init_repo(tmp_path)
    proc = subprocess.run(
        [str(script)],
        cwd=str(repo),
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    # Empty stage → exit 0 with the friendly no-op message.
    assert proc.returncode == 0, f"stdout={proc.stdout!r}\nstderr={proc.stderr!r}"
    assert "No staged files" in proc.stdout
