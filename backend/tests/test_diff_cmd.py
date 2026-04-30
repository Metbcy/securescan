"""Tests for the ``securescan diff`` subcommand.

The diff command is the user-facing surface that ties the wave-1 and
wave-2 work together: scan a base ref, scan a head ref, classify into
``ChangeSet``, render in any output format. These tests pin down the
contract without exercising the (slow, side-effectful) full scan
pipeline -- the snapshot-input mode lets every behaviour be verified
deterministically with synthetic JSON.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from securescan.cli import app, diff_should_run_ai
from securescan.render_pr_comment import MARKER


def _finding_dict(**overrides) -> dict:
    base = {
        "id": "fid-default",
        "scan_id": "scan-1",
        "scanner": "semgrep",
        "scan_type": "code",
        "severity": "high",
        "title": "SQL Injection",
        "description": "User input concatenated into SQL.",
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 10,
        "rule_id": "RULE-001",
        "cwe": "CWE-89",
        "remediation": "Use parameterised queries.",
        "metadata": {},
        "compliance_tags": [],
        "fingerprint": "fp-default",
    }
    base.update(overrides)
    return base


def _write_snapshot(path, findings):
    path.write_text(json.dumps({"findings": findings}))


def test_diff_command_registered_in_cli():
    """Verify the diff subcommand is registered with the expected flags.
    Uses Click's command introspection rather than asserting on rendered
    help output (which collapses without a TTY in CI)."""
    import click
    from typer.main import get_command

    cli = get_command(app)
    diff_cmd = cli.commands["diff"]  # type: ignore[union-attr]
    assert "Diff two scan snapshots" in (diff_cmd.help or "")

    opts: set[str] = set()
    for param in diff_cmd.params:
        if isinstance(param, click.Option):
            opts.update(param.opts)
    assert "--base-ref" in opts
    assert "--base-snapshot" in opts


def test_diff_requires_one_input_pair(tmp_path):
    runner = CliRunner()
    result = runner.invoke(app, ["diff", str(tmp_path)])
    assert result.exit_code == 2
    assert (
        "must provide" in result.output
        or "snapshot" in result.output.lower()
        or "ref" in result.output.lower()
    )


def test_diff_rejects_mixed_inputs(tmp_path):
    snap = tmp_path / "snap.json"
    _write_snapshot(snap, [])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-ref",
            "main",
            "--head-snapshot",
            str(snap),
        ],
    )
    assert result.exit_code == 2
    assert "not both" in result.output or "both" in result.output


def test_diff_snapshot_path_emits_pr_comment_marker_first(tmp_path):
    old_snap = tmp_path / "old.json"
    new_snap = tmp_path / "new.json"
    _write_snapshot(old_snap, [])
    _write_snapshot(
        new_snap,
        [_finding_dict(fingerprint="fp-NEW-A", title="Hardcoded Secret")],
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(old_snap),
            "--head-snapshot",
            str(new_snap),
            "--output",
            "github-pr-comment",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith(MARKER), result.stdout[:200]


def test_diff_snapshot_path_classifies_correctly(tmp_path):
    old_snap = tmp_path / "old.json"
    new_snap = tmp_path / "new.json"
    _write_snapshot(old_snap, [])
    _write_snapshot(
        new_snap,
        [_finding_dict(fingerprint="fp-classify-1", title="UniqueDistinctTitle")],
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(old_snap),
            "--head-snapshot",
            str(new_snap),
            "--output",
            "github-pr-comment",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "UniqueDistinctTitle" in result.stdout


def test_diff_with_no_changes_exits_zero_and_says_no_findings(tmp_path):
    empty = tmp_path / "empty.json"
    _write_snapshot(empty, [])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(empty),
            "--head-snapshot",
            str(empty),
            "--output",
            "github-pr-comment",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0
    assert "no new or fixed findings" in result.stdout.lower()


def test_diff_fail_on_severity_only_counts_new(tmp_path):
    """An OLD critical that's still UNCHANGED in HEAD must not trip the
    ``--fail-on-severity`` gate -- by design, only NEW findings count.
    """
    crit = _finding_dict(
        fingerprint="fp-crit-shared",
        severity="critical",
        title="Old critical",
    )
    high_new = _finding_dict(
        fingerprint="fp-high-new",
        severity="high",
        title="New high",
    )
    old_snap = tmp_path / "old.json"
    new_snap = tmp_path / "new.json"
    _write_snapshot(old_snap, [crit])
    _write_snapshot(new_snap, [crit, high_new])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(old_snap),
            "--head-snapshot",
            str(new_snap),
            "--fail-on-severity",
            "critical",
            "--output",
            "json",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output


def test_diff_fail_on_severity_exits_nonzero_when_new_meets_threshold(tmp_path):
    high_new = _finding_dict(
        fingerprint="fp-high-NEW",
        severity="critical",
        title="Brand-new critical",
    )
    old_snap = tmp_path / "old.json"
    new_snap = tmp_path / "new.json"
    _write_snapshot(old_snap, [])
    _write_snapshot(new_snap, [high_new])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(old_snap),
            "--head-snapshot",
            str(new_snap),
            "--fail-on-severity",
            "high",
            "--output",
            "json",
            "--no-ai",
        ],
    )
    assert result.exit_code == 1, result.output


def test_diff_baseline_suppresses_from_both_sides(tmp_path):
    shared = _finding_dict(
        fingerprint="fp-shared-suppressed",
        title="Pre-existing finding",
    )
    snap = tmp_path / "both.json"
    _write_snapshot(snap, [shared])

    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([{"fingerprint": "fp-shared-suppressed"}]))

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(snap),
            "--head-snapshot",
            str(snap),
            "--baseline",
            str(baseline),
            "--output",
            "json",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert parsed["new"] == []
    assert parsed["fixed"] == []
    assert parsed["unchanged_count"] == 0


def test_diff_output_json_emits_three_keys(tmp_path):
    empty = tmp_path / "e.json"
    _write_snapshot(empty, [])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(empty),
            "--head-snapshot",
            str(empty),
            "--output",
            "json",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert set(parsed.keys()) == {"new", "fixed", "unchanged_count"}


def test_diff_ai_default_off_in_diff_mode(monkeypatch):
    """In diff mode AI is off by default even when ``CI`` is unset/false.

    The diff command has its own gate (``diff_should_run_ai``) instead
    of reusing ``should_run_ai`` because diff is fundamentally a
    CI/automation surface and PR comments must be byte-identical
    across re-runs to enable upsert.
    """
    monkeypatch.setenv("CI", "false")
    assert diff_should_run_ai(explicit_ai=False, explicit_no_ai=False) is False
    assert diff_should_run_ai(explicit_ai=True, explicit_no_ai=False) is True
    assert diff_should_run_ai(explicit_ai=False, explicit_no_ai=True) is False


def test_diff_ai_default_off_does_not_construct_enricher(tmp_path, monkeypatch):
    """End-to-end: even with CI=false, running ``diff`` without ``--ai``
    must not instantiate ``AIEnricher``.
    """
    monkeypatch.setenv("CI", "false")
    constructed = []

    class _SentinelEnricher:
        def __init__(self, *args, **kwargs):
            constructed.append((args, kwargs))

    monkeypatch.setattr("securescan.cli._shared.AIEnricher", _SentinelEnricher)
    empty = tmp_path / "empty.json"
    _write_snapshot(empty, [])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(empty),
            "--head-snapshot",
            str(empty),
            "--output",
            "json",
        ],
    )
    assert result.exit_code == 0, result.output
    assert constructed == []


def test_diff_default_output_format_is_github_pr_comment(tmp_path):
    """CliRunner's stdout is not a TTY, so the unspecified-output default
    must resolve to ``github-pr-comment`` (the wedge use case).
    """
    empty = tmp_path / "e.json"
    _write_snapshot(empty, [])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(empty),
            "--head-snapshot",
            str(empty),
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    assert MARKER in result.stdout


def test_diff_output_file_writes_to_file(tmp_path):
    empty = tmp_path / "e.json"
    _write_snapshot(empty, [])
    out_file = tmp_path / "out.md"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(empty),
            "--head-snapshot",
            str(empty),
            "--output",
            "github-pr-comment",
            "--output-file",
            str(out_file),
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    assert out_file.exists()
    assert out_file.read_text().startswith(MARKER)


def test_diff_invalid_output_format_exits_2(tmp_path):
    empty = tmp_path / "e.json"
    _write_snapshot(empty, [])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(empty),
            "--head-snapshot",
            str(empty),
            "--output",
            "xml",
            "--no-ai",
        ],
    )
    assert result.exit_code == 2


def test_diff_mutually_exclusive_ai_flags(tmp_path):
    empty = tmp_path / "e.json"
    _write_snapshot(empty, [])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(empty),
            "--head-snapshot",
            str(empty),
            "--ai",
            "--no-ai",
        ],
    )
    assert result.exit_code == 2
