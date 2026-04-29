"""Tests for the ``securescan compare`` subcommand.

The compare command is the symmetric counterpart of ``diff`` (TS7,
v0.3.0): instead of two refs / two snapshots, you provide a saved
baseline JSON file and we run a fresh scan now. NEW = present now,
absent from baseline. DISAPPEARED = present in baseline, absent now
-- which often means someone fixed something and forgot to refresh
the baseline OR silently suppressed a real finding via .securescan.yml
or inline ignores. Both are worth flagging.

These tests pin down the contract without exercising the slow /
side-effectful real scan: by monkey-patching ``_run_scan_for_diff`` to
return a deterministic synthetic finding list, every behaviour is
verified deterministically.
"""
from __future__ import annotations

import json

from typer.testing import CliRunner

from securescan import cli as cli_mod
from securescan.cli import app
from securescan.models import Finding, ScanType, Severity
from securescan.render_pr_comment import MARKER, MARKER_COMPARE


def _finding(**overrides) -> Finding:
    base = dict(
        scan_id="scan-1",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=Severity.HIGH,
        title="SQL injection",
        description="User input concatenated into SQL.",
        file_path="src/app.py",
        line_start=10,
        line_end=10,
        rule_id="RULE-001",
        cwe="CWE-89",
        remediation="Use parameterised queries.",
        fingerprint="fp-default",
    )
    base.update(overrides)
    return Finding(**base)


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


def _stub_run_scan(monkeypatch, findings: list[Finding]) -> None:
    """Replace ``_run_scan_for_diff`` with a stub that returns ``findings``.

    Avoids invoking actual scanners. The compare subcommand reuses the
    same private helper as diff, so this is the right seam to fake.
    """

    async def _fake_run_scan(target_path, scan_types, *, enable_ai):
        return list(findings)

    monkeypatch.setattr(cli_mod, "_run_scan_for_diff", _fake_run_scan)


# --- registration / help --------------------------------------------------


def test_compare_command_registered_in_cli():
    runner = CliRunner()
    result = runner.invoke(app, ["compare", "--help"])
    assert result.exit_code == 0
    assert "baseline" in result.output.lower()


# --- input validation ----------------------------------------------------


def test_compare_missing_baseline_exits_2(tmp_path, monkeypatch):
    _stub_run_scan(monkeypatch, [])
    missing = tmp_path / "nonexistent.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(missing),
            "--output",
            "json",
            "--no-ai",
        ],
    )
    assert result.exit_code == 2
    combined = result.output + (result.stderr if hasattr(result, "stderr") else "")
    assert "baseline" in combined.lower()
    assert "not found" in combined.lower() or "hint" in combined.lower()


# --- classification semantics --------------------------------------------


def test_compare_with_empty_baseline_treats_all_as_new(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([]))
    _stub_run_scan(
        monkeypatch,
        [_finding(fingerprint="fp-NEW-1", title="Brand new")],
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline),
            "--output",
            "json",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert len(parsed["new"]) == 1
    assert parsed["disappeared"] == []
    assert parsed["unchanged_count"] == 0


def test_compare_identical_yields_unchanged(tmp_path, monkeypatch):
    shared = _finding_dict(fingerprint="fp-shared", title="Pre-existing")
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([shared]))
    _stub_run_scan(monkeypatch, [_finding(fingerprint="fp-shared", title="Pre-existing")])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline),
            "--output",
            "github-pr-comment",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    # No new, no disappeared -> empty-changeset short-circuit body.
    assert "no drift since baseline" in result.stdout.lower()


def test_compare_disappeared_findings_show_in_render(tmp_path, monkeypatch):
    """Baseline has a finding that's NOT in the fresh scan -> renders as
    ``Disappeared`` section in PR-comment markdown.
    """
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            [
                _finding_dict(
                    fingerprint="fp-disappeared",
                    title="VanishedFinding",
                )
            ]
        )
    )
    _stub_run_scan(monkeypatch, [])  # fresh scan finds nothing
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline),
            "--output",
            "github-pr-comment",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Disappeared from baseline" in result.stdout
    assert "VanishedFinding" in result.stdout


# --- PR-comment marker / wording -----------------------------------------


def test_compare_pr_comment_uses_compare_marker(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([]))
    _stub_run_scan(monkeypatch, [_finding(fingerprint="fp-new")])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline),
            "--output",
            "github-pr-comment",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    assert result.stdout.startswith(MARKER_COMPARE), result.stdout[:200]
    # Diff marker must NOT appear -- different upsert lanes.
    assert MARKER not in result.stdout


def test_compare_pr_comment_uses_compare_section_headings(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            [
                _finding_dict(
                    fingerprint="fp-disappeared",
                    title="Vanished",
                )
            ]
        )
    )
    _stub_run_scan(
        monkeypatch,
        [_finding(fingerprint="fp-new", title="Brand new")],
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline),
            "--output",
            "github-pr-comment",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Disappeared from baseline" in result.stdout
    assert "New since baseline" in result.stdout
    # The diff-mode wording must not leak into compare output.
    assert "Fixed findings" not in result.stdout


# --- TTY / pipe default output --------------------------------------------


def test_compare_default_output_format_text_on_tty(monkeypatch):
    """When stdout is a TTY (a human at a terminal), the unspecified
    ``--output`` default resolves to ``text`` -- not ``github-pr-comment``.

    Tested via ``_resolve_default_output`` directly because CliRunner
    swaps ``sys.stdout`` for capture, defeating any monkeypatch on the
    real stdout's ``isatty``.
    """
    import sys

    from securescan.cli import _resolve_default_output

    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert _resolve_default_output(None) == "text"
    # Explicit values pass through unchanged.
    assert _resolve_default_output("json") == "json"


def test_compare_default_output_format_pr_comment_when_piped(tmp_path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([]))
    _stub_run_scan(monkeypatch, [_finding(fingerprint="fp-new")])
    # CliRunner already pipes stdout (isatty -> False) so no monkeypatch
    # needed. Pin the default-resolution branch explicitly.
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline),
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    assert MARKER_COMPARE in result.stdout


# --- backward-compat for render_pr_comment --------------------------------


def test_render_pr_comment_diff_mode_unchanged_by_compare_addition():
    """Pre-existing call sites (no ``mode=`` argument) still get diff
    semantics: the diff marker, "New findings" / "Fixed findings"
    headings, and the diff-mode summary heading.
    """
    from securescan.diff import ChangeSet
    from securescan.render_pr_comment import render_pr_comment

    cs = ChangeSet(new=[_finding(fingerprint="fp-x")])
    out = render_pr_comment(cs)
    assert out.startswith(MARKER)
    assert MARKER_COMPARE not in out
    assert "New findings" in out
    assert "Fixed findings" in out
    assert "Disappeared from baseline" not in out


# --- baseline JSON envelope shape -----------------------------------------


def test_compare_baseline_with_findings_key_envelope_works(tmp_path, monkeypatch):
    """``{"findings": [...]}`` envelope is the TS4-era contract -- the
    same shape ``securescan scan --output json`` emits. ``compare``
    must accept it via ``load_findings_json``.
    """
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            {
                "findings": [
                    _finding_dict(
                        fingerprint="fp-baseline-only",
                        title="OnlyInBaseline",
                    )
                ],
            }
        )
    )
    _stub_run_scan(monkeypatch, [])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline),
            "--output",
            "json",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert parsed["new"] == []
    assert len(parsed["disappeared"]) == 1
    assert parsed["disappeared"][0]["title"] == "OnlyInBaseline"


# --- AI flag plumbing -----------------------------------------------------


def test_compare_command_no_ai_flag_works(tmp_path, monkeypatch):
    """Passing ``--no-ai`` does NOT construct an ``AIEnricher``.

    The compare command is informational / CI-friendly and shouldn't
    invoke models when the user opts out. We sentinel the constructor
    to assert no instances ever get built.
    """
    monkeypatch.setenv("CI", "false")
    constructed: list[tuple] = []

    class _SentinelEnricher:
        def __init__(self, *args, **kwargs):
            constructed.append((args, kwargs))

    monkeypatch.setattr(cli_mod, "AIEnricher", _SentinelEnricher)
    _stub_run_scan(monkeypatch, [])
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([]))
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline),
            "--output",
            "json",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output
    assert constructed == []


def test_compare_mutually_exclusive_ai_flags(tmp_path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([]))
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline),
            "--ai",
            "--no-ai",
        ],
    )
    assert result.exit_code == 2
