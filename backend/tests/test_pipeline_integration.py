"""End-to-end integration tests for TS10 wire-cli-flow.

These tests invoke the actual CLI subcommands (``scan``, ``diff``,
``compare``) via Typer's CliRunner with a stubbed scanner backend.
The goal is to verify the CLI reads ``.securescan.yml`` from
``tmp_path``, applies the pipeline (severity overrides + ignored
rules + inline comments + baseline) to the right side(s), and that
``--no-suppress`` / ``--show-suppressed`` flags propagate correctly.

We deliberately do NOT exercise real Semgrep / Bandit binaries:
the integration scope is "wiring", not "scanner behaviour".
:func:`_stub_scanners` replaces ``_run_scan_async`` /
``_run_scan_for_diff`` with deterministic helpers that return a
caller-supplied finding list.
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

import securescan.cli.scan as _cli_scan
from securescan.cli import _shared as _cli_shared
from securescan.cli import app
from securescan.models import Finding, Scan, ScanStatus, ScanType, Severity

# --- helpers --------------------------------------------------------------


def _finding(
    *,
    rule_id: str = "RULE-A",
    severity: Severity = Severity.HIGH,
    file_path: str = "src/app.py",
    line_start: int = 10,
    fingerprint: str = "",
    metadata: dict | None = None,
) -> Finding:
    return Finding(
        scan_id="scan-1",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=severity,
        title=f"Issue {rule_id}",
        description="d",
        file_path=file_path,
        line_start=line_start,
        line_end=line_start,
        rule_id=rule_id,
        fingerprint=fingerprint,
        metadata=metadata or {},
    )


def _finding_dict(**overrides) -> dict:
    base = {
        "id": "fid-default",
        "scan_id": "scan-1",
        "scanner": "semgrep",
        "scan_type": "code",
        "severity": "high",
        "title": "Issue RULE-A",
        "description": "d",
        "file_path": "src/app.py",
        "line_start": 10,
        "line_end": 10,
        "rule_id": "RULE-A",
        "cwe": "CWE-89",
        "remediation": "",
        "metadata": {},
        "compliance_tags": [],
        "fingerprint": "fp-rule-a",
    }
    base.update(overrides)
    return base


def _stub_scan_async(monkeypatch, findings: list[Finding]) -> None:
    """Stub ``_run_scan_async`` with a deterministic helper.

    Returns a synthetic Scan + the caller-supplied finding list.
    Avoids DB I/O and the real scanner pass.
    """

    async def _fake(target_path, types, enable_ai=True, *, scanner_kwargs=None):
        scan = Scan(target_path=str(target_path), scan_types=list(types))
        scan.status = ScanStatus.COMPLETED
        return scan, list(findings)

    monkeypatch.setattr(_cli_scan, "_run_scan_async", _fake)


def _stub_scan_for_diff(monkeypatch, findings: list[Finding]) -> None:
    async def _fake(target_path, scan_types, *, enable_ai, scanner_kwargs=None):
        return list(findings)

    monkeypatch.setattr(_cli_shared, "_run_scan_for_diff", _fake)


def _write_snapshot(path: Path, dicts: list[dict]) -> None:
    path.write_text(json.dumps({"findings": dicts}))


def _write_config(path: Path, body: str) -> None:
    (path / ".securescan.yml").write_text(body)


# --- diff ----------------------------------------------------------------


def test_diff_subcommand_applies_config_severity_overrides_end_to_end(tmp_path, monkeypatch):
    """A ``severity_overrides`` entry in ``.securescan.yml`` flips the
    severity of matching findings on both sides of a diff and lets
    ``--fail-on-severity high`` pass when the override demotes a
    would-be-failing finding to medium.

    We use snapshot mode (no git, no scanners) and one HIGH finding
    on the head side that ``RULE-A: medium`` should demote.
    """
    _write_config(
        tmp_path,
        "severity_overrides:\n  RULE-A: medium\n",
    )

    base_snap = tmp_path / "base.json"
    head_snap = tmp_path / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(
        head_snap,
        [_finding_dict(severity="high", fingerprint="fp-1")],
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(base_snap),
            "--head-snapshot",
            str(head_snap),
            "--output",
            "json",
            "--no-ai",
            "--fail-on-severity",
            "high",
        ],
    )

    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert len(parsed["new"]) == 1
    assert parsed["new"][0]["severity"] == "medium"
    assert parsed["new"][0]["metadata"]["original_severity"] == "high"


def test_diff_subcommand_config_ignored_rule_filters_from_default_output(tmp_path, monkeypatch):
    """``ignored_rules: [RULE-A]`` -> the new finding is suppressed.

    Default output (json) hides suppressed findings, so the JSON
    payload's ``new`` list is empty. ``--show-suppressed`` (covered in
    a separate test) makes them visible with the audit stamp.
    """
    _write_config(tmp_path, "ignored_rules:\n  - RULE-A\n")

    base_snap = tmp_path / "base.json"
    head_snap = tmp_path / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(
        head_snap,
        [_finding_dict(rule_id="RULE-A", fingerprint="fp-1")],
    )

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(base_snap),
            "--head-snapshot",
            str(head_snap),
            "--output",
            "json",
            "--no-ai",
        ],
    )

    assert result.exit_code == 0, result.output
    parsed = json.loads(result.stdout)
    assert parsed["new"] == []


# --- scan ----------------------------------------------------------------


def test_scan_subcommand_filters_config_ignored_rules(tmp_path, monkeypatch):
    """``ignored_rules: [RULE-A]`` -> RULE-A absent from default JSON output."""
    _write_config(tmp_path, "ignored_rules:\n  - RULE-A\n")

    findings = [
        _finding(rule_id="RULE-A"),
        _finding(rule_id="RULE-B", file_path="src/b.py", line_start=2),
    ]
    _stub_scan_async(monkeypatch, findings)

    out_file = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--output",
            "json",
            "--output-file",
            str(out_file),
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output

    payload = json.loads(out_file.read_text())
    rules = sorted(f["rule_id"] for f in payload)
    assert rules == ["RULE-B"], f"expected RULE-A filtered by config; got {rules}"


def test_scan_subcommand_show_suppressed_includes_filtered(tmp_path, monkeypatch):
    """``--show-suppressed`` shows the suppressed finding with audit stamp."""
    _write_config(tmp_path, "ignored_rules:\n  - RULE-A\n")

    findings = [
        _finding(rule_id="RULE-A"),
        _finding(rule_id="RULE-B", file_path="src/b.py", line_start=2),
    ]
    _stub_scan_async(monkeypatch, findings)

    out_file = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--output",
            "json",
            "--output-file",
            str(out_file),
            "--show-suppressed",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output

    payload = json.loads(out_file.read_text())
    rule_ids = sorted(f["rule_id"] for f in payload)
    assert rule_ids == ["RULE-A", "RULE-B"]
    rule_a = next(f for f in payload if f["rule_id"] == "RULE-A")
    assert rule_a["metadata"]["suppressed_by"] == "config"


def test_scan_subcommand_no_suppress_overrides_config(tmp_path, monkeypatch):
    """``--no-suppress`` -> RULE-A appears in normal output (no stamp)."""
    _write_config(tmp_path, "ignored_rules:\n  - RULE-A\n")

    findings = [_finding(rule_id="RULE-A")]
    _stub_scan_async(monkeypatch, findings)

    out_file = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--output",
            "json",
            "--output-file",
            str(out_file),
            "--no-suppress",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output

    payload = json.loads(out_file.read_text())
    assert len(payload) == 1
    f = payload[0]
    assert f["rule_id"] == "RULE-A"
    # No suppressed_by stamp when --no-suppress short-circuits the pipeline
    assert "suppressed_by" not in f.get("metadata", {})


def test_scan_subcommand_inline_comment_suppresses_with_show_suppressed(tmp_path, monkeypatch):
    """An inline ``# securescan: ignore RULE-A`` directive marks the
    finding suppressed at scan time; ``--show-suppressed`` reveals it
    with ``[SUPPRESSED:inline]`` semantics in the JSON payload."""
    src = tmp_path / "app.py"
    src.write_text("# l1\n# l2\n# l3\n# l4\nevil()  # securescan: ignore RULE-A\n")

    findings = [
        _finding(rule_id="RULE-A", file_path=str(src), line_start=5),
        _finding(rule_id="RULE-B", file_path=str(src), line_start=4),
    ]
    _stub_scan_async(monkeypatch, findings)

    out_file = tmp_path / "out.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "scan",
            str(tmp_path),
            "--output",
            "json",
            "--output-file",
            str(out_file),
            "--show-suppressed",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output

    payload = json.loads(out_file.read_text())
    by_rule = {f["rule_id"]: f for f in payload}
    assert set(by_rule) == {"RULE-A", "RULE-B"}
    assert by_rule["RULE-A"]["metadata"]["suppressed_by"] == "inline"
    assert "suppressed_by" not in by_rule["RULE-B"].get("metadata", {})


# --- compare -------------------------------------------------------------


def test_compare_subcommand_applies_pipeline_to_fresh_scan_only(tmp_path, monkeypatch):
    """The pipeline runs against the fresh scan only.

    Setup:
      * baseline JSON contains RULE-A (fp-rule-a)
      * .securescan.yml does NOT ignore RULE-A
      * fresh scan reports RULE-A (fp-rule-a)
    Expected:
      * RULE-A is classified ``unchanged`` (fingerprint matches both
        sides). The fresh-side pipeline didn't suppress it (config
        empty), and the baseline JSON wasn't re-filtered.
      * ``new`` and ``disappeared`` are both empty.
    """
    _write_config(
        tmp_path,
        "severity_overrides:\n  OTHER-RULE: low\n",  # config present but unrelated
    )

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"findings": [_finding_dict(rule_id="RULE-A", fingerprint="fp-rule-a")]})
    )

    fresh = [_finding(rule_id="RULE-A", fingerprint="fp-rule-a")]
    _stub_scan_for_diff(monkeypatch, fresh)

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
    assert parsed["disappeared"] == []
    # The single finding is matched on both sides -> unchanged.
    assert parsed["unchanged_count"] == 1


def test_compare_subcommand_config_filters_fresh_side_only(tmp_path, monkeypatch):
    """When config ignores RULE-A, fresh-side RULE-A is suppressed but
    the baseline still 'has' RULE-A. The pipeline-on-fresh-only
    contract means classify sees a suppressed RULE-A on the fresh
    side; ``unchanged_count`` (filtered) is 0 in default output."""
    _write_config(tmp_path, "ignored_rules:\n  - RULE-A\n")

    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps({"findings": [_finding_dict(rule_id="RULE-A", fingerprint="fp-rule-a")]})
    )
    fresh = [_finding(rule_id="RULE-A", fingerprint="fp-rule-a")]
    _stub_scan_for_diff(monkeypatch, fresh)

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
    # Default (CI) JSON filters suppressed: nothing user-visible.
    assert parsed["new"] == []
    assert parsed["disappeared"] == []
    assert parsed["unchanged_count"] == 0
