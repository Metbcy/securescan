"""CLI-level tests for the ``securescan baseline`` subcommand.

These exercise the typer wiring: argument parsing, default output
path, AI-off-by-default policy, byte-deterministic output across
repeated invocations, and parent-directory creation. The actual
scanner pipeline is mocked out via ``securescan.cli._run_scan_for_diff``
so the tests don't depend on semgrep/bandit/etc being installed.
"""
from __future__ import annotations

import json

from typer.testing import CliRunner

from securescan.cli import app
from securescan.fingerprint import populate_fingerprints
from securescan.models import Finding, ScanType, Severity


def _make_finding(
    *,
    scanner: str = "semgrep",
    rule_id: str = "RULE-001",
    file_path: str = "src/app.py",
    line_start: int = 10,
    title: str = "SQL Injection",
    severity: Severity = Severity.HIGH,
    cwe: str = "CWE-89",
) -> Finding:
    return Finding(
        scan_id="scan-cli-test",
        scanner=scanner,
        scan_type=ScanType.CODE,
        severity=severity,
        title=title,
        description="bulky description that should not appear in baseline",
        file_path=file_path,
        line_start=line_start,
        rule_id=rule_id,
        cwe=cwe,
        remediation="bulky remediation",
        metadata={},
        compliance_tags=[],
    )


def _patch_runner(monkeypatch, findings: list[Finding] | None = None):
    """Patch ``_run_scan_for_diff`` to return a fixed list of findings."""
    if findings is None:
        findings = [
            _make_finding(rule_id="RULE-A", file_path="src/a.py", line_start=1),
            _make_finding(
                rule_id="RULE-B",
                file_path="src/b.py",
                line_start=2,
                severity=Severity.CRITICAL,
                title="Hardcoded Secret",
                cwe="CWE-798",
            ),
        ]
    populate_fingerprints(findings)

    async def _fake(target_path, scan_types, *, enable_ai):
        _fake.calls.append(
            {
                "target_path": target_path,
                "scan_types": list(scan_types),
                "enable_ai": enable_ai,
            }
        )
        return [f.model_copy() for f in findings]

    _fake.calls = []  # type: ignore[attr-defined]
    monkeypatch.setattr("securescan.cli._run_scan_for_diff", _fake)
    return _fake


def test_baseline_command_registered():
    runner = CliRunner()
    result = runner.invoke(app, ["baseline", "--help"])
    assert result.exit_code == 0, result.output
    assert "Write a canonicalized baseline JSON" in result.output
    assert "--output-file" in result.output
    assert "--no-ai" in result.output
    assert "--ai" in result.output


def test_baseline_command_writes_default_path(tmp_path, monkeypatch):
    _patch_runner(monkeypatch)
    monkeypatch.chdir(tmp_path)

    runner = CliRunner()
    result = runner.invoke(app, ["baseline", str(tmp_path)])
    assert result.exit_code == 0, result.output

    expected = tmp_path / ".securescan" / "baseline.json"
    assert expected.exists(), f"default path missing: {expected}"
    parsed = json.loads(expected.read_text())
    assert parsed["version"] == 1
    assert "findings" in parsed


def test_baseline_command_no_ai_default(tmp_path, monkeypatch):
    """Without ``--ai``, baseline must not construct AIEnricher.

    Defense-in-depth: ``_run_scan_for_diff`` already gates this on
    ``enable_ai``, but we additionally swap ``AIEnricher`` for a
    sentinel so any accidental construction is loud.
    """
    fake = _patch_runner(monkeypatch)

    constructed: list[tuple] = []

    class _SentinelEnricher:
        def __init__(self, *args, **kwargs):
            constructed.append((args, kwargs))

    monkeypatch.setattr("securescan.cli.AIEnricher", _SentinelEnricher)

    out = tmp_path / "baseline.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["baseline", str(tmp_path), "--output-file", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert constructed == []
    assert fake.calls and fake.calls[0]["enable_ai"] is False


def test_baseline_command_ai_flag_opts_in(tmp_path, monkeypatch):
    fake = _patch_runner(monkeypatch)
    out = tmp_path / "baseline.json"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["baseline", str(tmp_path), "--output-file", str(out), "--ai"],
    )
    assert result.exit_code == 0, result.output
    assert fake.calls[0]["enable_ai"] is True


def test_baseline_command_creates_parent_dir(tmp_path, monkeypatch):
    _patch_runner(monkeypatch)
    out = tmp_path / "deeply" / "nested" / "baseline.json"
    assert not out.parent.exists()

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["baseline", str(tmp_path), "--output-file", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    assert out.parent.is_dir()


def test_baseline_command_byte_deterministic_output(tmp_path, monkeypatch):
    _patch_runner(monkeypatch)
    out = tmp_path / "baseline.json"

    runner = CliRunner()
    result_a = runner.invoke(
        app, ["baseline", str(tmp_path), "--output-file", str(out)]
    )
    assert result_a.exit_code == 0, result_a.output
    bytes_a = out.read_bytes()

    out.unlink()

    result_b = runner.invoke(
        app, ["baseline", str(tmp_path), "--output-file", str(out)]
    )
    assert result_b.exit_code == 0, result_b.output
    bytes_b = out.read_bytes()

    assert bytes_a == bytes_b, "baseline output must be byte-deterministic"


def test_baseline_command_explicit_output_file_path(tmp_path, monkeypatch):
    _patch_runner(monkeypatch)
    out = tmp_path / "custom" / "my-baseline.json"

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["baseline", str(tmp_path), "--output-file", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()

    parsed = json.loads(out.read_text())
    assert parsed["version"] == 1


def test_baseline_command_uses_short_o_flag(tmp_path, monkeypatch):
    _patch_runner(monkeypatch)
    out = tmp_path / "shorty.json"

    runner = CliRunner()
    result = runner.invoke(app, ["baseline", str(tmp_path), "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()


def test_baseline_command_stderr_summary_line(tmp_path, monkeypatch):
    _patch_runner(monkeypatch)
    out = tmp_path / "b.json"

    runner = CliRunner(mix_stderr=False) if _supports_mix_stderr() else CliRunner()
    result = runner.invoke(
        app, ["baseline", str(tmp_path), "--output-file", str(out)]
    )
    assert result.exit_code == 0, result.output

    combined = (result.output or "") + (getattr(result, "stderr", "") or "")
    assert "Wrote baseline to" in combined
    assert "findings" in combined
    assert "bytes" in combined


def _supports_mix_stderr() -> bool:
    """Older typer/click signatures don't accept ``mix_stderr``."""
    try:
        CliRunner(mix_stderr=False)
        return True
    except TypeError:
        return False
