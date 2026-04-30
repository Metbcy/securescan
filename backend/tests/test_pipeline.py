"""Unit tests for :func:`securescan.pipeline.apply_pipeline`.

These tests pin the integration order (load config -> fingerprints ->
severity overrides -> suppression) and the precedence contract across
the three suppression sources. Every test is fast: no scanners, no
filesystem walks beyond a couple of fixtures in ``tmp_path``.

The expected end-to-end CLI behaviour is covered by
``test_pipeline_integration.py``; this file tests the helper in
isolation so a regression in one stage points at the stage rather
than at a CLI subcommand.
"""

from __future__ import annotations

import json
from pathlib import Path

from securescan.config_file import SecureScanConfig
from securescan.models import Finding, ScanType, Severity
from securescan.pipeline import apply_pipeline

# --- helpers --------------------------------------------------------------


def _make_finding(
    *,
    rule_id: str | None = "RULE-A",
    severity: Severity = Severity.HIGH,
    file_path: str | None = "src/app.py",
    line_start: int | None = 10,
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


def _write_baseline(path: Path, fingerprints: list[str]) -> None:
    """Write a minimal ``[{"fingerprint": ...}]`` baseline."""
    path.write_text(json.dumps([{"fingerprint": fp} for fp in fingerprints]))


# --- tests ----------------------------------------------------------------


def test_apply_pipeline_with_no_config_just_fingerprints(tmp_path):
    """Empty config + no baseline -> all findings kept, fingerprints set."""
    findings = [
        _make_finding(rule_id="RULE-A"),
        _make_finding(rule_id="RULE-B", file_path="src/b.py", line_start=20),
    ]

    result = apply_pipeline(
        findings,
        target_path=tmp_path,
        config=SecureScanConfig(),
    )

    assert len(result.kept) == 2
    assert len(result.suppressed) == 0
    assert all(f.fingerprint for f in result.kept), "fingerprints populated"
    assert result.severity_overrides_applied == 0
    assert result.found_config_path is None


def test_apply_pipeline_severity_override_applied(tmp_path):
    """``severity_overrides`` flips severity and stamps original_severity."""
    findings = [
        _make_finding(rule_id="RULE-A", severity=Severity.HIGH),
        _make_finding(rule_id="RULE-B", severity=Severity.HIGH),
    ]
    config = SecureScanConfig(
        severity_overrides={"RULE-A": Severity.MEDIUM},
    )

    result = apply_pipeline(findings, target_path=tmp_path, config=config)

    by_rule = {f.rule_id: f for f in result.kept}
    assert by_rule["RULE-A"].severity == Severity.MEDIUM
    assert by_rule["RULE-A"].metadata["original_severity"] == "high"
    assert by_rule["RULE-B"].severity == Severity.HIGH
    assert "original_severity" not in by_rule["RULE-B"].metadata
    assert result.severity_overrides_applied == 1


def test_apply_pipeline_config_ignored_rule_suppresses(tmp_path):
    """``ignored_rules`` -> finding lands in suppressed with reason='config'."""
    findings = [
        _make_finding(rule_id="RULE-A"),
        _make_finding(rule_id="RULE-B", file_path="src/b.py", line_start=2),
    ]
    config = SecureScanConfig(ignored_rules=["RULE-A"])

    result = apply_pipeline(findings, target_path=tmp_path, config=config)

    assert [f.rule_id for f in result.kept] == ["RULE-B"]
    assert [f.rule_id for f in result.suppressed] == ["RULE-A"]
    assert result.suppressed[0].metadata["suppressed_by"] == "config"


def test_apply_pipeline_baseline_suppresses(tmp_path):
    """Baseline fingerprint match -> suppressed with reason='baseline'."""
    finding = _make_finding(rule_id="RULE-A")
    findings = [finding]

    # Pre-populate fingerprint so the baseline file can target it.
    from securescan.fingerprint import populate_fingerprints

    populate_fingerprints(findings)
    target_fp = finding.fingerprint
    assert target_fp

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, [target_fp])

    result = apply_pipeline(
        findings,
        target_path=tmp_path,
        baseline_path=baseline,
        config=SecureScanConfig(),
    )

    assert result.kept == []
    assert len(result.suppressed) == 1
    assert result.suppressed[0].metadata["suppressed_by"] == "baseline"


def test_apply_pipeline_inline_comment_suppresses(tmp_path):
    """Inline ``# securescan: ignore RULE-A`` -> reason='inline'."""
    src = tmp_path / "app.py"
    src.write_text(
        "# line 1\n"
        "# line 2\n"
        "# line 3\n"
        "# line 4\n"
        "evil_call()  # securescan: ignore RULE-A\n"
        "# line 6\n"
    )

    findings = [
        _make_finding(
            rule_id="RULE-A",
            file_path=str(src),
            line_start=5,
        )
    ]

    result = apply_pipeline(
        findings,
        target_path=tmp_path,
        config=SecureScanConfig(),
    )

    assert result.kept == []
    assert len(result.suppressed) == 1
    assert result.suppressed[0].metadata["suppressed_by"] == "inline"


def test_apply_pipeline_inline_beats_config_beats_baseline(tmp_path):
    """All three apply for the same finding -> reason='inline' wins."""
    src = tmp_path / "app.py"
    src.write_text("# l1\n# l2\n# l3\n# l4\nevil()  # securescan: ignore RULE-A\n")

    finding = _make_finding(rule_id="RULE-A", file_path=str(src), line_start=5)
    from securescan.fingerprint import populate_fingerprints

    populate_fingerprints([finding])

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, [finding.fingerprint])

    config = SecureScanConfig(ignored_rules=["RULE-A"])

    result = apply_pipeline(
        [finding],
        target_path=tmp_path,
        baseline_path=baseline,
        config=config,
    )

    assert result.kept == []
    assert len(result.suppressed) == 1
    assert result.suppressed[0].metadata["suppressed_by"] == "inline"


def test_apply_pipeline_no_suppress_returns_all_kept(tmp_path):
    """``no_suppress=True`` short-circuits all three mechanisms.

    No findings end up in ``suppressed``; no ``suppressed_by`` stamps
    pollute the audit trail.
    """
    src = tmp_path / "app.py"
    src.write_text("# l1\n# l2\n# l3\n# l4\nevil()  # securescan: ignore RULE-A\n")

    finding = _make_finding(rule_id="RULE-A", file_path=str(src), line_start=5)
    from securescan.fingerprint import populate_fingerprints

    populate_fingerprints([finding])

    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, [finding.fingerprint])

    config = SecureScanConfig(ignored_rules=["RULE-A"])

    result = apply_pipeline(
        [finding],
        target_path=tmp_path,
        baseline_path=baseline,
        no_suppress=True,
        config=config,
    )

    assert len(result.kept) == 1
    assert result.suppressed == []
    assert "suppressed_by" not in result.kept[0].metadata


def test_apply_pipeline_idempotent(tmp_path):
    """A second call returns the same result; no double-stamping."""
    findings = [
        _make_finding(rule_id="RULE-A", severity=Severity.HIGH),
        _make_finding(rule_id="RULE-B", severity=Severity.HIGH),
    ]
    config = SecureScanConfig(
        severity_overrides={"RULE-A": Severity.MEDIUM},
        ignored_rules=["RULE-B"],
    )

    first = apply_pipeline(findings, target_path=tmp_path, config=config)
    second = apply_pipeline(first.kept + first.suppressed, target_path=tmp_path, config=config)

    assert len(second.kept) == 1
    assert len(second.suppressed) == 1
    assert second.kept[0].metadata["original_severity"] == "high"
    assert second.suppressed[0].metadata["suppressed_by"] == "config"
    # Second call must report ZERO new severity overrides applied; the
    # stamps on the first call render the second pass a no-op.
    assert second.severity_overrides_applied == 0


def test_apply_pipeline_severity_overrides_applied_count(tmp_path):
    """3 findings, 2 match config overrides -> count == 2."""
    findings = [
        _make_finding(rule_id="RULE-A", severity=Severity.HIGH),
        _make_finding(rule_id="RULE-B", severity=Severity.HIGH),
        _make_finding(rule_id="RULE-C", severity=Severity.HIGH),
    ]
    config = SecureScanConfig(
        severity_overrides={
            "RULE-A": Severity.LOW,
            "RULE-B": Severity.LOW,
        },
    )

    result = apply_pipeline(findings, target_path=tmp_path, config=config)

    assert result.severity_overrides_applied == 2
    by_rule = {f.rule_id: f for f in result.kept}
    assert by_rule["RULE-A"].severity == Severity.LOW
    assert by_rule["RULE-B"].severity == Severity.LOW
    assert by_rule["RULE-C"].severity == Severity.HIGH


def test_apply_pipeline_loads_config_from_disk(tmp_path):
    """When ``config`` is None, the helper walks up from
    ``config_search_start`` and loads ``.securescan.yml``.

    Verifies the loader path runs end-to-end and that
    ``found_config_path`` is set on the result so the CLI can echo
    "loaded config from <path>" to stderr.
    """
    cfg_file = tmp_path / ".securescan.yml"
    cfg_file.write_text("ignored_rules:\n  - RULE-A\n")

    findings = [
        _make_finding(rule_id="RULE-A"),
        _make_finding(rule_id="RULE-B", file_path="src/b.py", line_start=2),
    ]

    result = apply_pipeline(
        findings,
        target_path=tmp_path,
        config_search_start=tmp_path,
    )

    assert result.found_config_path is not None
    assert result.found_config_path.name == ".securescan.yml"
    assert [f.rule_id for f in result.kept] == ["RULE-B"]
    assert result.suppressed[0].metadata["suppressed_by"] == "config"


def test_apply_pipeline_resolves_semgrep_rules_relative_paths(tmp_path):
    """``semgrep_rules`` in config get resolved against ``found_path.parent``.

    Ensures the resolved ``PipelineResult.config.semgrep_rules`` are
    absolute, so the CLI can hand them straight to the Semgrep
    scanner without per-call resolution.
    """
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "custom.yml").write_text("rules: []\n")

    cfg_file = tmp_path / ".securescan.yml"
    cfg_file.write_text("semgrep_rules:\n  - ./rules/custom.yml\n")

    result = apply_pipeline(
        [],
        target_path=tmp_path,
        config_search_start=tmp_path,
    )

    assert result.config.semgrep_rules
    resolved = result.config.semgrep_rules[0]
    assert resolved.is_absolute()
    assert resolved == (rules_dir / "custom.yml").resolve()
