"""Tests for the .securescan.yml linter.

The linter is a pure function on disk: pass a path, get a
:class:`LintReport`. These tests exercise each lint rule in isolation
plus the report-shape contract that the CLI relies on.
"""

from __future__ import annotations

from pathlib import Path

from securescan.config_lint import (
    LintIssue,
    LintReport,
    lint_config,
)


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_lint_valid_config_passes_clean(tmp_path):
    cfg = _write(
        tmp_path / ".securescan.yml",
        """
severity_overrides:
  SEMGREP-XYZ: medium
ignored_rules:
  - python.lang.security.audit.dangerous-eval
  - B305
fail_on_severity: high
""",
    )

    report = lint_config(cfg)

    assert report.issues == []
    assert not report.has_errors
    assert not report.has_warnings


def test_lint_missing_file_yields_error_issue(tmp_path):
    report = lint_config(tmp_path / "does-not-exist.yml")

    assert len(report.issues) == 1
    assert report.issues[0].severity == "error"
    assert "not found" in report.issues[0].message


def test_lint_malformed_yaml_yields_error_issue(tmp_path):
    cfg = _write(tmp_path / ".securescan.yml", "this: : not: valid: : yaml\n")

    report = lint_config(cfg)

    assert report.has_errors
    assert any("YAML" in i.message or "yaml" in i.message for i in report.errors())


def test_lint_invalid_severity_value_yields_error_with_location(tmp_path):
    cfg = _write(
        tmp_path / ".securescan.yml",
        """
severity_overrides:
  RULE-A: not-a-real-severity
""",
    )

    report = lint_config(cfg)

    assert report.has_errors
    locations = [i.location for i in report.errors()]
    assert any(loc and "severity_overrides" in loc and "RULE-A" in loc for loc in locations), locations


def test_lint_unknown_top_level_key_yields_error(tmp_path):
    cfg = _write(
        tmp_path / ".securescan.yml",
        """
ingored_rules:
  - SEMGREP-XYZ
""",
    )

    report = lint_config(cfg)

    assert report.has_errors
    # Pydantic surfaces extra-key errors with the bad key in the loc.
    assert any(
        i.location and "ingored_rules" in i.location for i in report.errors()
    )


def test_lint_missing_semgrep_rules_path_yields_error(tmp_path):
    cfg = _write(
        tmp_path / ".securescan.yml",
        """
semgrep_rules:
  - /nonexistent/rules-pack.yml
""",
    )

    report = lint_config(cfg)

    error_messages = [i.message for i in report.errors()]
    assert any("semgrep_rules" in m and "rules-pack.yml" in m for m in error_messages), error_messages
    locations = [i.location for i in report.errors()]
    assert any(loc and loc.startswith("semgrep_rules[") for loc in locations), locations


def test_lint_relative_semgrep_rules_path_resolved_against_config_dir(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rules_file = rules_dir / "custom.yml"
    rules_file.write_text("rules: []\n", encoding="utf-8")

    cfg = _write(
        tmp_path / ".securescan.yml",
        """
semgrep_rules:
  - rules/custom.yml
""",
    )

    report = lint_config(cfg)

    assert not report.has_errors, [i.message for i in report.errors()]


def test_lint_rule_id_with_spaces_yields_warning(tmp_path):
    cfg = _write(
        tmp_path / ".securescan.yml",
        """
severity_overrides:
  "RULE WITH SPACES": medium
""",
    )

    report = lint_config(cfg)

    assert not report.has_errors
    assert report.has_warnings
    locs = [i.location for i in report.warnings()]
    assert any(loc and "RULE WITH SPACES" in loc for loc in locs), locs


def test_lint_rule_id_format_heuristic_passes_normal_ids(tmp_path):
    cfg = _write(
        tmp_path / ".securescan.yml",
        """
severity_overrides:
  SEMGREP-XYZ: medium
  python.lang.security.audit.x: low
  B305: info
ignored_rules:
  - SEMGREP-ABC
  - python.dangerous-default-value
  - B101
""",
    )

    report = lint_config(cfg)

    assert not report.has_warnings, [i.message for i in report.warnings()]
    assert not report.has_errors


def test_lint_collision_between_ignored_and_overridden_yields_warning(tmp_path):
    cfg = _write(
        tmp_path / ".securescan.yml",
        """
severity_overrides:
  RULE-COLLISION: medium
ignored_rules:
  - RULE-COLLISION
""",
    )

    report = lint_config(cfg)

    assert not report.has_errors
    assert report.has_warnings
    msgs = [i.message for i in report.warnings()]
    assert any("RULE-COLLISION" in m and "ignored_rules" in m for m in msgs), msgs


def test_lint_empty_yaml_file_yields_info_issue(tmp_path):
    cfg = _write(tmp_path / ".securescan.yml", "")

    report = lint_config(cfg)

    assert not report.has_errors
    info_issues = [i for i in report.issues if i.severity == "info"]
    assert len(info_issues) == 1
    assert "empty" in info_issues[0].message.lower()


def test_lint_report_has_errors_when_any_error_present():
    report = LintReport(issues=[
        LintIssue(severity="warning", message="w"),
        LintIssue(severity="error", message="e"),
        LintIssue(severity="info", message="i"),
    ])
    assert report.has_errors is True


def test_lint_report_has_warnings_only_when_warnings_present():
    no_warn = LintReport(issues=[LintIssue(severity="error", message="e")])
    with_warn = LintReport(issues=[LintIssue(severity="warning", message="w")])
    assert no_warn.has_warnings is False
    assert with_warn.has_warnings is True


def test_lint_report_errors_method_returns_only_errors():
    report = LintReport(issues=[
        LintIssue(severity="warning", message="w"),
        LintIssue(severity="error", message="e1"),
        LintIssue(severity="info", message="i"),
        LintIssue(severity="error", message="e2"),
    ])
    errors = report.errors()
    assert [e.message for e in errors] == ["e1", "e2"]
    assert all(e.severity == "error" for e in errors)
