"""Tests for apply_severity_overrides.

Pinned contract:
  - rule_id is the match key (exact, case-sensitive).
  - metadata["original_severity"] is the *string* value of the original
    enum (JSON-serialisable, no special-casing in renderers).
  - Idempotency check is on metadata["original_severity"] presence, NOT on
    severity equality. Once stamped, hands off.
  - Edge case: when the override equals the current severity we still
    stamp + count. Rationale: user-pinned == audit data, even if the
    pinned value matches the current one. (See module docstring.)
"""
from __future__ import annotations

from securescan.config_file import SecureScanConfig
from securescan.models import Finding, ScanType, Severity
from securescan.severity import apply_severity_overrides


def _make_finding(
    rule_id: str | None = "RULE-A",
    severity: Severity = Severity.HIGH,
    **overrides,
) -> Finding:
    base = dict(
        scan_id="scan-1",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=severity,
        title="t",
        description="d",
        rule_id=rule_id,
    )
    base.update(overrides)
    return Finding(**base)


def test_no_overrides_is_noop():
    findings = [_make_finding(rule_id="RULE-A", severity=Severity.HIGH)]
    config = SecureScanConfig()  # severity_overrides={} by default

    out, n = apply_severity_overrides(findings, config)

    assert n == 0
    assert out is findings
    assert out[0].severity == Severity.HIGH
    assert "original_severity" not in out[0].metadata


def test_match_overrides_severity():
    findings = [_make_finding(rule_id="RULE-A", severity=Severity.HIGH)]
    config = SecureScanConfig(severity_overrides={"RULE-A": Severity.MEDIUM})

    out, n = apply_severity_overrides(findings, config)

    assert n == 1
    assert out[0].severity == Severity.MEDIUM
    assert out[0].metadata["original_severity"] == "high"


def test_non_matching_rule_left_alone():
    findings = [_make_finding(rule_id="RULE-Z", severity=Severity.HIGH)]
    config = SecureScanConfig(severity_overrides={"RULE-A": Severity.MEDIUM})

    out, n = apply_severity_overrides(findings, config)

    assert n == 0
    assert out[0].severity == Severity.HIGH
    assert "original_severity" not in out[0].metadata


def test_finding_without_rule_id_left_alone():
    findings = [_make_finding(rule_id=None, severity=Severity.HIGH)]
    config = SecureScanConfig(severity_overrides={"RULE-A": Severity.MEDIUM})

    out, n = apply_severity_overrides(findings, config)

    assert n == 0
    assert out[0].severity == Severity.HIGH
    assert "original_severity" not in out[0].metadata


def test_demote_critical_to_medium_records_original():
    findings = [_make_finding(rule_id="RULE-A", severity=Severity.CRITICAL)]
    config = SecureScanConfig(severity_overrides={"RULE-A": Severity.MEDIUM})

    out, n = apply_severity_overrides(findings, config)

    assert n == 1
    assert out[0].severity == Severity.MEDIUM
    assert out[0].metadata["original_severity"] == "critical"


def test_promote_low_to_high_records_original():
    findings = [_make_finding(rule_id="RULE-A", severity=Severity.LOW)]
    config = SecureScanConfig(severity_overrides={"RULE-A": Severity.HIGH})

    out, n = apply_severity_overrides(findings, config)

    assert n == 1
    assert out[0].severity == Severity.HIGH
    assert out[0].metadata["original_severity"] == "low"


def test_idempotent_second_call_is_noop():
    findings = [_make_finding(rule_id="RULE-A", severity=Severity.HIGH)]
    config = SecureScanConfig(severity_overrides={"RULE-A": Severity.MEDIUM})

    out1, n1 = apply_severity_overrides(findings, config)
    assert n1 == 1
    assert out1[0].severity == Severity.MEDIUM
    assert out1[0].metadata["original_severity"] == "high"

    out2, n2 = apply_severity_overrides(findings, config)

    assert n2 == 0
    assert out2[0].severity == Severity.MEDIUM
    # Stamp must reflect the *true* original, never the post-override value.
    assert out2[0].metadata["original_severity"] == "high"


def test_n_overridden_counts_only_actual_changes():
    findings = [
        _make_finding(rule_id="RULE-A", severity=Severity.HIGH),
        _make_finding(rule_id="RULE-B", severity=Severity.HIGH),
        _make_finding(rule_id="RULE-Z", severity=Severity.HIGH),  # not in config
    ]
    config = SecureScanConfig(
        severity_overrides={
            "RULE-A": Severity.MEDIUM,
            "RULE-B": Severity.LOW,
        }
    )

    out, n = apply_severity_overrides(findings, config)

    assert n == 2
    assert out[0].severity == Severity.MEDIUM
    assert out[1].severity == Severity.LOW
    assert out[2].severity == Severity.HIGH
    assert "original_severity" not in out[2].metadata


def test_mutates_in_place():
    findings = [_make_finding(rule_id="RULE-A", severity=Severity.HIGH)]
    original_ref = findings
    original_finding_ref = findings[0]
    config = SecureScanConfig(severity_overrides={"RULE-A": Severity.MEDIUM})

    out, _ = apply_severity_overrides(findings, config)

    assert out is original_ref
    assert out[0] is original_finding_ref
    # Caller's reference reflects the mutation without re-binding.
    assert original_ref[0].severity == Severity.MEDIUM


def test_finding_unchanged_when_override_equals_current_severity():
    """Edge case: user pins a rule at the severity it already has.

    Decision: still stamp original_severity ("high") and count this as
    overridden. The user explicitly pinning the rule is meaningful audit
    data; treating equal-severity as a silent no-op would create an
    inconsistent audit trail.
    """
    findings = [_make_finding(rule_id="RULE-A", severity=Severity.HIGH)]
    config = SecureScanConfig(severity_overrides={"RULE-A": Severity.HIGH})

    out, n = apply_severity_overrides(findings, config)

    assert n == 1
    assert out[0].severity == Severity.HIGH
    assert out[0].metadata["original_severity"] == "high"


def test_metadata_original_severity_is_string_not_enum():
    findings = [_make_finding(rule_id="RULE-A", severity=Severity.HIGH)]
    config = SecureScanConfig(severity_overrides={"RULE-A": Severity.MEDIUM})

    out, _ = apply_severity_overrides(findings, config)

    stamp = out[0].metadata["original_severity"]
    assert isinstance(stamp, str)
    # Importantly: not the enum itself, even though Severity inherits from str.
    assert type(stamp) is str
