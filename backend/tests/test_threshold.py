"""Tests for ``backend/src/threshold.py``."""

from __future__ import annotations

from dataclasses import dataclass

from securescan.models import Severity
from securescan.threshold import count_at_or_above


@dataclass
class _StubFinding:
    severity: Severity


def test_count_at_or_above_includes_threshold():
    findings = [
        _StubFinding(Severity.CRITICAL),
        _StubFinding(Severity.HIGH),
        _StubFinding(Severity.MEDIUM),
        _StubFinding(Severity.LOW),
        _StubFinding(Severity.INFO),
    ]
    # HIGH threshold should count critical + high (the two at-or-above)
    assert count_at_or_above(findings, Severity.HIGH) == 2
    # CRITICAL threshold counts only critical
    assert count_at_or_above(findings, Severity.CRITICAL) == 1
    # MEDIUM threshold counts critical + high + medium
    assert count_at_or_above(findings, Severity.MEDIUM) == 3


def test_count_at_or_above_excludes_below():
    # Nothing below the threshold should leak in
    findings = [
        _StubFinding(Severity.LOW),
        _StubFinding(Severity.LOW),
        _StubFinding(Severity.INFO),
    ]
    assert count_at_or_above(findings, Severity.HIGH) == 0
    assert count_at_or_above(findings, Severity.MEDIUM) == 0


def test_count_at_or_above_zero_for_empty():
    assert count_at_or_above([], Severity.CRITICAL) == 0
    assert count_at_or_above([], Severity.LOW) == 0


def test_count_at_or_above_low_threshold_includes_everything_but_info():
    findings = [
        _StubFinding(Severity.CRITICAL),
        _StubFinding(Severity.HIGH),
        _StubFinding(Severity.MEDIUM),
        _StubFinding(Severity.LOW),
        _StubFinding(Severity.INFO),
    ]
    # LOW threshold = rank 1, INFO = rank 0 -> 4 should count
    assert count_at_or_above(findings, Severity.LOW) == 4
