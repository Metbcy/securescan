"""SARIF partialFingerprints + in-pass dedup contract tests for SS8.

GitHub Code Scanning's "is this the same alert across uploads?" check
is keyed off ``result.partialFingerprints``. We emit our stable
fingerprint under the namespace key ``securescan/v1`` so the algorithm
itself is versioned — a future fingerprint change can ship as
``securescan/v2`` without re-keying existing alerts on the Security tab.

In-pass dedup catches scanners (e.g. some Semgrep configurations) that
emit the same logical finding twice in one run; without it the user
would see two identical alerts on the Security tab. Dedup is keyed on
``finding.fingerprint`` (the truth), not ``(rule_id, file, line)``.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime

from securescan.exporters import findings_to_sarif
from securescan.models import Finding, Scan, ScanStatus, ScanType, Severity


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _scan() -> Scan:
    return Scan(
        id="scan-fixed-id",
        target_path="/tmp/proj",
        scan_types=[ScanType.CODE],
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, 0, 0, 0),
        completed_at=datetime(2026, 1, 1, 0, 5, 0),
        findings_count=0,
        risk_score=0.0,
    )


def _finding(
    *,
    fingerprint: str = "",
    rule_id: str = "py.sqli",
    file_path: str = "app/db.py",
    line_start: int | None = 42,
    severity: Severity = Severity.HIGH,
    title: str = "SQL Injection",
    description: str = "user input concatenated into SQL",
) -> Finding:
    return Finding(
        scan_id="s",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=severity,
        title=title,
        description=description,
        file_path=file_path,
        line_start=line_start,
        rule_id=rule_id,
        fingerprint=fingerprint,
    )


# ---------------------------------------------------------------------------
# partialFingerprints emission
# ---------------------------------------------------------------------------


def test_sarif_each_result_has_partial_fingerprint_when_finding_has_fingerprint():
    findings = [
        _finding(fingerprint="a" * 64, rule_id="r1", file_path="a.py", line_start=1),
        _finding(fingerprint="b" * 64, rule_id="r2", file_path="b.py", line_start=2),
        _finding(fingerprint="c" * 64, rule_id="r3", file_path="c.py", line_start=3),
    ]
    sarif = findings_to_sarif(findings, _scan())
    results = sarif["runs"][0]["results"]
    assert len(results) == 3
    for result in results:
        assert "partialFingerprints" in result
        assert isinstance(result["partialFingerprints"], dict)
        assert len(result["partialFingerprints"]) == 1


def test_sarif_partial_fingerprint_uses_securescan_v1_namespace_key():
    fp = "deadbeef" * 8  # 64-char hex
    findings = [_finding(fingerprint=fp)]
    sarif = findings_to_sarif(findings, _scan())
    pf = sarif["runs"][0]["results"][0]["partialFingerprints"]
    assert "securescan/v1" in pf
    assert pf["securescan/v1"] == fp
    # No other keys — exactly one namespaced fingerprint.
    assert list(pf.keys()) == ["securescan/v1"]


def test_sarif_omits_partial_fingerprint_when_finding_fingerprint_empty():
    findings = [_finding(fingerprint="")]
    sarif = findings_to_sarif(findings, _scan())
    result = sarif["runs"][0]["results"][0]
    assert "partialFingerprints" not in result


# ---------------------------------------------------------------------------
# In-pass dedup
# ---------------------------------------------------------------------------


def test_sarif_dedupes_results_with_identical_fingerprints():
    fp = "f" * 64
    findings = [
        _finding(fingerprint=fp, line_start=10),
        _finding(fingerprint=fp, line_start=20),
    ]
    sarif = findings_to_sarif(findings, _scan())
    assert len(sarif["runs"][0]["results"]) == 1


def test_sarif_dedup_preserves_lowest_line_number():
    fp = "1" * 64
    findings = [
        _finding(fingerprint=fp, line_start=99),
        _finding(fingerprint=fp, line_start=5),
        _finding(fingerprint=fp, line_start=42),
    ]
    sarif = findings_to_sarif(findings, _scan())
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    region = results[0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 5


def test_sarif_dedup_skipped_when_fingerprint_empty():
    findings = [
        _finding(fingerprint="", line_start=10),
        _finding(fingerprint="", line_start=20),
    ]
    sarif = findings_to_sarif(findings, _scan())
    # Both must appear because empty fingerprint == "treat as unique".
    assert len(sarif["runs"][0]["results"]) == 2


def test_sarif_dedup_does_not_collapse_distinct_fingerprints():
    findings = [
        _finding(fingerprint="a" * 64, rule_id="r1", file_path="a.py", line_start=1),
        _finding(fingerprint="b" * 64, rule_id="r1", file_path="a.py", line_start=2),
    ]
    sarif = findings_to_sarif(findings, _scan())
    assert len(sarif["runs"][0]["results"]) == 2


def test_sarif_dedup_mixed_empty_and_populated_fingerprints():
    """Empty-fp findings are not deduped; populated-fp findings are.
    Both kinds should coexist in the same render.
    """
    fp = "9" * 64
    findings = [
        _finding(fingerprint=fp, rule_id="r1", file_path="a.py", line_start=10),
        _finding(fingerprint=fp, rule_id="r1", file_path="a.py", line_start=20),
        _finding(fingerprint="", rule_id="r2", file_path="b.py", line_start=5),
        _finding(fingerprint="", rule_id="r2", file_path="b.py", line_start=15),
    ]
    sarif = findings_to_sarif(findings, _scan())
    # 1 deduped (fp) + 2 unique (empty fp) = 3 results
    assert len(sarif["runs"][0]["results"]) == 3


# ---------------------------------------------------------------------------
# SARIF v2.1.0 compliance + determinism
# ---------------------------------------------------------------------------


def test_sarif_remains_v2_1_0_compliant():
    """partialFingerprints is a standard SARIF v2.1.0 field; verify the
    schema URL and version string still claim 2.1.0 after our additions.
    """
    findings = [_finding(fingerprint="a" * 64)]
    sarif = findings_to_sarif(findings, _scan())
    assert "2.1.0" in sarif["$schema"]
    assert sarif["version"] == "2.1.0"


def test_sarif_render_byte_identical_with_partial_fingerprints():
    """Adding partialFingerprints must not introduce non-determinism:
    same input must yield byte-identical SARIF across two renders, even
    when input order differs.
    """
    findings_a = [
        _finding(fingerprint="a" * 64, rule_id="r1", file_path="a.py", line_start=1),
        _finding(fingerprint="b" * 64, rule_id="r2", file_path="b.py", line_start=2),
        _finding(fingerprint="c" * 64, rule_id="r3", file_path="c.py", line_start=3),
        _finding(fingerprint="", rule_id="r4", file_path="d.py", line_start=4),
    ]
    findings_b = list(reversed(copy.deepcopy(findings_a)))
    scan_a = _scan()
    scan_b = copy.deepcopy(scan_a)

    out_a = json.dumps(findings_to_sarif(findings_a, scan_a), indent=2, sort_keys=True, default=str)
    out_b = json.dumps(findings_to_sarif(findings_b, scan_b), indent=2, sort_keys=True, default=str)

    assert out_a == out_b
    # Sanity: at least one partialFingerprints block actually appears.
    assert "securescan/v1" in out_a


def test_sarif_render_byte_identical_when_dedup_target_order_differs():
    """When the input contains duplicate-fingerprint findings, the same
    representative must be picked regardless of which order the dupes
    arrive in. Re-runs of a flaky scanner must not flip the chosen
    line_start.
    """
    fp = "7" * 64
    findings_a = [
        _finding(fingerprint=fp, line_start=10),
        _finding(fingerprint=fp, line_start=5),
        _finding(fingerprint=fp, line_start=20),
    ]
    findings_b = [
        _finding(fingerprint=fp, line_start=20),
        _finding(fingerprint=fp, line_start=10),
        _finding(fingerprint=fp, line_start=5),
    ]
    scan_a = _scan()
    scan_b = copy.deepcopy(scan_a)

    out_a = json.dumps(findings_to_sarif(findings_a, scan_a), indent=2, sort_keys=True, default=str)
    out_b = json.dumps(findings_to_sarif(findings_b, scan_b), indent=2, sort_keys=True, default=str)

    assert out_a == out_b


def test_sarif_dedup_prefers_concrete_line_over_none():
    """A finding with a concrete line_start is more actionable for the
    user than one with line_start=None; dedup should keep the concrete
    one even if the None-line one was encountered first.
    """
    fp = "e" * 64
    findings = [
        _finding(fingerprint=fp, line_start=None),
        _finding(fingerprint=fp, line_start=42),
    ]
    sarif = findings_to_sarif(findings, _scan())
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    region = results[0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 42
