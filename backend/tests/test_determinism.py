"""Determinism contract tests for SS3.

Each renderer (SARIF, CSV, JUnit, JSON model dump, HTML report,
CycloneDX SBOM, SPDX SBOM) must produce byte-identical output when
called twice with the same logical inputs. This is what lets the
PR-comment renderer upsert without churn and lets SARIF re-uploads to
the GitHub Security tab not generate false-new-alert noise.

Wall-clock leaks are pinned via the ``SECURESCAN_FAKE_NOW`` env var.
PDF determinism is intentionally NOT covered: WeasyPrint embeds font
and producer metadata that depends on host font cache state.
"""
from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path

import pytest

from securescan.exporters import findings_to_csv, findings_to_junit, findings_to_sarif
from securescan.models import (
    Finding,
    SBOMComponent,
    SBOMDocument,
    Scan,
    ScanStatus,
    ScanType,
    Severity,
)
from securescan.ordering import sort_findings_canonical
from securescan.reports import ReportGenerator
from securescan.sbom import SBOMGenerator
from securescan.scoring import build_summary


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _findings_bag() -> list[Finding]:
    """A deliberately unsorted bag of findings covering every code path."""
    return [
        Finding(
            scan_id="s",
            scanner="bandit",
            scan_type=ScanType.CODE,
            severity=Severity.LOW,
            title="weak random",
            description="random.random() used",
            file_path="app/util.py",
            line_start=10,
            rule_id="B311",
        ),
        Finding(
            scan_id="s",
            scanner="semgrep",
            scan_type=ScanType.CODE,
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="user input concatenated into SQL",
            file_path="app/db.py",
            line_start=42,
            rule_id="py.sqli",
            cwe="CWE-89",
        ),
        Finding(
            scan_id="s",
            scanner="semgrep",
            scan_type=ScanType.CODE,
            severity=Severity.HIGH,
            title="hardcoded secret",
            description="api key in source",
            file_path="app/config.py",
            line_start=5,
            rule_id="py.secret",
        ),
        Finding(
            scan_id="s",
            scanner="bandit",
            scan_type=ScanType.CODE,
            severity=Severity.HIGH,
            title="shell injection",
            description="subprocess shell=True with user input",
            file_path="app/cmd.py",
            line_start=8,
            rule_id="B602",
        ),
        Finding(
            scan_id="s",
            scanner="bandit",
            scan_type=ScanType.CODE,
            severity=Severity.HIGH,
            title="shell injection",
            description="subprocess shell=True with user input (second site)",
            file_path="app/cmd.py",
            line_start=20,
            rule_id="B602",
        ),
    ]


def _scan() -> Scan:
    return Scan(
        id="scan-fixed-id",
        target_path="/tmp/proj",
        scan_types=[ScanType.CODE],
        status=ScanStatus.COMPLETED,
        started_at=datetime(2026, 1, 1, 0, 0, 0),
        completed_at=datetime(2026, 1, 1, 0, 5, 0),
        findings_count=5,
        risk_score=42.0,
    )


# ---------------------------------------------------------------------------
# sort_findings_canonical
# ---------------------------------------------------------------------------


def test_sort_findings_canonical_orders_by_severity_then_file_then_line():
    findings = _findings_bag()
    sorted_f = sort_findings_canonical(findings)
    keys = [
        (f.severity.value, f.file_path, f.line_start, f.rule_id, f.title)
        for f in sorted_f
    ]
    assert keys == [
        # CRITICAL first
        ("critical", "app/db.py", 42, "py.sqli", "SQL Injection"),
        # HIGH next, ordered by file_path, then line_start
        ("high", "app/cmd.py", 8, "B602", "shell injection"),
        ("high", "app/cmd.py", 20, "B602", "shell injection"),
        ("high", "app/config.py", 5, "py.secret", "hardcoded secret"),
        # LOW last
        ("low", "app/util.py", 10, "B311", "weak random"),
    ]


def test_sort_findings_canonical_is_idempotent():
    findings = _findings_bag()
    once = sort_findings_canonical(findings)
    twice = sort_findings_canonical(once)
    thrice = sort_findings_canonical(twice)
    assert [f.id for f in once] == [f.id for f in twice] == [f.id for f in thrice]


def test_sort_findings_canonical_does_not_mutate_input():
    findings = _findings_bag()
    original_ids = [f.id for f in findings]
    sort_findings_canonical(findings)
    assert [f.id for f in findings] == original_ids


def test_sort_findings_canonical_handles_missing_optional_fields():
    findings = [
        Finding(
            scan_id="s",
            scanner="x",
            scan_type=ScanType.CODE,
            severity=Severity.MEDIUM,
            title="z-no-file",
            description="",
        ),
        Finding(
            scan_id="s",
            scanner="x",
            scan_type=ScanType.CODE,
            severity=Severity.MEDIUM,
            title="a-with-file",
            description="",
            file_path="a.py",
            line_start=1,
            rule_id="r1",
        ),
        Finding(
            scan_id="s",
            scanner="x",
            scan_type=ScanType.CODE,
            severity=Severity.MEDIUM,
            title="middle",
            description="",
            file_path="a.py",
            # line_start missing -> collates as 0
            rule_id=None,
        ),
        Finding(
            scan_id="s",
            scanner="x",
            scan_type=ScanType.CODE,
            severity=Severity.CRITICAL,
            title="top",
            description="",
        ),
    ]
    sorted_f = sort_findings_canonical(findings)
    # CRITICAL first; within MEDIUM, empty file_path collates before "a.py";
    # within "a.py" the line_start=0 (None) item comes before line_start=1.
    assert [f.title for f in sorted_f] == [
        "top",
        "z-no-file",
        "middle",
        "a-with-file",
    ]


def test_sort_findings_canonical_returns_new_list():
    findings = _findings_bag()
    out = sort_findings_canonical(findings)
    assert out is not findings


# ---------------------------------------------------------------------------
# SARIF byte-identity
# ---------------------------------------------------------------------------


def test_sarif_render_is_byte_identical():
    findings_a = _findings_bag()
    findings_b = copy.deepcopy(findings_a)
    scan_a = _scan()
    scan_b = copy.deepcopy(scan_a)

    sarif_a = json.dumps(findings_to_sarif(findings_a, scan_a), indent=2, default=str)
    sarif_b = json.dumps(findings_to_sarif(findings_b, scan_b), indent=2, default=str)

    assert sarif_a == sarif_b


def test_sarif_render_is_byte_identical_when_input_order_differs():
    findings_a = _findings_bag()
    findings_b = list(reversed(copy.deepcopy(findings_a)))
    scan_a = _scan()
    scan_b = copy.deepcopy(scan_a)

    sarif_a = json.dumps(findings_to_sarif(findings_a, scan_a), indent=2, default=str)
    sarif_b = json.dumps(findings_to_sarif(findings_b, scan_b), indent=2, default=str)

    assert sarif_a == sarif_b


def test_sarif_does_not_leak_invocation_wall_clock():
    """Invocation timestamps would change between re-runs of the same
    logical scan and trigger false-new-alert noise on GitHub's Security
    tab; the SARIF generator must omit them.
    """
    sarif = findings_to_sarif(_findings_bag(), _scan())
    inv = sarif["runs"][0]["invocations"][0]
    assert "startTimeUtc" not in inv
    assert "endTimeUtc" not in inv


def test_sarif_rules_are_sorted_lexicographically():
    sarif = findings_to_sarif(_findings_bag(), _scan())
    rule_ids = [r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids == sorted(rule_ids)


def test_sarif_results_follow_canonical_finding_order():
    sarif = findings_to_sarif(_findings_bag(), _scan())
    rule_ids = [r["ruleId"] for r in sarif["runs"][0]["results"]]
    # Critical first, then highs (file order), then low.
    assert rule_ids == ["py.sqli", "B602", "B602", "py.secret", "B311"]


# ---------------------------------------------------------------------------
# CSV / JUnit byte-identity
# ---------------------------------------------------------------------------


def test_csv_render_is_byte_identical():
    findings_a = _findings_bag()
    findings_b = list(reversed(copy.deepcopy(findings_a)))

    csv_a = findings_to_csv(findings_a)
    csv_b = findings_to_csv(findings_b)

    assert csv_a == csv_b


def test_csv_render_uses_canonical_order():
    csv = findings_to_csv(_findings_bag())
    body_lines = csv.splitlines()[1:]  # skip header
    severities = [line.split(",", 1)[0] for line in body_lines]
    assert severities == ["critical", "high", "high", "high", "low"]


def test_junit_render_is_byte_identical():
    findings_a = _findings_bag()
    findings_b = list(reversed(copy.deepcopy(findings_a)))
    scan_a = _scan()
    scan_b = copy.deepcopy(scan_a)

    junit_a = findings_to_junit(findings_a, scan_a)
    junit_b = findings_to_junit(findings_b, scan_b)

    assert junit_a == junit_b


# ---------------------------------------------------------------------------
# SBOM byte-identity (CycloneDX + SPDX)
# ---------------------------------------------------------------------------


def _fixed_sbom_doc() -> SBOMDocument:
    """An SBOM doc with explicit IDs and timestamp so byte-identity is
    not perturbed by per-construction UUIDs / wall clock.
    """
    doc = SBOMDocument(
        id="sbom-fixed-id",
        target_path="/tmp/proj",
        components=[
            # Built in unsorted order on purpose; SBOMGenerator should sort
            # them in generate(), but for export-only tests we still want
            # the exporter to be deterministic for whatever comes in.
            SBOMComponent(
                id="comp-z",
                sbom_id="sbom-fixed-id",
                name="zlib",
                version="1.0",
                purl="pkg:npm/zlib@1.0",
            ),
            SBOMComponent(
                id="comp-a",
                sbom_id="sbom-fixed-id",
                name="alpha",
                version="2.0",
                purl="pkg:pypi/alpha@2.0",
                license="MIT",
            ),
        ],
        created_at=datetime(2026, 1, 1, 0, 0, 0),
    )
    return doc


def test_sbom_cyclonedx_is_byte_identical_with_frozen_now(monkeypatch):
    monkeypatch.setenv("SECURESCAN_FAKE_NOW", "2026-01-01T00:00:00")
    doc_a = _fixed_sbom_doc()
    doc_b = copy.deepcopy(doc_a)
    gen = SBOMGenerator("/tmp/proj")

    out_a = json.dumps(gen.export_cyclonedx(doc_a), indent=2, default=str)
    out_b = json.dumps(gen.export_cyclonedx(doc_b), indent=2, default=str)

    assert out_a == out_b
    assert "2026-01-01T00:00:00" in out_a  # timestamp came through


def test_sbom_spdx_is_byte_identical_with_frozen_now(monkeypatch):
    monkeypatch.setenv("SECURESCAN_FAKE_NOW", "2026-01-01T00:00:00")
    doc_a = _fixed_sbom_doc()
    doc_b = copy.deepcopy(doc_a)
    gen = SBOMGenerator("/tmp/proj")

    out_a = json.dumps(gen.export_spdx(doc_a), indent=2, default=str)
    out_b = json.dumps(gen.export_spdx(doc_b), indent=2, default=str)

    assert out_a == out_b
    assert "2026-01-01T00:00:00" in out_a


@pytest.mark.asyncio
async def test_sbom_generate_components_are_sorted(tmp_path, monkeypatch):
    """SBOMGenerator.generate() must emit components in canonical
    (name, version, purl) order so re-runs against the same source tree
    yield byte-identical exports even when the filesystem walk visits
    manifests in a different order.
    """
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setenv("SECURESCAN_FAKE_NOW", "2026-01-01T00:00:00")

    (tmp_path / "package.json").write_text(json.dumps({
        "name": "p",
        "dependencies": {
            "zebra": "1.0.0",
            "apple": "2.0.0",
            "mango": "3.0.0",
        },
    }))

    gen = SBOMGenerator(str(tmp_path))
    doc = await gen.generate()

    names = [c.name for c in doc.components]
    assert names == sorted(names)
    assert doc.created_at == datetime(2026, 1, 1, 0, 0, 0)


# ---------------------------------------------------------------------------
# HTML report byte-identity
# ---------------------------------------------------------------------------


@pytest.fixture
def html_generator() -> ReportGenerator:
    template_dir = Path(__file__).resolve().parent.parent / "securescan" / "templates" / "reports"
    return ReportGenerator(template_dir)


def test_html_report_excludes_or_freezes_wall_clock(html_generator, monkeypatch):
    """Re-rendering the same scan/findings/summary must produce the same
    HTML bytes. ``SECURESCAN_FAKE_NOW`` is set to make absolutely sure
    no implicit ``datetime.now()`` would slip into the output.
    """
    monkeypatch.setenv("SECURESCAN_FAKE_NOW", "2026-01-01T00:00:00")

    scan_a = _scan()
    findings_a = _findings_bag()
    summary_a = build_summary(findings_a, ["semgrep", "bandit"])

    scan_b = copy.deepcopy(scan_a)
    findings_b = list(reversed(copy.deepcopy(findings_a)))
    summary_b = build_summary(findings_b, ["bandit", "semgrep"])  # different order on purpose

    html_a = html_generator.generate_html(scan_a, findings_a, summary_a, compliance_coverage=[])
    html_b = html_generator.generate_html(scan_b, findings_b, summary_b, compliance_coverage=[])

    assert html_a == html_b


def test_html_report_findings_appear_in_canonical_order(html_generator):
    scan = _scan()
    findings = _findings_bag()
    summary = build_summary(findings, ["semgrep", "bandit"])
    html = html_generator.generate_html(scan, findings, summary, compliance_coverage=[])

    # The CRITICAL SQL Injection title must appear before the HIGH and
    # LOW finding titles in the rendered HTML.
    sqli_pos = html.index("SQL Injection")
    shell_pos = html.index("shell injection")
    weak_random_pos = html.index("weak random")
    assert sqli_pos < shell_pos < weak_random_pos
