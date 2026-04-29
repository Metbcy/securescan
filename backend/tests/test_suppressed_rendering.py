"""Suppressed-finding rendering contract tests for TS6.

A security tool that hides findings without surfacing what was hidden
becomes a silent-mute attack vector: a malicious .securescan.yml or
inline ignore comment can silently disable detection. TS6's contract
is to make every renderer aware of suppressed findings so the audit
trail is always visible at the right ergonomic surface:

* TTY / text output: show suppressed findings with a
  ``[SUPPRESSED:<reason>]`` prefix so a developer running locally
  immediately sees what would have been hidden in CI.
* PR comment / SARIF / JSON / CSV / JUnit: hide suppressed findings
  by default (low noise on the canonical CI surface). When
  ``show_suppressed=True`` is passed every renderer includes them
  with a format-appropriate marker.

These tests exercise the renderer behaviour directly with hand-built
``metadata['suppressed_by']`` stamps -- the integration with
``SuppressionContext.apply()`` is owned by the wire-cli-flow agent
(TS10). The CLI tests at the bottom of this file only assert that
the new flags are accepted by the ``scan`` / ``diff`` / ``compare``
typer surface; the full end-to-end pipeline is TS10 territory.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from typer.testing import CliRunner

from securescan.cli import (
    _default_show_suppressed,
    _render_compare_text,
    _render_diff_text,
    app,
)
from securescan.diff import ChangeSet
from securescan.exporters import (
    findings_to_csv,
    findings_to_json,
    findings_to_junit,
    findings_to_pr_comment,
    findings_to_sarif,
)
from securescan.models import (
    Finding,
    Scan,
    ScanStatus,
    ScanType,
    Severity,
)
from securescan.render_pr_comment import (
    MARKER,
    render_pr_comment,
)
from securescan.suppression import (
    REASON_BASELINE,
    REASON_CONFIG,
    REASON_INLINE,
    SuppressionContext,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _scan() -> Scan:
    return Scan(
        id="scan-fixed",
        target_path="/tmp/proj",
        scan_types=[ScanType.CODE],
        status=ScanStatus.COMPLETED,
    )


def _finding(
    *,
    title: str,
    rule_id: str = "RULE-001",
    file_path: str = "src/app.py",
    line_start: int = 10,
    severity: Severity = Severity.HIGH,
    fingerprint: str = "",
    suppressed_by: str | None = None,
) -> Finding:
    metadata: dict = {}
    if suppressed_by is not None:
        metadata["suppressed_by"] = suppressed_by
    return Finding(
        scan_id="scan-fixed",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=severity,
        title=title,
        description=f"Description for {title}.",
        file_path=file_path,
        line_start=line_start,
        line_end=line_start,
        rule_id=rule_id,
        cwe="CWE-89",
        remediation="Use parameterised queries.",
        metadata=metadata,
        fingerprint=fingerprint,
    )


def _two_kept_one_suppressed() -> list[Finding]:
    """Returns 3 findings: 2 normal + 1 stamped suppressed_by=inline.

    Distinct titles / file:line so canonical sort is well-defined.
    """
    return [
        _finding(
            title="A SQL injection",
            rule_id="RULE-A",
            file_path="src/a.py",
            line_start=10,
        ),
        _finding(
            title="B XSS",
            rule_id="RULE-B",
            file_path="src/b.py",
            line_start=20,
        ),
        _finding(
            title="C SUPPRESSED bug",
            rule_id="RULE-C",
            file_path="src/c.py",
            line_start=30,
            suppressed_by=REASON_INLINE,
        ),
    ]


# ---------------------------------------------------------------------------
# SuppressionContext.apply() round-trip: tests that the metadata stamp the
# real precedence resolver writes is the same string the renderers read.
# ---------------------------------------------------------------------------


def test_suppression_context_stamps_metadata_consumed_by_renderer():
    """The stamping in ``SuppressionContext.apply`` and the reading in
    the renderers must agree on the metadata key + reason string. If
    this round-trip ever breaks the renderers will silently fall back
    to 'not suppressed' for every finding -- the silent-mute attack
    vector this whole subsystem exists to prevent. Pin it.
    """
    from securescan.config_file import SecureScanConfig
    from securescan.suppression import IgnoreMap

    cfg = SecureScanConfig(ignored_rules={"RULE-C"})
    ctx = SuppressionContext(
        config=cfg,
        ignore_map=IgnoreMap(),
        baseline_fingerprints=frozenset(),
    )
    findings = [
        _finding(title="A", rule_id="RULE-A"),
        _finding(title="B", rule_id="RULE-B"),
        _finding(title="C", rule_id="RULE-C"),
    ]
    kept, suppressed = ctx.apply(findings)
    assert len(kept) == 2
    assert len(suppressed) == 1
    assert suppressed[0].metadata["suppressed_by"] == REASON_CONFIG

    # Now the SARIF renderer in default mode hides it,
    # show_suppressed=True surfaces it as a property.
    sarif_off = findings_to_sarif(kept + suppressed, _scan())
    assert len(sarif_off["runs"][0]["results"]) == 2

    sarif_on = findings_to_sarif(
        kept + suppressed, _scan(), show_suppressed=True
    )
    assert len(sarif_on["runs"][0]["results"]) == 3
    suppressed_results = [
        r for r in sarif_on["runs"][0]["results"]
        if r.get("properties", {}).get("suppressed_by") == REASON_CONFIG
    ]
    assert len(suppressed_results) == 1


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------


def test_sarif_default_filters_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_sarif(findings, _scan())
    rule_ids = [r["ruleId"] for r in out["runs"][0]["results"]]
    assert len(rule_ids) == 2
    assert "RULE-C" not in rule_ids


def test_sarif_show_suppressed_true_includes_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_sarif(findings, _scan(), show_suppressed=True)
    rule_ids = [r["ruleId"] for r in out["runs"][0]["results"]]
    assert len(rule_ids) == 3
    assert "RULE-C" in rule_ids


def test_sarif_show_suppressed_marks_with_reason():
    findings = _two_kept_one_suppressed()
    out = findings_to_sarif(findings, _scan(), show_suppressed=True)
    suppressed = [
        r for r in out["runs"][0]["results"]
        if r.get("properties", {}).get("suppressed_by")
    ]
    assert len(suppressed) == 1
    assert suppressed[0]["properties"]["suppressed_by"] == REASON_INLINE


def test_sarif_suppressed_finding_carries_suppressed_by_property_when_shown():
    """SARIF properties.suppressed_by is the cross-tool audit trail.
    Pin its presence and exact value.
    """
    findings = [
        _finding(title="A", rule_id="RULE-A"),
        _finding(
            title="B baseline-muted",
            rule_id="RULE-B",
            suppressed_by=REASON_BASELINE,
        ),
    ]
    out = findings_to_sarif(findings, _scan(), show_suppressed=True)
    matching = [
        r for r in out["runs"][0]["results"]
        if r["ruleId"] == "RULE-B"
    ]
    assert len(matching) == 1
    assert matching[0]["properties"]["suppressed_by"] == REASON_BASELINE


def test_sarif_default_off_does_not_add_suppressed_property():
    """When show_suppressed=False, no result should carry a
    suppressed_by property even if upstream metadata leaked in --
    because suppressed findings are filtered out entirely.
    """
    findings = _two_kept_one_suppressed()
    out = findings_to_sarif(findings, _scan())
    for result in out["runs"][0]["results"]:
        assert "suppressed_by" not in result.get("properties", {})


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def test_csv_default_filters_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_csv(findings)
    body_lines = out.splitlines()
    # 1 header + 2 rows, no third
    assert len(body_lines) == 3
    assert "C SUPPRESSED bug" not in out


def test_csv_default_header_unchanged_for_legacy_consumers():
    """Default-mode header must be byte-identical to pre-TS6
    (9-column form). CSV consumers schema-validate the header.
    """
    out = findings_to_csv(_two_kept_one_suppressed())
    assert out.splitlines()[0] == (
        "severity,scanner,title,file,line,rule_id,cwe,description,remediation"
    )


def test_csv_show_suppressed_true_includes_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_csv(findings, show_suppressed=True)
    body_lines = out.splitlines()
    assert len(body_lines) == 4
    assert "C SUPPRESSED bug" in out


def test_csv_show_suppressed_marks_with_reason():
    findings = _two_kept_one_suppressed()
    out = findings_to_csv(findings, show_suppressed=True)
    header = out.splitlines()[0]
    assert header.endswith(",suppressed")
    rows = out.splitlines()[1:]
    suppressed_row = next(r for r in rows if "C SUPPRESSED bug" in r)
    assert suppressed_row.endswith(f",{REASON_INLINE}")
    # Non-suppressed rows have an empty trailing cell.
    non_suppressed = [r for r in rows if "C SUPPRESSED bug" not in r]
    for r in non_suppressed:
        assert r.endswith(",")


# ---------------------------------------------------------------------------
# JUnit
# ---------------------------------------------------------------------------


def test_junit_default_filters_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_junit(findings, _scan())
    root = ET.fromstring(out)
    cases = root.findall("testcase")
    assert len(cases) == 2
    assert all("SUPPRESSED" not in c.get("name", "") for c in cases)
    assert root.get("tests") == "2"


def test_junit_show_suppressed_true_includes_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_junit(findings, _scan(), show_suppressed=True)
    root = ET.fromstring(out)
    cases = root.findall("testcase")
    assert len(cases) == 3
    assert root.get("tests") == "3"


def test_junit_show_suppressed_marks_with_reason():
    """We surface suppression as <system-out>SUPPRESSED:<reason></system-out>
    inside the testcase. Avoid <skipped> because Jenkins treats it as
    'investigation needed' and a suppression is intentional."""
    findings = _two_kept_one_suppressed()
    out = findings_to_junit(findings, _scan(), show_suppressed=True)
    root = ET.fromstring(out)
    suppressed_case = next(
        c for c in root.findall("testcase")
        if "SUPPRESSED" in c.get("name", "")
    )
    sysouts = suppressed_case.findall("system-out")
    suppression_markers = [
        s.text for s in sysouts
        if s.text and s.text.startswith("SUPPRESSED:")
    ]
    assert suppression_markers == [f"SUPPRESSED:{REASON_INLINE}"]
    # No <skipped> element -- intentional choice (see docstring).
    assert suppressed_case.find("skipped") is None


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def test_json_default_filters_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_json(findings)
    parsed = json.loads(out)
    titles = [f["title"] for f in parsed]
    assert len(titles) == 2
    assert "C SUPPRESSED bug" not in titles


def test_json_show_suppressed_true_includes_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_json(findings, show_suppressed=True)
    parsed = json.loads(out)
    titles = [f["title"] for f in parsed]
    assert len(titles) == 3
    assert "C SUPPRESSED bug" in titles


def test_json_show_suppressed_marks_with_reason():
    """Pydantic dumps metadata as-is, so the reason travels through
    metadata.suppressed_by rather than via a renderer-added column.
    """
    findings = _two_kept_one_suppressed()
    out = findings_to_json(findings, show_suppressed=True)
    parsed = json.loads(out)
    suppressed = [
        f for f in parsed
        if f.get("metadata", {}).get("suppressed_by")
    ]
    assert len(suppressed) == 1
    assert suppressed[0]["metadata"]["suppressed_by"] == REASON_INLINE


# ---------------------------------------------------------------------------
# PR comment
# ---------------------------------------------------------------------------


def test_pr_comment_default_filters_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_pr_comment(findings)
    assert "C SUPPRESSED bug" not in out
    assert "[SUPPRESSED:" not in out


def test_pr_comment_show_suppressed_true_includes_suppressed():
    findings = _two_kept_one_suppressed()
    out = findings_to_pr_comment(findings, show_suppressed=True)
    assert "C SUPPRESSED bug" in out


def test_pr_comment_show_suppressed_marks_with_reason():
    findings = _two_kept_one_suppressed()
    out = findings_to_pr_comment(findings, show_suppressed=True)
    assert f"[SUPPRESSED:{REASON_INLINE}]" in out


def test_pr_comment_summary_counts_excluded_suppressed_by_default():
    """Summary table 'New: 2', not 'New: 3'. The default-off path
    filters BEFORE counting so the summary reflects what is shown.
    """
    findings = _two_kept_one_suppressed()
    out = findings_to_pr_comment(findings)
    assert "| New findings | 2 |" in out
    assert "| New findings | 3 |" not in out
    # No Suppressed row in default mode.
    assert "| Suppressed |" not in out


def test_pr_comment_summary_includes_suppressed_breakdown_when_show_true():
    """With show_suppressed=True, the summary gains a row breaking
    suppressed counts down by reason. Format: 'Suppressed: N
    (inline=I, config=C, baseline=B)'.
    """
    findings = [
        _finding(title="A", rule_id="RULE-A"),
        _finding(title="B", rule_id="RULE-B"),
        _finding(
            title="C inline-mute",
            rule_id="RULE-C",
            suppressed_by=REASON_INLINE,
        ),
    ]
    out = findings_to_pr_comment(findings, show_suppressed=True)
    assert "| Suppressed | 1 (inline=1, config=0, baseline=0) |" in out


def test_pr_comment_summary_breakdown_mixed_reasons():
    findings = [
        _finding(title="A", rule_id="RULE-A"),
        _finding(
            title="B inline",
            rule_id="RULE-B",
            suppressed_by=REASON_INLINE,
        ),
        _finding(
            title="C config",
            rule_id="RULE-C",
            suppressed_by=REASON_CONFIG,
        ),
        _finding(
            title="D baseline",
            rule_id="RULE-D",
            suppressed_by=REASON_BASELINE,
        ),
    ]
    out = findings_to_pr_comment(findings, show_suppressed=True)
    assert "| Suppressed | 3 (inline=1, config=1, baseline=1) |" in out


def test_pr_comment_marker_first_line_preserved_with_show_suppressed():
    """The upsert grep relies on the marker being line 1 in EVERY
    output. Adding the suppressed-breakdown row must not break that.
    """
    findings = _two_kept_one_suppressed()
    out_off = findings_to_pr_comment(findings)
    out_on = findings_to_pr_comment(findings, show_suppressed=True)
    assert out_off.splitlines()[0] == MARKER
    assert out_on.splitlines()[0] == MARKER


# ---------------------------------------------------------------------------
# Text renderers (cli._render_diff_text / _render_compare_text)
# ---------------------------------------------------------------------------


def test_text_diff_default_filters_suppressed():
    cs = ChangeSet(new=_two_kept_one_suppressed())
    out = _render_diff_text(cs)
    assert "C SUPPRESSED bug" not in out
    assert "[SUPPRESSED:" not in out
    # Counts reflect post-filter view.
    assert out.startswith("SecureScan diff: 2 new")


def test_text_diff_show_suppressed_true_includes_suppressed():
    cs = ChangeSet(new=_two_kept_one_suppressed())
    out = _render_diff_text(cs, show_suppressed=True)
    assert "C SUPPRESSED bug" in out
    assert out.startswith("SecureScan diff: 3 new")


def test_text_diff_show_suppressed_marks_with_reason():
    cs = ChangeSet(new=_two_kept_one_suppressed())
    out = _render_diff_text(cs, show_suppressed=True)
    assert f"[SUPPRESSED:{REASON_INLINE}]" in out


def test_text_compare_default_filters_suppressed():
    cs = ChangeSet(new=_two_kept_one_suppressed())
    out = _render_compare_text(cs)
    assert "C SUPPRESSED bug" not in out
    assert out.startswith("SecureScan compare: 2 new since baseline")


def test_text_compare_show_suppressed_true_includes_suppressed():
    cs = ChangeSet(new=_two_kept_one_suppressed())
    out = _render_compare_text(cs, show_suppressed=True)
    assert "C SUPPRESSED bug" in out
    assert out.startswith("SecureScan compare: 3 new since baseline")


def test_text_compare_show_suppressed_marks_with_reason():
    cs = ChangeSet(new=_two_kept_one_suppressed())
    out = _render_compare_text(cs, show_suppressed=True)
    assert f"[SUPPRESSED:{REASON_INLINE}]" in out


# ---------------------------------------------------------------------------
# Determinism: byte-identical output for byte-identical input, with the
# flag in either state. Mirror the SS3 determinism contract.
# ---------------------------------------------------------------------------


def _diverse_findings() -> list[Finding]:
    return [
        _finding(
            title="A SQL",
            rule_id="RULE-A",
            file_path="src/a.py",
            line_start=10,
            severity=Severity.HIGH,
        ),
        _finding(
            title="B XSS",
            rule_id="RULE-B",
            file_path="src/b.py",
            line_start=20,
            severity=Severity.MEDIUM,
        ),
        _finding(
            title="C inline-mute",
            rule_id="RULE-C",
            file_path="src/c.py",
            line_start=30,
            severity=Severity.LOW,
            suppressed_by=REASON_INLINE,
        ),
        _finding(
            title="D config-mute",
            rule_id="RULE-D",
            file_path="src/d.py",
            line_start=40,
            severity=Severity.LOW,
            suppressed_by=REASON_CONFIG,
        ),
    ]


def test_renderer_determinism_with_show_suppressed_false():
    findings = _diverse_findings()

    sarif1 = findings_to_sarif(findings, _scan())
    sarif2 = findings_to_sarif(findings, _scan())
    assert json.dumps(sarif1, sort_keys=True) == json.dumps(
        sarif2, sort_keys=True
    )

    csv1 = findings_to_csv(findings)
    csv2 = findings_to_csv(findings)
    assert csv1 == csv2

    junit1 = findings_to_junit(findings, _scan())
    junit2 = findings_to_junit(findings, _scan())
    assert junit1 == junit2

    json1 = findings_to_json(findings)
    json2 = findings_to_json(findings)
    assert json1 == json2

    pr1 = findings_to_pr_comment(findings)
    pr2 = findings_to_pr_comment(findings)
    assert pr1 == pr2

    diff_text1 = _render_diff_text(ChangeSet(new=findings))
    diff_text2 = _render_diff_text(ChangeSet(new=findings))
    assert diff_text1 == diff_text2


def test_renderer_determinism_with_show_suppressed_true():
    findings = _diverse_findings()

    sarif1 = findings_to_sarif(findings, _scan(), show_suppressed=True)
    sarif2 = findings_to_sarif(findings, _scan(), show_suppressed=True)
    assert json.dumps(sarif1, sort_keys=True) == json.dumps(
        sarif2, sort_keys=True
    )

    csv1 = findings_to_csv(findings, show_suppressed=True)
    csv2 = findings_to_csv(findings, show_suppressed=True)
    assert csv1 == csv2

    junit1 = findings_to_junit(findings, _scan(), show_suppressed=True)
    junit2 = findings_to_junit(findings, _scan(), show_suppressed=True)
    assert junit1 == junit2

    json1 = findings_to_json(findings, show_suppressed=True)
    json2 = findings_to_json(findings, show_suppressed=True)
    assert json1 == json2

    pr1 = findings_to_pr_comment(findings, show_suppressed=True)
    pr2 = findings_to_pr_comment(findings, show_suppressed=True)
    assert pr1 == pr2

    diff_text1 = _render_diff_text(
        ChangeSet(new=findings), show_suppressed=True
    )
    diff_text2 = _render_diff_text(
        ChangeSet(new=findings), show_suppressed=True
    )
    assert diff_text1 == diff_text2


def test_default_off_output_matches_pre_ts6_for_unsuppressed_only():
    """If no findings carry metadata.suppressed_by, output with
    show_suppressed=False must be byte-identical to the pre-TS6
    output. Pin backward compat against the legacy CSV / SARIF
    consumers.
    """
    findings = [
        _finding(title="A SQL", rule_id="RULE-A"),
        _finding(title="B XSS", rule_id="RULE-B"),
    ]
    csv_default = findings_to_csv(findings)
    csv_explicit = findings_to_csv(findings, show_suppressed=False)
    assert csv_default == csv_explicit
    # Header is the legacy 9-column form.
    assert csv_default.splitlines()[0] == (
        "severity,scanner,title,file,line,rule_id,cwe,description,remediation"
    )

    sarif_default = findings_to_sarif(findings, _scan())
    sarif_explicit = findings_to_sarif(findings, _scan(), show_suppressed=False)
    assert json.dumps(sarif_default, sort_keys=True) == json.dumps(
        sarif_explicit, sort_keys=True
    )


# ---------------------------------------------------------------------------
# render_pr_comment (the lower-level renderer in render_pr_comment.py)
# ---------------------------------------------------------------------------


def test_render_pr_comment_filters_suppressed_in_new_and_fixed_by_default():
    cs = ChangeSet(
        new=[
            _finding(title="N1", rule_id="N1"),
            _finding(
                title="N2 muted",
                rule_id="N2",
                suppressed_by=REASON_INLINE,
            ),
        ],
        fixed=[
            _finding(title="F1", rule_id="F1"),
            _finding(
                title="F2 muted",
                rule_id="F2",
                suppressed_by=REASON_BASELINE,
            ),
        ],
    )
    out = render_pr_comment(cs)
    assert "N2 muted" not in out
    assert "F2 muted" not in out
    assert "| New findings | 1 |" in out
    assert "| Fixed findings | 1 |" in out


def test_render_pr_comment_show_suppressed_includes_in_new_and_fixed():
    cs = ChangeSet(
        new=[
            _finding(title="N1", rule_id="N1"),
            _finding(
                title="N2 muted",
                rule_id="N2",
                suppressed_by=REASON_INLINE,
            ),
        ],
        fixed=[
            _finding(title="F1", rule_id="F1"),
            _finding(
                title="F2 muted",
                rule_id="F2",
                suppressed_by=REASON_BASELINE,
            ),
        ],
    )
    out = render_pr_comment(cs, show_suppressed=True)
    assert "N2 muted" in out
    assert "F2 muted" in out
    assert "| New findings | 2 |" in out
    assert "| Fixed findings | 2 |" in out
    assert "| Suppressed | 2 (inline=1, config=0, baseline=1) |" in out


# ---------------------------------------------------------------------------
# CLI flag plumbing -- accept the new flags. Full pipeline integration
# is owned by TS10; here we only assert the CLI surface accepts them.
# ---------------------------------------------------------------------------


def _write_snapshot(path, findings: list[dict]) -> None:
    path.write_text(json.dumps({"findings": findings}))


def _snap_finding(**overrides) -> dict:
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


def test_diff_command_accepts_show_suppressed_flag(tmp_path):
    base_path = tmp_path / "base.json"
    head_path = tmp_path / "head.json"
    _write_snapshot(base_path, [])
    _write_snapshot(head_path, [_snap_finding()])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            "--base-snapshot",
            str(base_path),
            "--head-snapshot",
            str(head_path),
            "--show-suppressed",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output


def test_diff_command_accepts_hide_suppressed_flag(tmp_path):
    base_path = tmp_path / "base.json"
    head_path = tmp_path / "head.json"
    _write_snapshot(base_path, [])
    _write_snapshot(head_path, [_snap_finding()])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            "--base-snapshot",
            str(base_path),
            "--head-snapshot",
            str(head_path),
            "--hide-suppressed",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output


def test_diff_command_accepts_no_suppress_flag(tmp_path):
    base_path = tmp_path / "base.json"
    head_path = tmp_path / "head.json"
    _write_snapshot(base_path, [])
    _write_snapshot(head_path, [_snap_finding()])
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            "--base-snapshot",
            str(base_path),
            "--head-snapshot",
            str(head_path),
            "--no-suppress",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output


def test_compare_command_accepts_show_suppressed_flag(tmp_path, monkeypatch):
    """Compare with the new flag accepted -- monkeypatched scanner so
    we don't shell out to real scanners.
    """
    from securescan import cli as cli_mod

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps([]))

    async def _stub_scan(_target, _types, *, enable_ai):  # noqa: ARG001
        return []

    monkeypatch.setattr(cli_mod, "_run_scan_for_diff", _stub_scan)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline_path),
            "--show-suppressed",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output


def test_compare_command_accepts_hide_suppressed_flag(tmp_path, monkeypatch):
    from securescan import cli as cli_mod

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps([]))

    async def _stub_scan(_target, _types, *, enable_ai):  # noqa: ARG001
        return []

    monkeypatch.setattr(cli_mod, "_run_scan_for_diff", _stub_scan)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline_path),
            "--hide-suppressed",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output


def test_compare_command_accepts_no_suppress_flag(tmp_path, monkeypatch):
    from securescan import cli as cli_mod

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps([]))

    async def _stub_scan(_target, _types, *, enable_ai):  # noqa: ARG001
        return []

    monkeypatch.setattr(cli_mod, "_run_scan_for_diff", _stub_scan)
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(tmp_path),
            str(baseline_path),
            "--no-suppress",
            "--no-ai",
        ],
    )
    assert result.exit_code == 0, result.output


def test_scan_command_accepts_show_suppressed_flag(monkeypatch):
    """Run the scan command with --show-suppressed and verify the
    parser accepts the flag (no "no such option" error). Full pipeline
    behaviour belongs to TS10; here we monkey-patch ``_run_scan_async``
    so the test stays fast and side-effect-free.
    """
    from securescan import cli as cli_mod
    from securescan.models import Scan, ScanStatus

    async def _stub_run_scan_async(target, types, *, enable_ai):  # noqa: ARG001
        return (
            Scan(
                target_path=target,
                scan_types=types or [ScanType.CODE],
                status=ScanStatus.COMPLETED,
            ),
            [],
        )

    monkeypatch.setattr(cli_mod, "_run_scan_async", _stub_run_scan_async)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", ".", "--show-suppressed", "--no-ai", "--output", "json"],
    )
    assert result.exit_code == 0, result.output


def test_scan_command_accepts_hide_suppressed_flag(monkeypatch):
    from securescan import cli as cli_mod
    from securescan.models import Scan, ScanStatus

    async def _stub_run_scan_async(target, types, *, enable_ai):  # noqa: ARG001
        return (
            Scan(
                target_path=target,
                scan_types=types or [ScanType.CODE],
                status=ScanStatus.COMPLETED,
            ),
            [],
        )

    monkeypatch.setattr(cli_mod, "_run_scan_async", _stub_run_scan_async)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", ".", "--hide-suppressed", "--no-ai", "--output", "json"],
    )
    assert result.exit_code == 0, result.output


def test_scan_command_accepts_no_suppress_flag(monkeypatch):
    from securescan import cli as cli_mod
    from securescan.models import Scan, ScanStatus

    async def _stub_run_scan_async(target, types, *, enable_ai):  # noqa: ARG001
        return (
            Scan(
                target_path=target,
                scan_types=types or [ScanType.CODE],
                status=ScanStatus.COMPLETED,
            ),
            [],
        )

    monkeypatch.setattr(cli_mod, "_run_scan_async", _stub_run_scan_async)
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", ".", "--no-suppress", "--no-ai", "--output", "json"],
    )
    assert result.exit_code == 0, result.output


def test_diff_command_help_lists_new_flags():
    runner = CliRunner()
    result = runner.invoke(app, ["diff", "--help"], terminal_width=200)
    assert result.exit_code == 0
    assert "--show-suppressed" in result.output
    assert "--no-suppress" in result.output


def test_compare_command_help_lists_new_flags():
    runner = CliRunner()
    result = runner.invoke(app, ["compare", "--help"], terminal_width=200)
    assert result.exit_code == 0
    assert "--show-suppressed" in result.output
    assert "--no-suppress" in result.output


# ---------------------------------------------------------------------------
# _default_show_suppressed -- TTY-vs-pipe auto-default contract.
# ---------------------------------------------------------------------------


def test_default_show_suppressed_explicit_true_wins():
    """User-supplied True wins regardless of TTY state."""
    assert _default_show_suppressed(explicit=True, output_format="text") is True
    assert _default_show_suppressed(explicit=True, output_format="sarif") is True


def test_default_show_suppressed_explicit_false_wins():
    assert _default_show_suppressed(explicit=False, output_format="text") is False
    assert _default_show_suppressed(explicit=False, output_format="table") is False


def test_default_show_suppressed_text_on_tty_defaults_true(monkeypatch):
    import sys

    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    assert _default_show_suppressed(explicit=None, output_format="text") is True
    assert _default_show_suppressed(explicit=None, output_format="table") is True


def test_default_show_suppressed_text_when_piped_defaults_false(monkeypatch):
    import sys

    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    assert _default_show_suppressed(explicit=None, output_format="text") is False


def test_default_show_suppressed_non_text_formats_default_false(monkeypatch):
    """Even on a TTY, sarif/json/csv/junit/github-pr-comment default to
    False -- the audit prefix only makes sense for human-readable text.
    """
    import sys

    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    for fmt in ("sarif", "json", "csv", "junit", "github-pr-comment"):
        assert _default_show_suppressed(explicit=None, output_format=fmt) is False
