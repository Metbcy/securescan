"""Tests for the GitHub PR-comment Markdown renderer.

The PR-comment renderer is the user-facing wedge for SecureScan v0.2.0:
a single, diff-aware comment that upserts in place across pushes via a
stable marker. These tests pin down the contract that the GitHub Action
(SS9) and the ``securescan diff`` subcommand (SS6) will rely on:

- the marker line is ALWAYS first (so the upsert grep is reliable)
- empty changesets still emit the marker
- per-severity bucketing in critical -> info order, empty buckets dropped
- canonical within-bucket ordering (matches every other renderer)
- repo+sha enables GitHub blob-URL links; missing either falls back to plain
- byte-identical output for byte-identical input (determinism invariant)
- no emojis (pinned v0.2.0 decision)
- description is first-sentence-or-truncated (chosen over raw paragraph)
"""
from __future__ import annotations

import re

import pytest

from src.diff import ChangeSet
from src.models import Finding, ScanType, Severity
from src.render_pr_comment import MARKER, render_pr_comment


def _make_finding(**overrides) -> Finding:
    base = dict(
        scan_id="scan-1",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=Severity.HIGH,
        title="SQL injection",
        description="A SQL injection vulnerability was detected in the query builder.",
        file_path="src/x.py",
        line_start=42,
        line_end=42,
        rule_id="RULE-001",
        cwe="CWE-89",
        remediation="Use parameterized queries instead of string concatenation.",
    )
    base.update(overrides)
    return Finding(**base)


# --- marker invariants ----------------------------------------------------


def test_marker_string_is_securescan_diff():
    assert MARKER == "<!-- securescan:diff -->"


def test_marker_is_first_line():
    cs = ChangeSet(new=[_make_finding()])
    out = render_pr_comment(cs)
    assert out.splitlines()[0] == MARKER


def test_marker_is_first_line_on_empty_changeset():
    out = render_pr_comment(ChangeSet())
    assert out.splitlines()[0] == MARKER


# --- empty / summary ------------------------------------------------------


def test_empty_changeset_renders_short_message():
    out = render_pr_comment(ChangeSet())
    assert MARKER in out
    assert "_No new or fixed findings._" in out
    # The empty-changeset body is intentionally tiny -- marker + one line.
    assert out.count("\n") <= 2


def test_summary_table_shows_new_fixed_unchanged_counts():
    cs = ChangeSet(
        new=[_make_finding(rule_id="N1"), _make_finding(rule_id="N2")],
        fixed=[_make_finding(rule_id="F1")],
        unchanged=[
            _make_finding(rule_id="U1"),
            _make_finding(rule_id="U2"),
            _make_finding(rule_id="U3"),
        ],
    )
    out = render_pr_comment(cs)
    assert "| Change | Count |" in out
    assert "| New findings | 2 |" in out
    assert "| Fixed findings | 1 |" in out
    assert "| Unchanged findings | 3 |" in out


# --- per-severity bucketing -----------------------------------------------


def test_new_findings_section_grouped_by_severity_critical_first():
    cs = ChangeSet(
        new=[
            _make_finding(severity=Severity.LOW, rule_id="L"),
            _make_finding(severity=Severity.CRITICAL, rule_id="C"),
            _make_finding(severity=Severity.MEDIUM, rule_id="M"),
            _make_finding(severity=Severity.HIGH, rule_id="H"),
        ],
    )
    out = render_pr_comment(cs)
    # Severity headings appear in critical -> info order in the New section.
    crit_idx = out.index("#### Critical")
    high_idx = out.index("#### High")
    med_idx = out.index("#### Medium")
    low_idx = out.index("#### Low")
    assert crit_idx < high_idx < med_idx < low_idx


def test_severity_subsection_omitted_when_no_findings_at_that_level():
    cs = ChangeSet(
        new=[
            _make_finding(severity=Severity.CRITICAL, rule_id="C"),
            _make_finding(severity=Severity.LOW, rule_id="L"),
        ],
    )
    out = render_pr_comment(cs)
    assert "#### Critical" in out
    assert "#### Low" in out
    # No findings at high / medium / info -> those subsections are dropped.
    assert "#### High" not in out
    assert "#### Medium" not in out
    assert "#### Info" not in out


def test_findings_within_severity_sorted_canonically():
    # Same severity, varying file/line -- canonical key is (sev desc, file
    # asc, line asc, rule_id asc, title asc), so b.py:5 must come before
    # b.py:10 must come before c.py:1.
    cs = ChangeSet(
        new=[
            _make_finding(file_path="c.py", line_start=1, rule_id="R3"),
            _make_finding(file_path="b.py", line_start=10, rule_id="R2"),
            _make_finding(file_path="b.py", line_start=5, rule_id="R1"),
        ],
    )
    out = render_pr_comment(cs)
    pos_b5 = out.index("b.py:5")
    pos_b10 = out.index("b.py:10")
    pos_c1 = out.index("c.py:1")
    assert pos_b5 < pos_b10 < pos_c1


# --- file references / GitHub links --------------------------------------


def test_with_repo_and_sha_renders_github_links():
    cs = ChangeSet(
        new=[_make_finding(file_path="src/x.py", line_start=42, line_end=42)],
    )
    out = render_pr_comment(cs, repo="owner/repo", sha="abc123")
    assert "https://github.com/owner/repo/blob/abc123/src/x.py#L42" in out


def test_without_repo_renders_plain_file_path():
    cs = ChangeSet(
        new=[_make_finding(file_path="src/x.py", line_start=42, line_end=42)],
    )
    out = render_pr_comment(cs)
    assert "src/x.py:42" in out
    assert "https://github.com" not in out


def test_without_sha_renders_plain_file_path():
    # Only repo, no sha -> still plain text. There's no useful link
    # without both.
    cs = ChangeSet(
        new=[_make_finding(file_path="src/x.py", line_start=42)],
    )
    out = render_pr_comment(cs, repo="owner/repo")
    assert "src/x.py:42" in out
    assert "https://github.com" not in out


def test_link_includes_line_range_when_line_end_present():
    cs = ChangeSet(
        new=[_make_finding(file_path="src/x.py", line_start=10, line_end=20)],
    )
    out = render_pr_comment(cs, repo="owner/repo", sha="abc123")
    assert "https://github.com/owner/repo/blob/abc123/src/x.py#L10-L20" in out
    # Display label also reflects the range.
    assert "src/x.py:10-20" in out


def test_link_omits_range_when_line_end_equals_line_start():
    cs = ChangeSet(
        new=[_make_finding(file_path="src/x.py", line_start=10, line_end=10)],
    )
    out = render_pr_comment(cs, repo="owner/repo", sha="abc123")
    assert "#L10" in out
    assert "#L10-L10" not in out


# --- determinism ----------------------------------------------------------


def test_render_is_deterministic():
    # Two ChangeSets with identical contents must produce byte-identical
    # output -- the same invariant SS3 pinned for SARIF / Markdown.
    def _build():
        return ChangeSet(
            new=[
                _make_finding(severity=Severity.HIGH, file_path="a.py", line_start=1, rule_id="R1"),
                _make_finding(severity=Severity.CRITICAL, file_path="b.py", line_start=2, rule_id="R2"),
            ],
            fixed=[
                _make_finding(severity=Severity.LOW, file_path="c.py", line_start=3, rule_id="R3"),
            ],
            unchanged=[
                _make_finding(severity=Severity.MEDIUM, file_path="d.py", line_start=4, rule_id="R4"),
            ],
        )

    first = render_pr_comment(_build(), repo="o/r", sha="deadbeef")
    second = render_pr_comment(_build(), repo="o/r", sha="deadbeef")
    assert first == second
    # And byte-identical at the bytes level too.
    assert first.encode("utf-8") == second.encode("utf-8")


def test_render_is_deterministic_when_input_order_varies():
    # Same logical findings in different input order -> same output.
    a = _make_finding(severity=Severity.HIGH, file_path="a.py", line_start=1, rule_id="R1")
    b = _make_finding(severity=Severity.CRITICAL, file_path="b.py", line_start=2, rule_id="R2")
    out1 = render_pr_comment(ChangeSet(new=[a, b]))
    out2 = render_pr_comment(ChangeSet(new=[b, a]))
    assert out1 == out2


# --- no emojis ------------------------------------------------------------


_EMOJI_REGEX = re.compile(
    "["
    "\U0001F300-\U0001FAFF"  # symbols, pictographs, emoticons, etc.
    "\U00002600-\U000027BF"  # misc symbols + dingbats (covers checkmark, cross, warning)
    "\U0001F000-\U0001F2FF"  # mahjong, dominoes, enclosed alphanumerics supplement
    "]"
)

_NAMED_EMOJI_LEAKS = ("\u2705", "\u274C", "\u26A0", "\U0001F525", "\U0001F389", "\U0001F6A8", "\u2B50")


def test_no_emojis_in_output():
    cs = ChangeSet(
        new=[
            _make_finding(severity=Severity.CRITICAL, rule_id="C"),
            _make_finding(severity=Severity.HIGH, rule_id="H"),
        ],
        fixed=[_make_finding(severity=Severity.LOW, rule_id="L")],
        unchanged=[_make_finding(severity=Severity.MEDIUM, rule_id="M")],
    )
    out = render_pr_comment(cs, repo="owner/repo", sha="abc123")
    assert _EMOJI_REGEX.search(out) is None, "renderer leaked an emoji into output"
    for ch in _NAMED_EMOJI_LEAKS:
        assert ch not in out, f"renderer leaked named emoji {ch!r}"

    # Empty-changeset path also emoji-free.
    empty_out = render_pr_comment(ChangeSet())
    assert _EMOJI_REGEX.search(empty_out) is None
    for ch in _NAMED_EMOJI_LEAKS:
        assert ch not in empty_out


# --- remediation / description --------------------------------------------


def test_remediation_field_rendered_when_present():
    f = _make_finding(remediation="Switch to parameterized queries.")
    out = render_pr_comment(ChangeSet(new=[f]))
    assert "Remediation" in out
    assert "Switch to parameterized queries." in out


def test_remediation_omitted_when_absent():
    f = _make_finding(remediation=None)
    out = render_pr_comment(ChangeSet(new=[f]))
    assert "Remediation" not in out


def test_remediation_not_rendered_in_fixed_section():
    # Fixed findings don't need remediation guidance -- they're already
    # gone. Only the New section renders it.
    f = _make_finding(remediation="Switch to parameterized queries.")
    out = render_pr_comment(ChangeSet(fixed=[f]))
    assert "Remediation" not in out


def test_description_truncated_to_first_sentence_or_120_chars():
    # First sentence within the 120-char cap -> kept verbatim.
    short = _make_finding(description="A short sentence. A second one that should be dropped.")
    out_short = render_pr_comment(ChangeSet(new=[short]))
    assert "A short sentence." in out_short
    assert "second one" not in out_short

    # No sentence boundary, longer than the cap -> hard-truncated with
    # an ellipsis.
    long_text = "x" * 500
    long_f = _make_finding(description=long_text)
    out_long = render_pr_comment(ChangeSet(new=[long_f]))
    # The full 500-char string is not present.
    assert long_text not in out_long
    # But a 119-char x-string with the ellipsis is.
    assert ("x" * 119) + "\u2026" in out_long


# --- structural / smoke ---------------------------------------------------


def test_h2_header_present_when_changeset_nonempty():
    cs = ChangeSet(new=[_make_finding()])
    out = render_pr_comment(cs)
    assert "## SecureScan: dependency & code change review" in out


def test_no_ansi_escape_codes_in_output():
    # The Action posts the body verbatim into a comment; ANSI bytes
    # would render as visible junk.
    cs = ChangeSet(
        new=[_make_finding()],
        fixed=[_make_finding(rule_id="F")],
    )
    out = render_pr_comment(cs)
    assert "\x1b" not in out


def test_finding_with_no_file_path_still_renders():
    f = _make_finding(file_path=None, line_start=None, line_end=None)
    out = render_pr_comment(ChangeSet(new=[f]))
    # No crash, finding title still appears.
    assert "SQL injection" in out


@pytest.mark.parametrize(
    "title",
    [
        "New findings",
        "Fixed findings",
    ],
)
def test_each_top_section_includes_count_in_heading(title):
    cs = ChangeSet(
        new=[_make_finding(rule_id="N1"), _make_finding(rule_id="N2")],
        fixed=[_make_finding(rule_id="F1")],
    )
    out = render_pr_comment(cs)
    # Heading shows section-specific count, not total.
    expected_count = 2 if title == "New findings" else 1
    assert f"### {title} ({expected_count})" in out
