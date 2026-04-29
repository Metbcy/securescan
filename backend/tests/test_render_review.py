"""Tests for the GitHub Reviews API payload serializer.

The renderer ties IR1 (diff-position lookup), IR2 (fingerprint
upsert marker), and IR3 (suggestion fences) into a single
deterministic JSON document. These tests pin the contract that
``post-review.sh`` will rely on:

- byte-identical re-renders for byte-identical inputs;
- inline anchor at the LINE ABOVE when a buildable inline-ignore
  ``suggestion`` block is attached, fall back to the natural
  line otherwise (anchor-shift contract pinned by IR3);
- findings outside the diff land in the body fallback (NOT
  inline);
- per-mode markers on the first body line so the action's grep
  can find them;
- fingerprint marker on every inline comment (upsert lookup);
- ``COMMENT`` review event by default; overridable.
"""

from __future__ import annotations

import json

import pytest

from securescan.diff import ChangeSet
from securescan.fingerprint import populate_fingerprints
from securescan.models import Finding, ScanType, Severity
from securescan.render_review import (
    MARKER_REVIEW,
    MARKER_REVIEW_COMPARE,
    ReviewComment,
    render_inline_comment_body,
    render_review,
    render_review_json,
)
from securescan.review_marker import (
    extract_fingerprint,
    fingerprint_prefix,
)


# ----------------------------- fixtures -----------------------------------


def _make_finding(**overrides) -> Finding:
    base = dict(
        scan_id="scan-1",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=Severity.HIGH,
        title="SQL injection",
        description=(
            "A SQL injection vulnerability was detected in the query builder. "
            "Untrusted user input is concatenated into the query string."
        ),
        file_path="src/foo.py",
        line_start=10,
        line_end=10,
        rule_id="RULE-001",
        cwe="CWE-89",
        remediation="Use parameterized queries instead of string concatenation.",
    )
    base.update(overrides)
    return Finding(**base)


def _diff_with_lines(file_path: str, lines: list[str]) -> str:
    """Build a single-hunk diff that adds N consecutive lines.

    The hunk header claims "+1,N", so head-side line K maps to a
    diff position trace-able by counting from the @@ line:

      @@ -0,0 +1,N @@   -> position 0
      +line[0]          -> position 1, head_line 1
      +line[1]          -> position 2, head_line 2
      ...
    """
    header = [
        f"diff --git a/{file_path} b/{file_path}",
        "new file mode 100644",
        "index 0000000..1111111",
        "--- /dev/null",
        f"+++ b/{file_path}",
        f"@@ -0,0 +1,{len(lines)} @@",
    ]
    body = [f"+{ln}" for ln in lines]
    return "\n".join(header + body) + "\n"


def _diff_for_foo_py_lines_1_to_20() -> str:
    """A diff where every line 1..20 of src/foo.py has a position.

    Position N maps to head-line N for N in 1..20.
    """
    return _diff_with_lines("src/foo.py", [f"line{i}" for i in range(1, 21)])


# ----------------------------- determinism --------------------------------


def test_render_review_byte_identical_for_same_inputs():
    diff_text = _diff_for_foo_py_lines_1_to_20()
    cs1 = ChangeSet(new=[_make_finding()])
    cs2 = ChangeSet(new=[_make_finding()])
    p1 = render_review(cs1, commit_id="deadbeef" * 5, diff_text=diff_text)
    p2 = render_review(cs2, commit_id="deadbeef" * 5, diff_text=diff_text)
    assert p1.to_api_dict() == p2.to_api_dict()


def test_render_review_json_is_byte_identical():
    diff_text = _diff_for_foo_py_lines_1_to_20()
    cs1 = ChangeSet(new=[_make_finding()])
    cs2 = ChangeSet(new=[_make_finding()])
    j1 = render_review_json(cs1, commit_id="d" * 40, diff_text=diff_text)
    j2 = render_review_json(cs2, commit_id="d" * 40, diff_text=diff_text)
    assert j1 == j2


def test_render_review_json_uses_sort_keys_and_ensure_ascii_false():
    diff_text = _diff_for_foo_py_lines_1_to_20()
    cs = ChangeSet(new=[_make_finding(title="caf\u00e9 injection")])
    out = render_review_json(cs, commit_id="d" * 40, diff_text=diff_text)
    parsed = json.loads(out)
    keys = list(parsed.keys())
    assert keys == sorted(keys), "top-level keys must be sorted"
    assert "caf\u00e9" in out, "ensure_ascii=False keeps non-ASCII raw"


# ----------------------------- structure ----------------------------------


def test_review_payload_has_required_top_level_keys():
    payload = render_review(
        ChangeSet(new=[_make_finding()]),
        commit_id="deadbeef" * 5,
        diff_text=_diff_for_foo_py_lines_1_to_20(),
    )
    d = payload.to_api_dict()
    assert set(d.keys()) == {"commit_id", "event", "body", "comments"}


def test_review_body_starts_with_diff_marker_in_diff_mode():
    payload = render_review(
        ChangeSet(new=[_make_finding()]),
        commit_id="d" * 40,
        diff_text=_diff_for_foo_py_lines_1_to_20(),
        mode="diff",
    )
    assert payload.body.splitlines()[0] == MARKER_REVIEW


def test_review_body_starts_with_compare_marker_in_compare_mode():
    payload = render_review(
        ChangeSet(new=[_make_finding()]),
        commit_id="d" * 40,
        diff_text=_diff_for_foo_py_lines_1_to_20(),
        mode="compare",
    )
    assert payload.body.splitlines()[0] == MARKER_REVIEW_COMPARE


def test_diff_and_compare_markers_are_distinct():
    assert MARKER_REVIEW != MARKER_REVIEW_COMPARE
    assert MARKER_REVIEW == "<!-- securescan:diff-review -->"
    assert MARKER_REVIEW_COMPARE == "<!-- securescan:compare-review -->"


def test_comments_sorted_by_path_then_position():
    findings = [
        _make_finding(file_path="src/zeta.py", line_start=2, rule_id="Z1"),
        _make_finding(file_path="src/alpha.py", line_start=5, rule_id="A1"),
        _make_finding(file_path="src/alpha.py", line_start=2, rule_id="A2"),
    ]
    diff_text = (
        _diff_with_lines("src/alpha.py", [f"a{i}" for i in range(1, 11)])
        + _diff_with_lines("src/zeta.py", [f"z{i}" for i in range(1, 11)])
    )
    payload = render_review(
        ChangeSet(new=findings),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=False,
    )
    paths_positions = [(c.path, c.position) for c in payload.comments]
    assert paths_positions == sorted(paths_positions)


# ----------------------------- position lookup ----------------------------


def test_finding_with_valid_position_becomes_inline_comment():
    finding = _make_finding(line_start=3)
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=False,
    )
    assert len(payload.comments) == 1
    c = payload.comments[0]
    assert c.path == "src/foo.py"
    assert c.position == 3


def test_finding_outside_diff_lands_in_body_fallback():
    finding = _make_finding(file_path="src/not_in_diff.py", line_start=10)
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
    )
    assert payload.comments == ()
    assert "src/not_in_diff.py" in payload.body


def test_finding_at_unchanged_line_lands_in_body_fallback():
    """IR1 maps both ' ' (context) and '+' lines to positions, so a
    plain context line IS an inline-comment target. A line that
    appears in the file but is OUTSIDE every hunk (e.g., line 100
    in a file whose only hunk covers 1..20) has NO position and
    falls through to the body bucket. This test pins the latter
    semantic since it's the actually-load-bearing one for
    "scan picked up a finding the diff didn't touch".
    """
    finding = _make_finding(line_start=100)
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
    )
    assert payload.comments == ()
    assert "src/foo.py" in payload.body


def test_context_line_does_get_a_position_per_ir1():
    """IR1 contract: context lines DO have positions. This test
    documents the semantic so a future refactor can't quietly
    skip context lines and break a real use case (a finding that
    fires on an unmodified line within a hunk).
    """
    diff_text = "\n".join(
        [
            "diff --git a/src/foo.py b/src/foo.py",
            "--- a/src/foo.py",
            "+++ b/src/foo.py",
            "@@ -1,4 +1,5 @@",
            " context_line_1",
            " context_line_2",
            "+added_line_3",
            " context_line_4",
        ]
    )
    finding = _make_finding(file_path="src/foo.py", line_start=1)
    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=False,
    )
    assert len(payload.comments) == 1
    assert payload.comments[0].position == 1


# ----------------------------- body fallback ------------------------------


def test_body_fallback_includes_findings_grouped_by_severity():
    findings = [
        _make_finding(
            file_path="src/missing.py",
            line_start=1,
            severity=Severity.CRITICAL,
            rule_id="C1",
            title="Critical missing",
        ),
        _make_finding(
            file_path="src/missing.py",
            line_start=2,
            severity=Severity.LOW,
            rule_id="L1",
            title="Low missing",
        ),
    ]
    payload = render_review(
        ChangeSet(new=findings),
        commit_id="d" * 40,
        diff_text="",
    )
    body = payload.body
    assert "#### Critical (1)" in body
    assert "#### Low (1)" in body
    crit_idx = body.index("#### Critical")
    low_idx = body.index("#### Low")
    assert crit_idx < low_idx, "critical must precede low (severity desc)"


def test_body_fallback_omits_section_when_no_unanchored_findings():
    finding = _make_finding(line_start=3)
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
    )
    assert "Findings without inline anchor" not in payload.body
    assert "Body fallback | 0" in payload.body


# ----------------------------- suggestions / anchor-shift -----------------


def test_inline_ignore_suggestion_anchors_at_line_above():
    finding = _make_finding(line_start=10, rule_id="E101")
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=True,
    )
    assert len(payload.comments) == 1
    c = payload.comments[0]
    assert c.position == 9, "anchor must shift to line above when suggestion attaches"
    assert "```suggestion" in c.body
    assert "securescan: ignore E101" in c.body


def test_inline_ignore_suggestion_dropped_when_line_above_not_in_diff():
    """Diff covers head-lines 5..10 only. A finding at line 5
    has a natural position (line 5) but no position for line 4.
    The renderer must drop the inline-ignore suggestion (keeping
    the severity-pin) and anchor at the natural line.
    """
    diff_text = "\n".join(
        [
            "diff --git a/src/foo.py b/src/foo.py",
            "--- a/src/foo.py",
            "+++ b/src/foo.py",
            "@@ -5,3 +5,6 @@",
            "+a",
            "+b",
            "+c",
            " d",
            " e",
            " f",
        ]
    )
    finding = _make_finding(line_start=5, rule_id="E101")
    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=True,
    )
    assert len(payload.comments) == 1
    c = payload.comments[0]
    assert c.position == 1, "natural position 1 (the first '+a' line)"
    assert "```suggestion" not in c.body, "inline-ignore must be dropped"
    assert "severity_overrides:" in c.body, "severity-pin must remain"


def test_no_suggestions_when_include_suggestions_false():
    finding = _make_finding(line_start=10, rule_id="E101")
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=False,
    )
    assert len(payload.comments) == 1
    c = payload.comments[0]
    assert c.position == 10, "no anchor shift when suggestions are off"
    assert "```suggestion" not in c.body
    assert "severity_overrides:" not in c.body


def test_severity_pin_suggestion_always_includes_yaml_block_when_rule_id_present():
    finding = _make_finding(line_start=10, rule_id="MY-RULE", severity=Severity.HIGH)
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=True,
    )
    body = payload.comments[0].body
    assert "```yaml" in body
    assert "severity_overrides:" in body
    assert "MY-RULE: medium" in body, "default demotion: high -> medium"


# ----------------------------- fingerprint markers ------------------------


def test_each_inline_comment_carries_fingerprint_marker():
    findings = [_make_finding(line_start=3, rule_id="A"),
                _make_finding(line_start=4, rule_id="B")]
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        ChangeSet(new=findings),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=False,
    )
    assert len(payload.comments) == 2
    for c in payload.comments:
        assert extract_fingerprint(c.body) is not None


def test_fingerprint_in_marker_matches_finding_fingerprint():
    finding = _make_finding(line_start=3, rule_id="X")
    diff_text = _diff_for_foo_py_lines_1_to_20()
    populate_fingerprints([finding])
    expected_prefix = fingerprint_prefix(finding.fingerprint)

    payload = render_review(
        ChangeSet(new=[finding]),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=False,
    )
    body_marker = extract_fingerprint(payload.comments[0].body)
    assert body_marker == expected_prefix


# ----------------------------- compare mode -------------------------------


def test_compare_mode_includes_disappeared_section_in_body():
    fixed = _make_finding(
        file_path="src/old.py",
        line_start=3,
        rule_id="GONE-1",
        title="Disappeared finding",
    )
    payload = render_review(
        ChangeSet(new=[], fixed=[fixed]),
        commit_id="cafebabecafebabecafebabecafebabecafebabe",
        diff_text="",
        mode="compare",
    )
    assert "### Disappeared since baseline" in payload.body
    assert "Disappeared finding" in payload.body
    assert "Fixed in `cafebab`" in payload.body


def test_compare_marker_used_in_compare_mode():
    payload = render_review(
        ChangeSet(),
        commit_id="d" * 40,
        diff_text="",
        mode="compare",
    )
    assert payload.body.splitlines()[0] == MARKER_REVIEW_COMPARE
    assert "## SecureScan baseline-drift review" in payload.body


def test_compare_disappeared_findings_NOT_inline():
    """Disappeared findings have no head-side line by definition,
    so even if the head diff happened to map their old line they
    must NOT become inline comments. They go to the fixed section
    of the review body.
    """
    fixed = _make_finding(file_path="src/foo.py", line_start=3, rule_id="GONE")
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        ChangeSet(new=[], fixed=[fixed]),
        commit_id="d" * 40,
        diff_text=diff_text,
        mode="compare",
    )
    assert payload.comments == ()
    assert "Disappeared since baseline" in payload.body


def test_diff_mode_fixed_section_uses_fixed_label():
    fixed = _make_finding(
        file_path="src/old.py", line_start=3, rule_id="F1", title="Fixed thing"
    )
    payload = render_review(
        ChangeSet(new=[], fixed=[fixed]),
        commit_id="abc1234abc1234abc1234abc1234abc1234abc12",
        diff_text="",
        mode="diff",
    )
    assert "### Fixed findings" in payload.body
    assert "Fixed in `abc1234`" in payload.body


# ----------------------------- edge cases ---------------------------------


def test_empty_changeset_yields_empty_comments_and_short_body():
    payload = render_review(
        ChangeSet(),
        commit_id="d" * 40,
        diff_text="",
    )
    assert payload.comments == ()
    body_lines = [ln for ln in payload.body.splitlines() if ln.strip()]
    assert body_lines[0] == MARKER_REVIEW
    assert "## SecureScan review" in payload.body
    assert "New findings | 0" in payload.body
    assert "Inline comments | 0" in payload.body


def test_findings_only_path_no_changeset_works():
    finding = _make_finding(line_start=3, rule_id="X")
    diff_text = _diff_for_foo_py_lines_1_to_20()
    payload = render_review(
        findings=[finding],
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=False,
    )
    assert len(payload.comments) == 1
    assert payload.comments[0].path == "src/foo.py"
    assert payload.comments[0].position == 3


def test_event_default_is_COMMENT():
    payload = render_review(
        ChangeSet(),
        commit_id="d" * 40,
        diff_text="",
    )
    assert payload.event == "COMMENT"
    assert payload.to_api_dict()["event"] == "COMMENT"


def test_event_can_be_overridden_to_REQUEST_CHANGES():
    payload = render_review(
        ChangeSet(),
        commit_id="d" * 40,
        diff_text="",
        event="REQUEST_CHANGES",
    )
    assert payload.event == "REQUEST_CHANGES"
    assert payload.to_api_dict()["event"] == "REQUEST_CHANGES"


def test_review_payload_is_frozen_and_comments_is_a_tuple():
    payload = render_review(
        ChangeSet(new=[_make_finding(line_start=3)]),
        commit_id="d" * 40,
        diff_text=_diff_for_foo_py_lines_1_to_20(),
        include_suggestions=False,
    )
    assert isinstance(payload.comments, tuple)
    with pytest.raises((AttributeError, Exception)):
        payload.commit_id = "other"  # frozen dataclass


def test_review_comment_to_api_dict_has_three_keys():
    c = ReviewComment(path="x.py", position=1, body="hi")
    d = c.to_api_dict()
    assert d == {"path": "x.py", "position": 1, "body": "hi"}


def test_review_payload_to_api_dict_serialises_comments_in_order():
    findings = [
        _make_finding(file_path="src/alpha.py", line_start=2, rule_id="A"),
        _make_finding(file_path="src/alpha.py", line_start=5, rule_id="B"),
    ]
    diff_text = _diff_with_lines("src/alpha.py", [f"a{i}" for i in range(1, 11)])
    payload = render_review(
        ChangeSet(new=findings),
        commit_id="d" * 40,
        diff_text=diff_text,
        include_suggestions=False,
    )
    serialised = payload.to_api_dict()["comments"]
    assert [c["position"] for c in serialised] == [2, 5]


def test_render_inline_comment_body_has_severity_uppercase_and_scanner():
    finding = _make_finding(severity=Severity.CRITICAL, scanner="bandit")
    body = render_inline_comment_body(finding)
    first_line = body.splitlines()[0]
    assert first_line.startswith("**CRITICAL: bandit**")


def test_render_inline_comment_body_linkifies_title_when_repo_and_cwe_present():
    finding = _make_finding(title="SQLi", cwe="CWE-89")
    body_with_repo = render_inline_comment_body(finding, repo="org/repo")
    body_no_repo = render_inline_comment_body(finding, repo=None)
    assert "[SQLi](https://cwe.mitre.org/data/definitions/89.html)" in body_with_repo
    assert "(https://cwe.mitre.org/" not in body_no_repo


def test_render_inline_comment_body_no_link_when_no_cwe():
    finding = _make_finding(title="No CWE here", cwe=None)
    body = render_inline_comment_body(finding, repo="org/repo")
    assert "(https://cwe.mitre.org/" not in body
