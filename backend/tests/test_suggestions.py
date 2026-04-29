"""Tests for ``securescan.suggestions`` -- the GitHub ``suggestion``
block builders for inline-ignore and severity-pin.

These tests pin two contracts the rest of the v0.4.0 inline-review
plumbing relies on:

* ``build_inline_ignore_suggestion`` documents and adheres to the
  anchor-shift contract (the suggestion REPLACES the line above the
  finding, so the renderer must anchor at ``line_start - 1``).
* ``build_severity_pin_suggestion`` is intentionally NOT a
  ``suggestion`` block -- a one-click commit on it would rewrite the
  finding's source line with literal YAML.
"""
from __future__ import annotations

from pathlib import Path

from securescan.models import Finding, ScanType, Severity
from securescan.suggestions import (
    build_inline_ignore_suggestion,
    build_severity_pin_suggestion,
    comment_prefix_for,
)
from securescan.suppression import parse_file_ignores


def _make_finding(**overrides) -> Finding:
    base = dict(
        scan_id="scan-1",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=Severity.HIGH,
        title="SQL injection",
        description="...",
        file_path="src/x.py",
        line_start=10,
        line_end=10,
        rule_id="RULE-001",
    )
    base.update(overrides)
    return Finding(**base)


# ---------------------------------------------------------------------------
# comment_prefix_for
# ---------------------------------------------------------------------------


def test_python_uses_hash():
    assert comment_prefix_for("src/foo.py") == "#"


def test_javascript_uses_double_slash():
    assert comment_prefix_for("src/foo.js") == "//"
    assert comment_prefix_for("src/foo.ts") == "//"
    assert comment_prefix_for("src/foo.jsx") == "//"


def test_sql_uses_double_dash():
    assert comment_prefix_for("migrations/001.sql") == "--"


def test_dockerfile_no_extension_uses_hash():
    assert comment_prefix_for("Dockerfile") == "#"
    assert comment_prefix_for("infra/Dockerfile") == "#"


def test_makefile_no_extension_uses_hash():
    assert comment_prefix_for("Makefile") == "#"
    assert comment_prefix_for("GNUmakefile") == "#"


def test_unknown_extension_uses_default_hash():
    # No ext, unknown filename -> default ``#``.
    assert comment_prefix_for("weird.xyz") == "#"
    assert comment_prefix_for("README") == "#"


def test_uppercase_extension_normalized():
    assert comment_prefix_for("FOO.PY") == "#"
    assert comment_prefix_for("BAR.JS") == "//"
    assert comment_prefix_for("BAZ.SQL") == "--"


# ---------------------------------------------------------------------------
# build_inline_ignore_suggestion
# ---------------------------------------------------------------------------


def test_inline_ignore_includes_securescan_marker():
    out = build_inline_ignore_suggestion(_make_finding())
    assert out is not None
    assert "securescan: ignore" in out
    assert "RULE-001" in out
    # Must be inside a ``suggestion`` fenced block.
    assert "```suggestion" in out


def test_inline_ignore_uses_python_hash_for_py():
    out = build_inline_ignore_suggestion(
        _make_finding(file_path="src/app.py")
    )
    assert out is not None
    assert "# securescan: ignore RULE-001" in out


def test_inline_ignore_uses_double_slash_for_js():
    out = build_inline_ignore_suggestion(
        _make_finding(file_path="src/app.js")
    )
    assert out is not None
    assert "// securescan: ignore RULE-001" in out


def test_inline_ignore_uses_double_dash_for_sql():
    out = build_inline_ignore_suggestion(
        _make_finding(file_path="migrations/up.sql")
    )
    assert out is not None
    assert "-- securescan: ignore RULE-001" in out


def test_inline_ignore_returns_none_when_no_rule_id():
    f = _make_finding(rule_id=None)
    assert build_inline_ignore_suggestion(f) is None


def test_inline_ignore_returns_none_when_no_line_start():
    f = _make_finding(line_start=None, line_end=None)
    assert build_inline_ignore_suggestion(f) is None


def test_inline_ignore_returns_none_when_line_start_is_1():
    # No "line above" to anchor on.
    f = _make_finding(line_start=1, line_end=1)
    assert build_inline_ignore_suggestion(f) is None


def test_inline_ignore_returns_none_when_no_file_path():
    f = _make_finding(file_path=None)
    assert build_inline_ignore_suggestion(f) is None


def test_inline_ignore_indent_is_preserved():
    out = build_inline_ignore_suggestion(
        _make_finding(file_path="src/app.py"), indent="    "
    )
    assert out is not None
    assert "    # securescan: ignore RULE-001" in out


def test_inline_ignore_documents_anchor_shift_in_docstring():
    # The IR4 renderer reads this docstring to know the anchor
    # contract; if the wording silently changes, future readers won't
    # see why ``line_start - 1`` is used.
    doc = (build_inline_ignore_suggestion.__doc__ or "").lower()
    assert "anchor" in doc
    assert "above" in doc


def test_inline_ignore_output_parseable_by_ts2(tmp_path: Path) -> None:
    """Round-trip: the comment SecureScan suggests must be one TS2
    can parse on the next scan, otherwise the one-click commit would
    silently fail to suppress anything."""
    out = build_inline_ignore_suggestion(
        _make_finding(file_path="src/app.py", rule_id="MY-RULE")
    )
    assert out is not None
    # Extract the suggestion's body line (the first non-fence line
    # inside the ``suggestion`` block).
    in_block = False
    body_line: str | None = None
    for line in out.splitlines():
        if line.startswith("```suggestion"):
            in_block = True
            continue
        if in_block:
            if line.startswith("```"):
                break
            body_line = line
            break
    assert body_line is not None, "no body line found inside suggestion block"

    # Materialise a file as if the reviewer had committed the
    # suggestion above a line that triggers ``MY-RULE``.
    target = tmp_path / "app.py"
    target.write_text(body_line + "\n" + "x = bad()\n", encoding="utf-8")

    marks = parse_file_ignores(target)
    assert len(marks) == 1
    mark = marks[0]
    assert "MY-RULE" in mark.rule_ids
    # ``ignore`` (without ``-next-line``) targets the comment's own
    # line. That's still useful here -- the round-trip test exists
    # to confirm the parser SEES the directive at all; placement is
    # a separate, IR4-side concern documented by the anchor-shift
    # contract.
    assert mark.line == 1


# ---------------------------------------------------------------------------
# build_severity_pin_suggestion
# ---------------------------------------------------------------------------


def test_severity_pin_includes_yaml_block():
    out = build_severity_pin_suggestion(_make_finding())
    assert out is not None
    assert "```yaml" in out
    assert "severity_overrides:" in out


def test_severity_pin_includes_rule_id_and_new_severity():
    out = build_severity_pin_suggestion(
        _make_finding(rule_id="MY-RULE", severity=Severity.CRITICAL),
        new_severity="medium",
    )
    assert out is not None
    assert "MY-RULE: medium" in out


def test_severity_pin_default_demotion_critical_to_high():
    out = build_severity_pin_suggestion(
        _make_finding(severity=Severity.CRITICAL)
    )
    assert out is not None
    assert "RULE-001: high" in out


def test_severity_pin_default_demotion_high_to_medium():
    out = build_severity_pin_suggestion(
        _make_finding(severity=Severity.HIGH)
    )
    assert out is not None
    assert "RULE-001: medium" in out


def test_severity_pin_default_demotion_info_stays_info():
    out = build_severity_pin_suggestion(
        _make_finding(severity=Severity.INFO)
    )
    assert out is not None
    assert "RULE-001: info" in out


def test_severity_pin_explicit_new_severity_honored():
    out = build_severity_pin_suggestion(
        _make_finding(severity=Severity.CRITICAL),
        new_severity="low",
    )
    assert out is not None
    # Explicit override beats the default demotion (which would say
    # ``high``).
    assert "RULE-001: low" in out
    assert "RULE-001: high" not in out


def test_severity_pin_returns_none_when_no_rule_id():
    f = _make_finding(rule_id=None)
    assert build_severity_pin_suggestion(f) is None


def test_severity_pin_is_NOT_a_suggestion_block():
    # Critical correctness check: severity-pin targets a different
    # file than the inline comment is anchored on, so a ``suggestion``
    # fence here would let GitHub one-click-rewrite the source line
    # with literal YAML. Must be a ``yaml`` fence only.
    out = build_severity_pin_suggestion(_make_finding())
    assert out is not None
    assert "```suggestion" not in out
