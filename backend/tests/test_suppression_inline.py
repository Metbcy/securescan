"""Tests for the inline ignore-comment parser (TS2).

These tests pin down:

* the per-language comment prefix dispatch (``#`` / ``//`` / ``--``)
* the directive grammar (``ignore`` / ``ignore-this-line`` /
  ``ignore-next-line``)
* the wildcard rule (``*``)
* the comma-separated rule-id form
* the case-insensitive marker
* the documented string-literal false positive (so future regressions
  on this *known* limitation surface as test failures)
* the "NEVER raise" contract for missing / unreadable files
* the per-file cache on :class:`IgnoreMap`
* the guard rails for ``None`` arguments on :meth:`IgnoreMap.applies_to`
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from securescan import suppression
from securescan.suppression import IgnoreMap, IgnoreMark, parse_file_ignores


# ---------------------------------------------------------------------------
# parse_file_ignores: per-language prefixes
# ---------------------------------------------------------------------------


def test_python_hash_comment_suppresses_same_line(tmp_path: Path) -> None:
    f = tmp_path / "code.py"
    f.write_text("password = 'hunter2'  # securescan: ignore RULE-A\n")
    marks = parse_file_ignores(f)
    assert len(marks) == 1
    mark = marks[0]
    assert mark.line == 1
    assert mark.target_line == 1
    assert mark.rule_ids == frozenset({"RULE-A"})
    assert mark.directive == "ignore"


def test_js_double_slash_comment_suppresses_same_line(tmp_path: Path) -> None:
    f = tmp_path / "app.ts"
    f.write_text('const k = "AKIA..."; // securescan: ignore AWS-KEY\n')
    marks = parse_file_ignores(f)
    assert len(marks) == 1
    assert marks[0].rule_ids == frozenset({"AWS-KEY"})
    assert marks[0].target_line == 1


def test_sql_double_dash_comment_suppresses_same_line(tmp_path: Path) -> None:
    f = tmp_path / "query.sql"
    f.write_text("SELECT * FROM users; -- securescan: ignore SQLI-001\n")
    marks = parse_file_ignores(f)
    assert len(marks) == 1
    assert marks[0].rule_ids == frozenset({"SQLI-001"})


def test_dockerfile_hash_works(tmp_path: Path) -> None:
    """A ``Dockerfile`` (no extension) is parsed as ``#``-style."""
    f = tmp_path / "Dockerfile"
    f.write_text("FROM scratch  # securescan: ignore DOCKER-1\n")
    marks = parse_file_ignores(f)
    assert len(marks) == 1
    assert marks[0].rule_ids == frozenset({"DOCKER-1"})


def test_unknown_extension_falls_back_to_all_prefixes(tmp_path: Path) -> None:
    """Unknown extension still parses; we don't want users locked out
    just because the file ends in ``.weirdlang``."""
    f = tmp_path / "thing.weirdlang"
    f.write_text("some_token  # securescan: ignore RULE-X\n")
    marks = parse_file_ignores(f)
    assert len(marks) == 1
    assert marks[0].rule_ids == frozenset({"RULE-X"})


# ---------------------------------------------------------------------------
# Directive variants
# ---------------------------------------------------------------------------


def test_ignore_next_line_targets_next_line(tmp_path: Path) -> None:
    f = tmp_path / "code.py"
    f.write_text(
        "# securescan: ignore-next-line RULE-A\n"
        "password = 'hunter2'\n"
    )
    marks = parse_file_ignores(f)
    assert len(marks) == 1
    mark = marks[0]
    assert mark.line == 1
    assert mark.target_line == 2
    assert mark.directive == "ignore-next-line"


def test_ignore_this_line_synonym_of_ignore(tmp_path: Path) -> None:
    f = tmp_path / "code.py"
    f.write_text("x = 1  # securescan: ignore-this-line RULE-A\n")
    marks = parse_file_ignores(f)
    assert len(marks) == 1
    assert marks[0].directive == "ignore-this-line"
    assert marks[0].target_line == 1
    assert marks[0].rule_ids == frozenset({"RULE-A"})


def test_multiple_rule_ids_comma_separated(tmp_path: Path) -> None:
    f = tmp_path / "code.py"
    f.write_text("x = 1  # securescan: ignore RULE-A, RULE-B, RULE-C\n")
    marks = parse_file_ignores(f)
    assert len(marks) == 1
    assert marks[0].rule_ids == frozenset({"RULE-A", "RULE-B", "RULE-C"})

    m = IgnoreMap()
    assert m.applies_to(f, 1, "RULE-A") is True
    assert m.applies_to(f, 1, "RULE-B") is True
    assert m.applies_to(f, 1, "RULE-C") is True
    assert m.applies_to(f, 1, "RULE-D") is False


def test_wildcard_star_suppresses_any_rule_id(tmp_path: Path) -> None:
    f = tmp_path / "code.py"
    f.write_text("x = 1  # securescan: ignore *\n")
    m = IgnoreMap()
    assert m.applies_to(f, 1, "ANY-RULE") is True
    assert m.applies_to(f, 1, "SEMGREP-XYZ") is True
    # Wildcard is line-scoped, not file-scoped:
    assert m.applies_to(f, 2, "ANY-RULE") is False


def test_no_match_when_rule_id_does_not_match(tmp_path: Path) -> None:
    f = tmp_path / "code.py"
    f.write_text("x = 1  # securescan: ignore RULE-A\n")
    m = IgnoreMap()
    assert m.applies_to(f, 1, "RULE-B") is False


def test_case_insensitive_marker(tmp_path: Path) -> None:
    f = tmp_path / "code.py"
    f.write_text("x = 1  # Securescan: IGNORE rule-X\n")
    marks = parse_file_ignores(f)
    assert len(marks) == 1
    mark = marks[0]
    # Directive is normalised to lower-case so downstream comparisons
    # don't have to care about user formatting.
    assert mark.directive == "ignore"
    # Rule-id casing is preserved verbatim — rule registries compare
    # case-sensitively.
    assert mark.rule_ids == frozenset({"rule-X"})


def test_empty_rule_id_list_produces_no_mark(tmp_path: Path) -> None:
    """``# securescan: ignore   `` (no rule id) must not generate a
    blanket suppression — that would be too easy to do accidentally."""
    f = tmp_path / "code.py"
    f.write_text("x = 1  # securescan: ignore   \n")
    marks = parse_file_ignores(f)
    assert marks == []


# ---------------------------------------------------------------------------
# Documented limitation
# ---------------------------------------------------------------------------


def test_marker_inside_string_is_a_known_false_positive(tmp_path: Path) -> None:
    """KNOWN LIMITATION: we don't parse string literals vs. real
    comments. A ``# securescan:`` marker that lives inside a
    triple-quoted (multi-line) string still triggers suppression.

    This test pins the *current* behaviour so any future regression
    (good or bad) shows up in CI. If we ever add proper
    string-vs-comment parsing, update this test to assert the marker
    is ignored.
    """
    f = tmp_path / "fp.py"
    f.write_text(
        'docstring = """\n'
        "# securescan: ignore X\n"
        '"""\n'
    )
    marks = parse_file_ignores(f)
    # Current behaviour: false positive — the marker matches even
    # though the line is inside a string literal.
    assert len(marks) == 1
    assert marks[0].rule_ids == frozenset({"X"})
    assert marks[0].line == 2


# ---------------------------------------------------------------------------
# Failure-mode contract: NEVER raise
# ---------------------------------------------------------------------------


def test_missing_file_returns_no_ignores_no_exception(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.py"
    assert parse_file_ignores(missing) == []
    m = IgnoreMap()
    assert m.applies_to(missing, 1, "RULE-A") is False


def test_unreadable_file_returns_no_ignores_no_exception(tmp_path: Path) -> None:
    """A binary blob is decoded with ``errors='replace'`` so we don't
    raise; the regex simply finds nothing on the garbled output."""
    f = tmp_path / "blob.bin"
    f.write_bytes(bytes(range(256)) * 4)
    marks = parse_file_ignores(f)
    assert marks == []


def test_directory_path_returns_no_ignores_no_exception(tmp_path: Path) -> None:
    """A directory path must not crash the parser."""
    d = tmp_path / "subdir"
    d.mkdir()
    assert parse_file_ignores(d) == []


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="chmod-based unreadability doesn't apply to Windows or root",
)
def test_permission_denied_file_returns_no_ignores_no_exception(
    tmp_path: Path,
) -> None:
    f = tmp_path / "locked.py"
    f.write_text("# securescan: ignore RULE-A\n")
    f.chmod(0)
    try:
        assert parse_file_ignores(f) == []
    finally:
        # restore permissions so pytest can clean up the tmp_path
        f.chmod(stat.S_IRUSR | stat.S_IWUSR)


# ---------------------------------------------------------------------------
# IgnoreMap behaviour
# ---------------------------------------------------------------------------


def test_ignore_map_cache_avoids_re_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    f = tmp_path / "x.py"
    f.write_text("# securescan: ignore RULE-A\n")

    real_parse = suppression.parse_file_ignores
    calls: list[Path] = []

    def counting_parse(path: Path) -> list[IgnoreMark]:
        calls.append(path)
        return real_parse(path)

    monkeypatch.setattr(suppression, "parse_file_ignores", counting_parse)

    m = IgnoreMap()
    # Multiple lookups against the same path — should parse exactly once.
    m.applies_to(f, 1, "RULE-A")
    m.applies_to(f, 1, "RULE-A")
    m.applies_to(f, 1, "RULE-B")
    m.reasons(f, 1, "RULE-A")
    assert len(calls) == 1


def test_ignore_map_accepts_string_path(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("# securescan: ignore RULE-A\n")
    m = IgnoreMap()
    assert m.applies_to(str(f), 1, "RULE-A") is True


def test_applies_to_with_none_path_returns_false() -> None:
    m = IgnoreMap()
    assert m.applies_to(None, 1, "RULE-A") is False


def test_applies_to_with_none_line_returns_false(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("# securescan: ignore RULE-A\n")
    m = IgnoreMap()
    assert m.applies_to(f, None, "RULE-A") is False


def test_applies_to_with_none_rule_id_returns_false(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("# securescan: ignore RULE-A\n")
    m = IgnoreMap()
    assert m.applies_to(f, 1, None) is False


def test_reasons_returns_matching_marks(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("# securescan: ignore RULE-A, RULE-B\n")
    m = IgnoreMap()
    reasons = m.reasons(f, 1, "RULE-A")
    assert len(reasons) == 1
    only = reasons[0]
    assert isinstance(only, IgnoreMark)
    assert only.file == f
    assert only.line == 1
    assert only.target_line == 1
    assert only.rule_ids == frozenset({"RULE-A", "RULE-B"})
    assert only.directive == "ignore"


def test_reasons_for_unrelated_rule_is_empty(tmp_path: Path) -> None:
    f = tmp_path / "x.py"
    f.write_text("# securescan: ignore RULE-A\n")
    m = IgnoreMap()
    assert m.reasons(f, 1, "RULE-Z") == []
