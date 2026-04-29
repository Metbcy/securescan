"""Golden-fixture tests for the unified-diff to GitHub-position parser.

The expected positions in the hand-traced tests below were computed by
counting lines in the diff body for each file, starting at -1 and
incrementing on every line of the body (the ``@@`` line itself, every
context line, every ``+`` line, every ``-`` line). Only context and
added lines populate the lookup map -- removed lines have no head-side
line number.
"""

from __future__ import annotations

from securescan.diff_position import DiffPositionMap, parse_unified_diff


def _diff(*lines: str) -> str:
    """Build a unified-diff string from raw lines (no trailing newline)."""
    return "\n".join(lines)


def test_single_hunk_single_file():
    diff = _diff(
        "diff --git a/foo.py b/foo.py",
        "index abc1234..def5678 100644",
        "--- a/foo.py",
        "+++ b/foo.py",
        "@@ -1,5 +1,6 @@",
        " alpha",
        " beta",
        "+gamma",
        " delta",
        " epsilon",
    )
    pmap = parse_unified_diff(diff)

    # Hand-traced: @@ is position 0, then alpha=1, beta=2, gamma=3,
    # delta=4, epsilon=5. Only context + added lines are stored, and
    # head-side line numbers come from "+1" in the hunk header.
    assert pmap.lookup("foo.py", 1) == 1
    assert pmap.lookup("foo.py", 2) == 2
    assert pmap.lookup("foo.py", 3) == 3
    assert pmap.lookup("foo.py", 4) == 4
    assert pmap.lookup("foo.py", 5) == 5
    assert pmap.files() == ["foo.py"]


def test_multi_hunk_single_file():
    diff = _diff(
        "diff --git a/big.py b/big.py",
        "--- a/big.py",
        "+++ b/big.py",
        "@@ -1,4 +1,5 @@",
        " a",
        " b",
        "+c",
        " d",
        "@@ -20,3 +21,3 @@",
        " x",
        "-old",
        "+new",
    )
    pmap = parse_unified_diff(diff)

    # Hand-traced positions:
    #   @@(1) -> pos 0,  a->1,  b->2,  +c->3,  d->4,
    #   @@(2) -> pos 5,  x->6,  -old->7 (no head line),  +new->8.
    # Head lines for hunk 2 come from "+21" -> x=21, +new takes head line
    # 22 because -old does not advance the head cursor.
    assert pmap.lookup("big.py", 1) == 1
    assert pmap.lookup("big.py", 2) == 2
    assert pmap.lookup("big.py", 3) == 3
    assert pmap.lookup("big.py", 4) == 4
    assert pmap.lookup("big.py", 21) == 6
    assert pmap.lookup("big.py", 22) == 8

    # The hunk header itself (position 5) is not commentable: no line
    # in the head file maps to it.
    assert 5 not in [pmap.lookup("big.py", n) for n in range(1, 30)]


def test_multiple_files_position_resets():
    diff = _diff(
        "diff --git a/one.py b/one.py",
        "--- a/one.py",
        "+++ b/one.py",
        "@@ -1,1 +1,2 @@",
        " keep",
        "+added",
        "diff --git a/two.py b/two.py",
        "--- a/two.py",
        "+++ b/two.py",
        "@@ -1,1 +1,2 @@",
        " keep2",
        "+added2",
    )
    pmap = parse_unified_diff(diff)

    # Both files have identical positions because the counter resets at
    # the second `diff --git`. If it didn't, two.py's positions would
    # continue from one.py's last value.
    assert pmap.lookup("one.py", 1) == 1
    assert pmap.lookup("one.py", 2) == 2
    assert pmap.lookup("two.py", 1) == 1
    assert pmap.lookup("two.py", 2) == 2
    assert pmap.files() == ["one.py", "two.py"]


def test_added_line_only_diff():
    diff = _diff(
        "diff --git a/new.py b/new.py",
        "new file mode 100644",
        "index 0000000..abcdef0",
        "--- /dev/null",
        "+++ b/new.py",
        "@@ -0,0 +1,3 @@",
        "+line1",
        "+line2",
        "+line3",
    )
    pmap = parse_unified_diff(diff)

    assert pmap.lookup("new.py", 1) == 1
    assert pmap.lookup("new.py", 2) == 2
    assert pmap.lookup("new.py", 3) == 3
    assert pmap.lookup("new.py", 4) is None


def test_removed_line_returns_none():
    diff = _diff(
        "diff --git a/foo.py b/foo.py",
        "--- a/foo.py",
        "+++ b/foo.py",
        "@@ -1,3 +1,2 @@",
        " keep",
        "-removed",
        " keep_too",
    )
    pmap = parse_unified_diff(diff)

    # The "-removed" line has no head-side line number, so nothing is
    # stored for it. The head-line cursor stays at 2, so " keep_too"
    # lands at head line 2 (its actual line in the new file).
    assert pmap.lookup("foo.py", 1) == 1
    assert pmap.lookup("foo.py", 2) == 3  # " keep_too" -- @@=0, keep=1, -removed=2, keep_too=3
    # No entry corresponds to the removed line.
    assert all(v != 2 for v in [pmap.lookup("foo.py", n) for n in range(1, 10)])


def test_untouched_file_returns_none():
    diff = _diff(
        "diff --git a/touched.py b/touched.py",
        "--- a/touched.py",
        "+++ b/touched.py",
        "@@ -1,1 +1,2 @@",
        " a",
        "+b",
    )
    pmap = parse_unified_diff(diff)

    assert pmap.lookup("untouched.py", 5) is None
    assert pmap.lookup("untouched.py", 1) is None
    # Sanity: the touched file IS findable.
    assert pmap.lookup("touched.py", 1) == 1


def test_line_outside_hunks_returns_none():
    diff = _diff(
        "diff --git a/foo.py b/foo.py",
        "--- a/foo.py",
        "+++ b/foo.py",
        "@@ -1,2 +1,2 @@",
        " line1",
        "+line2",
    )
    pmap = parse_unified_diff(diff)

    # Line 100 is in the file but past the diff hunks -- not commentable.
    assert pmap.lookup("foo.py", 100) is None
    assert pmap.lookup("foo.py", 0) is None
    assert pmap.lookup("foo.py", None) is None


def test_path_with_spaces():
    diff = _diff(
        'diff --git "a/src/with space.py" "b/src/with space.py"',
        '--- "a/src/with space.py"',
        '+++ "b/src/with space.py"',
        "@@ -1,1 +1,2 @@",
        " keep",
        "+added",
    )
    pmap = parse_unified_diff(diff)

    assert pmap.files() == ["src/with space.py"]
    assert pmap.lookup("src/with space.py", 1) == 1
    assert pmap.lookup("src/with space.py", 2) == 2


def test_renamed_file_uses_new_path():
    diff = _diff(
        "diff --git a/old_name.py b/new_name.py",
        "similarity index 90%",
        "rename from old_name.py",
        "rename to new_name.py",
        "index abc..def 100644",
        "--- a/old_name.py",
        "+++ b/new_name.py",
        "@@ -1,2 +1,2 @@",
        "-foo",
        "+bar",
        " baz",
    )
    pmap = parse_unified_diff(diff)

    assert pmap.files() == ["new_name.py"]
    # Hand-traced: @@=0, -foo=1 (no store), +bar=2 (head line 1),
    # baz=3 (head line 2).
    assert pmap.lookup("new_name.py", 1) == 2
    assert pmap.lookup("new_name.py", 2) == 3
    # The old name has no entry.
    assert pmap.lookup("old_name.py", 1) is None


def test_binary_files_yield_no_positions():
    diff = _diff(
        "diff --git a/img.png b/img.png",
        "index abc..def 100644",
        "Binary files a/img.png and b/img.png differ",
    )
    pmap = parse_unified_diff(diff)

    assert pmap.files() == []
    assert pmap.lookup("img.png", 1) is None


def test_deleted_file_yields_no_positions():
    diff = _diff(
        "diff --git a/gone.py b/gone.py",
        "deleted file mode 100644",
        "index abc..0000000",
        "--- a/gone.py",
        "+++ /dev/null",
        "@@ -1,3 +0,0 @@",
        "-line1",
        "-line2",
        "-line3",
    )
    pmap = parse_unified_diff(diff)

    assert pmap.files() == []
    assert pmap.lookup("gone.py", 1) is None
    assert pmap.lookup("gone.py", 2) is None


def test_empty_diff_yields_empty_map():
    pmap = parse_unified_diff("")
    assert isinstance(pmap, DiffPositionMap)
    assert pmap.files() == []
    assert pmap.lookup("anything.py", 1) is None


def test_lookup_with_pathlib_path():
    """The lookup API accepts both str and Path."""
    from pathlib import Path

    diff = _diff(
        "diff --git a/foo.py b/foo.py",
        "--- a/foo.py",
        "+++ b/foo.py",
        "@@ -1,1 +1,2 @@",
        " keep",
        "+added",
    )
    pmap = parse_unified_diff(diff)

    assert pmap.lookup(Path("foo.py"), 1) == 1
    assert pmap.lookup(Path("foo.py"), 2) == 2


def test_no_newline_marker_does_not_count():
    """The `\\ No newline at end of file` marker is not part of position."""
    diff = _diff(
        "diff --git a/foo.py b/foo.py",
        "--- a/foo.py",
        "+++ b/foo.py",
        "@@ -1,2 +1,2 @@",
        " keep",
        "-old",
        "+new",
        "\\ No newline at end of file",
    )
    pmap = parse_unified_diff(diff)

    # Without the no-newline marker counting: @@=0, keep=1, -old=2, +new=3.
    assert pmap.lookup("foo.py", 1) == 1
    assert pmap.lookup("foo.py", 2) == 3


def test_immutability_of_map():
    """DiffPositionMap is frozen so callers can't accidentally mutate it."""
    import dataclasses

    pmap = parse_unified_diff(
        _diff(
            "diff --git a/foo.py b/foo.py",
            "--- a/foo.py",
            "+++ b/foo.py",
            "@@ -1,1 +1,1 @@",
            "-old",
            "+new",
        )
    )
    try:
        pmap._by_file = {}  # type: ignore[misc]
    except dataclasses.FrozenInstanceError:
        pass
    else:
        raise AssertionError("DiffPositionMap should be frozen")
