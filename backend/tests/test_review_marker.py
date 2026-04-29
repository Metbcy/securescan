"""Tests for the fingerprint marker module."""
from __future__ import annotations

import pytest

from securescan.review_marker import (
    FINGERPRINT_PREFIX_LEN,
    add_fingerprint_marker,
    extract_fingerprint,
    fingerprint_prefix,
    has_fingerprint,
    strip_fingerprint_markers,
)


FP_FULL_A = "a" * 64
FP_FULL_B = "b" * 64
FP_MIXED = "deadbeefcafe" + "0" * 52


def test_fingerprint_prefix_takes_first_12_chars() -> None:
    assert fingerprint_prefix("0123456789abcdef" * 4) == "0123456789ab"
    assert len(fingerprint_prefix(FP_FULL_A)) == FINGERPRINT_PREFIX_LEN


def test_fingerprint_prefix_lowercases() -> None:
    assert fingerprint_prefix("ABCDEF123456" + "0" * 52) == "abcdef123456"
    assert fingerprint_prefix("DEADBEEFCAFE") == "deadbeefcafe"


def test_fingerprint_prefix_rejects_too_short() -> None:
    with pytest.raises(ValueError):
        fingerprint_prefix("abc")
    with pytest.raises(ValueError):
        fingerprint_prefix("a" * (FINGERPRINT_PREFIX_LEN - 1))
    with pytest.raises(ValueError):
        fingerprint_prefix("")


def test_fingerprint_prefix_rejects_non_hex() -> None:
    with pytest.raises(ValueError):
        fingerprint_prefix("z" * 12)
    with pytest.raises(ValueError):
        fingerprint_prefix("not-hex-at-all-but-long-enough")


def test_fingerprint_prefix_accepts_64_char_full_sha256() -> None:
    sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert fingerprint_prefix(sha) == "e3b0c44298fc"


def test_add_marker_appends_to_body() -> None:
    body = "Finding: typosquat detected on `requests-oauth`."
    out = add_fingerprint_marker(body, FP_FULL_A)
    assert out.startswith(body)
    assert out.endswith("<!-- securescan:fp:aaaaaaaaaaaa -->")
    assert "\n\n<!-- securescan:fp:" in out


def test_add_marker_to_empty_body() -> None:
    out = add_fingerprint_marker("", FP_FULL_A)
    assert out == "<!-- securescan:fp:aaaaaaaaaaaa -->"


def test_add_marker_to_body_ending_with_single_newline() -> None:
    body = "Line one.\n"
    out = add_fingerprint_marker(body, FP_FULL_A)
    assert out == "Line one.\n\n<!-- securescan:fp:aaaaaaaaaaaa -->"


def test_add_marker_to_body_ending_with_double_newline() -> None:
    body = "Line one.\n\n"
    out = add_fingerprint_marker(body, FP_FULL_A)
    assert out == "Line one.\n\n<!-- securescan:fp:aaaaaaaaaaaa -->"


def test_add_marker_idempotent_for_same_fingerprint() -> None:
    body = "A finding."
    once = add_fingerprint_marker(body, FP_FULL_A)
    twice = add_fingerprint_marker(once, FP_FULL_A)
    assert once == twice
    assert once.count("securescan:fp:") == 1


def test_add_different_marker_to_already_marked_body() -> None:
    body = "A finding."
    marked = add_fingerprint_marker(body, FP_FULL_A)
    out = add_fingerprint_marker(marked, FP_FULL_B)
    assert out == marked
    assert out.count("securescan:fp:") == 1
    assert "aaaaaaaaaaaa" in out
    assert "bbbbbbbbbbbb" not in out


def test_extract_marker_finds_fingerprint() -> None:
    body = "Body text\n\n<!-- securescan:fp:abcdef123456 -->"
    assert extract_fingerprint(body) == "abcdef123456"


def test_extract_marker_returns_none_for_unmarked_body() -> None:
    assert extract_fingerprint("Just plain text.") is None
    assert extract_fingerprint("") is None
    assert extract_fingerprint("<!-- securescan:diff -->") is None


def test_extract_marker_handles_whitespace_variants() -> None:
    assert (
        extract_fingerprint("<!--   securescan:fp:abc123def456 -->")
        == "abc123def456"
    )
    assert (
        extract_fingerprint("<!-- securescan:fp:abc123def456   -->")
        == "abc123def456"
    )
    assert (
        extract_fingerprint("<!-- securescan:fp: abc123def456 -->")
        == "abc123def456"
    )
    assert (
        extract_fingerprint("<!--securescan:fp:abc123def456-->")
        == "abc123def456"
    )
    assert (
        extract_fingerprint("body\n<!-- SECURESCAN:FP:ABC123 -->\nmore")
        == "abc123"
    )


def test_extract_marker_returns_first_when_multiple_present() -> None:
    body = (
        "<!-- securescan:fp:aaaaaaaaaaaa -->\n"
        "Some text in between.\n"
        "<!-- securescan:fp:bbbbbbbbbbbb -->\n"
    )
    assert extract_fingerprint(body) == "aaaaaaaaaaaa"


def test_has_fingerprint_true_for_match() -> None:
    body = add_fingerprint_marker("body", FP_FULL_A)
    assert has_fingerprint(body, FP_FULL_A) is True


def test_has_fingerprint_false_for_mismatch() -> None:
    body = add_fingerprint_marker("body", FP_FULL_A)
    assert has_fingerprint(body, FP_FULL_B) is False


def test_has_fingerprint_false_for_unmarked_body() -> None:
    assert has_fingerprint("plain body", FP_FULL_A) is False


def test_has_fingerprint_normalizes_case() -> None:
    body = "<!-- SECURESCAN:FP:DEADBEEFCAFE -->"
    assert has_fingerprint(body, "deadbeefcafe" + "0" * 52) is True
    assert has_fingerprint(body, "DEADBEEFCAFE" + "0" * 52) is True
    assert has_fingerprint(body, "DeAdBeEfCaFe" + "0" * 52) is True


def test_strip_markers_removes_all() -> None:
    body = (
        "Finding A.\n\n"
        "<!-- securescan:fp:aaaaaaaaaaaa -->\n"
        "Finding B.\n\n"
        "<!-- securescan:fp:bbbbbbbbbbbb -->\n"
    )
    out = strip_fingerprint_markers(body)
    assert "securescan:fp:" not in out
    assert "Finding A." in out
    assert "Finding B." in out


def test_strip_markers_returns_body_unchanged_when_none_present() -> None:
    body = "No markers here.\n\nNot one bit."
    assert strip_fingerprint_markers(body) == body


def test_strip_markers_on_empty_body() -> None:
    assert strip_fingerprint_markers("") == ""


def test_strip_markers_handles_whitespace_variants() -> None:
    body = "Body\n\n<!--   SECURESCAN:FP:ABC123  -->\n"
    out = strip_fingerprint_markers(body)
    assert "securescan:fp:" not in out.lower()
    assert "Body" in out


def test_round_trip_add_then_extract() -> None:
    body = "A finding description with `code` and **markdown**."
    marked = add_fingerprint_marker(body, FP_MIXED)
    assert extract_fingerprint(marked) == "deadbeefcafe"
    assert has_fingerprint(marked, FP_MIXED) is True


def test_round_trip_add_strip_returns_original_content() -> None:
    body = "A finding description."
    marked = add_fingerprint_marker(body, FP_FULL_A)
    stripped = strip_fingerprint_markers(marked)
    assert "securescan:fp:" not in stripped
    assert "A finding description." in stripped


def test_marker_does_not_break_markdown_rendering() -> None:
    """Sanity: the marker is an HTML comment and is invisible in rendered
    Markdown. We assert it doesn't appear in the stripped form, which is
    what a Markdown renderer would also hide from end users."""
    body = (
        "## Finding\n\n"
        "Severity: **high**\n\n"
        "```python\nimport requests\n```\n"
    )
    marked = add_fingerprint_marker(body, FP_FULL_A)
    stripped = strip_fingerprint_markers(marked)
    assert "<!-- securescan:fp:" not in stripped
    assert "## Finding" in stripped
    assert "Severity: **high**" in stripped
    assert "```python" in stripped
