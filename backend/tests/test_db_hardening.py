import aiosqlite
import pytest

from securescan.database import _is_duplicate_column, _safe_ident


class TestSafeIdent:
    def test_accepts_simple(self):
        assert _safe_ident("foo") == "foo"

    def test_accepts_with_underscore(self):
        assert _safe_ident("foo_bar_2") == "foo_bar_2"

    def test_accepts_leading_underscore(self):
        assert _safe_ident("_internal") == "_internal"

    def test_accepts_max_length(self):
        # 63-char identifier (1 leading + 62 trailing) is allowed.
        ident = "a" + "b" * 62
        assert _safe_ident(ident) == ident

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="unsafe SQL identifier"):
            _safe_ident("")

    def test_rejects_leading_digit(self):
        with pytest.raises(ValueError, match="unsafe SQL identifier"):
            _safe_ident("1col")

    def test_rejects_space(self):
        with pytest.raises(ValueError, match="unsafe SQL identifier"):
            _safe_ident("foo bar")

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError, match="unsafe SQL identifier"):
            _safe_ident("foo; DROP TABLE bar")

    def test_rejects_double_dash_comment(self):
        with pytest.raises(ValueError, match="unsafe SQL identifier"):
            _safe_ident("foo--")

    def test_rejects_quote(self):
        with pytest.raises(ValueError, match="unsafe SQL identifier"):
            _safe_ident('foo"bar')

    def test_rejects_too_long(self):
        # 64 chars (1 leading + 63 trailing) is rejected.
        with pytest.raises(ValueError, match="unsafe SQL identifier"):
            _safe_ident("a" + "b" * 63)

    def test_rejects_non_string(self):
        with pytest.raises(ValueError, match="unsafe SQL identifier"):
            _safe_ident(None)  # type: ignore[arg-type]


class TestIsDuplicateColumn:
    def test_recognizes_sqlite_default(self):
        e = aiosqlite.OperationalError("duplicate column name: foo")
        assert _is_duplicate_column(e) is True

    def test_case_insensitive(self):
        e = aiosqlite.OperationalError("Duplicate Column Name: foo")
        assert _is_duplicate_column(e) is True

    def test_rejects_syntax_error(self):
        # Real risk: a typo like "ADD COLUMN foo TXT" raises a syntax
        # error, NOT duplicate-column. We must re-raise.
        e = aiosqlite.OperationalError('near "TXT": syntax error')
        assert _is_duplicate_column(e) is False

    def test_rejects_missing_table(self):
        e = aiosqlite.OperationalError("no such table: scans")
        assert _is_duplicate_column(e) is False
