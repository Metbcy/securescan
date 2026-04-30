"""Tests for the per-finding fingerprint primitive.

The fingerprint is the foundation for diff-aware classification (SS4) and
the PR-comment upsert (SS7). The contract these tests pin down:

- Same finding -> same fingerprint, always.
- Different scanner / file / rule_id / cwe -> different fingerprint.
- Trivial code edits (line shift, whitespace change, trailing comment)
  must NOT change the fingerprint -- otherwise every refactor would mark
  the same vulnerability as "new + fixed" in the diff classifier.
- populate_fingerprints is idempotent and skips already-populated rows.
- The DB migration is forward-only and can be re-run safely.
"""

from __future__ import annotations

import asyncio
import os

import aiosqlite

from securescan.database import get_findings, init_db, save_findings, set_db_path
from securescan.fingerprint import fingerprint, normalized_line_context, populate_fingerprints
from securescan.models import Finding, ScanType, Severity


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
        cwe="CWE-89",
        metadata={"line_snippet": "x = 1"},
    )
    base.update(overrides)
    return Finding(**base)


def test_fingerprint_is_deterministic():
    f = _make_finding()
    assert fingerprint(f) == fingerprint(f)


def test_fingerprint_returns_64_char_hex():
    fp = fingerprint(_make_finding())
    assert len(fp) == 64
    int(fp, 16)  # must parse as hex


def test_fingerprint_differs_for_different_scanner():
    a = _make_finding(scanner="semgrep")
    b = _make_finding(scanner="bandit")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_differs_for_different_file():
    a = _make_finding(file_path="src/x.py")
    b = _make_finding(file_path="src/y.py")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_differs_for_different_rule_id():
    a = _make_finding(rule_id="RULE-001")
    b = _make_finding(rule_id="RULE-002")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_differs_for_different_cwe():
    a = _make_finding(cwe="CWE-89")
    b = _make_finding(cwe="CWE-79")
    assert fingerprint(a) != fingerprint(b)


def test_fingerprint_invariant_to_line_shift():
    # Intentional: the diff classifier (SS4) must not flag the same
    # vulnerability as "new + fixed" just because a refactor moved the
    # line up or down inside the same file.
    a = _make_finding(line_start=10, line_end=10)
    b = _make_finding(line_start=15, line_end=15)
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_invariant_to_whitespace():
    a = _make_finding(metadata={"line_snippet": "x = 1"})
    b = _make_finding(metadata={"line_snippet": "    x   =   1   "})
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_invariant_to_trailing_comment():
    a = _make_finding(metadata={"line_snippet": "x = 1"})
    b = _make_finding(metadata={"line_snippet": "x = 1  # noqa"})
    c = _make_finding(metadata={"line_snippet": "x = 1 // trailing js comment"})
    d = _make_finding(metadata={"line_snippet": "x = 1 -- sql comment"})
    assert fingerprint(a) == fingerprint(b)
    assert fingerprint(a) == fingerprint(c)
    assert fingerprint(a) == fingerprint(d)


def test_fingerprint_invariant_to_block_comment():
    a = _make_finding(metadata={"line_snippet": "x = 1"})
    b = _make_finding(metadata={"line_snippet": "x = /* inline */ 1"})
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_normalizes_path_separators():
    a = _make_finding(file_path="src/x.py")
    b = _make_finding(file_path="src\\x.py")
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_relativizes_absolute_paths_in_cwd():
    cwd = os.getcwd().replace("\\", "/")
    abs_path = f"{cwd}/src/x.py"
    a = _make_finding(file_path="src/x.py")
    b = _make_finding(file_path=abs_path)
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_handles_missing_optional_fields():
    f = Finding(
        scan_id="scan-1",
        scanner="bandit",
        scan_type=ScanType.CODE,
        severity=Severity.LOW,
        title="t",
        description="d",
    )
    fp = fingerprint(f)
    assert len(fp) == 64


def test_normalized_line_context_empty_when_no_snippet():
    f = _make_finding(metadata={})
    assert normalized_line_context(f) == ""


def test_normalized_line_context_joins_multiline_snippets():
    f = _make_finding(metadata={"line_snippet": "x = 1\n  y = 2\n"})
    ctx = normalized_line_context(f)
    assert ctx == "x = 1 y = 2"


def test_normalized_line_context_lowercases():
    a = _make_finding(metadata={"line_snippet": "User.password = 'X'"})
    b = _make_finding(metadata={"line_snippet": "user.password = 'x'"})
    assert normalized_line_context(a) == normalized_line_context(b)


def test_populate_fingerprints_skips_already_populated():
    f = _make_finding()
    f.fingerprint = "preset-do-not-touch"
    populate_fingerprints([f])
    assert f.fingerprint == "preset-do-not-touch"


def test_populate_fingerprints_is_idempotent():
    findings = [_make_finding(), _make_finding(file_path="src/y.py")]
    populate_fingerprints(findings)
    snapshot = [f.fingerprint for f in findings]
    populate_fingerprints(findings)
    assert [f.fingerprint for f in findings] == snapshot


def test_populate_fingerprints_sets_field_on_empty():
    findings = [_make_finding(), _make_finding(file_path="src/y.py")]
    assert all(f.fingerprint == "" for f in findings)
    populate_fingerprints(findings)
    assert all(len(f.fingerprint) == 64 for f in findings)
    assert findings[0].fingerprint != findings[1].fingerprint


def test_finding_model_has_fingerprint_field():
    f = Finding(
        scan_id="s",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=Severity.LOW,
        title="t",
        description="d",
    )
    assert f.fingerprint == ""


def test_db_migration_adds_fingerprint_column(tmp_path):
    db_path = str(tmp_path / "fp.db")
    set_db_path(db_path)

    async def _run():
        # Run init_db twice to prove the migration is idempotent.
        await init_db()
        await init_db()

        f = _make_finding()
        populate_fingerprints([f])
        await save_findings([f])

        # Direct SELECT to prove the column exists and round-trips.
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT fingerprint FROM findings")
            rows = await cursor.fetchall()
            assert len(rows) == 1
            assert rows[0]["fingerprint"] == f.fingerprint

        # And via the model loader.
        loaded = await get_findings(f.scan_id)
        assert len(loaded) == 1
        assert loaded[0].fingerprint == f.fingerprint

    asyncio.run(_run())


def test_db_migration_handles_legacy_table(tmp_path):
    """A pre-existing findings table without the fingerprint column should
    be migrated in place by init_db and accept new inserts after."""
    db_path = str(tmp_path / "legacy.db")

    async def _seed_legacy():
        async with aiosqlite.connect(db_path) as db:
            # Mirror the v0.1.0 schema (no fingerprint column).
            await db.execute("""
                CREATE TABLE findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    scanner TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    file_path TEXT,
                    line_start INTEGER,
                    line_end INTEGER,
                    rule_id TEXT,
                    cwe TEXT,
                    remediation TEXT,
                    metadata TEXT DEFAULT '{}'
                )
            """)
            await db.commit()

    asyncio.run(_seed_legacy())

    set_db_path(db_path)

    async def _migrate_and_use():
        await init_db()
        f = _make_finding()
        populate_fingerprints([f])
        await save_findings([f])
        loaded = await get_findings(f.scan_id)
        assert len(loaded) == 1
        assert loaded[0].fingerprint == f.fingerprint

    asyncio.run(_migrate_and_use())


def test_fingerprint_joiner_layout():
    """Pin the input layout so unrelated refactors cannot silently change
    every persisted fingerprint. The joiner is '|' and the field order is
    scanner, rule_id, file_path, normalized_line_context, cwe."""
    import hashlib

    f = _make_finding(
        scanner="semgrep",
        rule_id="RULE-001",
        file_path="src/x.py",
        cwe="CWE-89",
        metadata={"line_snippet": "x = 1"},
    )
    expected_payload = "semgrep|RULE-001|src/x.py|x = 1|CWE-89"
    assert fingerprint(f) == hashlib.sha256(expected_payload.encode("utf-8")).hexdigest()
