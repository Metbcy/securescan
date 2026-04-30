"""Tests for scanners_run + scanners_skipped persistence and surfacing.

Pin the PG2 contract:

- A scan that ran K of N scanners records the K names in `scanners_run` and
  the (N-K) skipped ones in `scanners_skipped` -- each skipped entry carries
  the install_hint so the UI can render actionable text without re-fetching
  /api/dashboard/status.
- Both fields survive the DB round-trip.
- Both fields are sorted alphabetically -- determinism contract.
- The DB migration is idempotent (can be re-run safely on an existing DB).
"""

from __future__ import annotations

import asyncio

import aiosqlite

from securescan.api.scans import _run_scan
from securescan.database import (
    get_scan,
    init_db,
    save_scan,
    set_db_path,
)
from securescan.models import (
    Scan,
    ScannerSkip,
    ScanStatus,
    ScanType,
)


def _set_temp_db(tmp_path) -> str:
    db_path = str(tmp_path / "skipped.db")
    set_db_path(db_path)
    return db_path


# ---------------------------------------------------------------------------
# Model-level
# ---------------------------------------------------------------------------


def test_scanner_skip_model_serializes_with_hint():
    skip = ScannerSkip(name="bandit", reason="not installed", install_hint="pip install bandit")
    dumped = skip.model_dump()
    assert dumped == {
        "name": "bandit",
        "reason": "not installed",
        "install_hint": "pip install bandit",
    }


def test_scanner_skip_model_optional_install_hint():
    skip = ScannerSkip(name="trivy", reason="unavailable")
    assert skip.install_hint is None


def test_scan_defaults_have_empty_lists():
    scan = Scan(target_path="/tmp/x", scan_types=[ScanType.CODE])
    assert scan.scanners_run == []
    assert scan.scanners_skipped == []


# ---------------------------------------------------------------------------
# DB round-trip + migration
# ---------------------------------------------------------------------------


def test_scan_skipped_persists_through_db_round_trip(tmp_path):
    _set_temp_db(tmp_path)

    async def _run():
        await init_db()
        scan = Scan(
            target_path="/tmp/proj",
            scan_types=[ScanType.CODE],
            status=ScanStatus.COMPLETED,
            scanners_run=["bandit", "semgrep"],
            scanners_skipped=[
                ScannerSkip(name="trivy", reason="not installed", install_hint="pip install trivy"),
                ScannerSkip(name="zap", reason="unavailable"),
            ],
        )
        await save_scan(scan)
        loaded = await get_scan(scan.id)
        assert loaded is not None
        assert loaded.scanners_run == ["bandit", "semgrep"]
        assert len(loaded.scanners_skipped) == 2
        names = sorted(s.name for s in loaded.scanners_skipped)
        assert names == ["trivy", "zap"]
        trivy = next(s for s in loaded.scanners_skipped if s.name == "trivy")
        assert trivy.install_hint == "pip install trivy"
        assert trivy.reason == "not installed"
        zap = next(s for s in loaded.scanners_skipped if s.name == "zap")
        assert zap.install_hint is None

    asyncio.run(_run())


def test_scan_skipped_empty_when_all_available(tmp_path):
    _set_temp_db(tmp_path)

    async def _run():
        await init_db()
        scan = Scan(
            target_path="/tmp/proj",
            scan_types=[ScanType.CODE],
            status=ScanStatus.COMPLETED,
            scanners_run=["bandit"],
            scanners_skipped=[],
        )
        await save_scan(scan)
        loaded = await get_scan(scan.id)
        assert loaded is not None
        assert loaded.scanners_skipped == []
        assert loaded.scanners_run == ["bandit"]

    asyncio.run(_run())


def test_db_migration_adds_scanners_skipped_column_idempotent(tmp_path):
    db_path = _set_temp_db(tmp_path)

    async def _run():
        # Two consecutive init_db calls must both succeed (the ALTER TABLEs
        # for scanners_run + scanners_skipped are wrapped in try/except so the
        # second call no-ops on the existing column).
        await init_db()
        await init_db()

        # Direct SELECT proves both columns exist on the persisted schema.
        async with aiosqlite.connect(db_path) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT scanners_run, scanners_skipped FROM scans")
            await cursor.fetchall()  # must not raise

    asyncio.run(_run())


def test_db_migration_preserves_existing_scan_rows(tmp_path):
    """Old rows (pre-PG2) decode as empty lists, not as NULL/error."""
    db_path = _set_temp_db(tmp_path)

    async def _run():
        await init_db()
        # Simulate an old row by manually NULLing the new columns.
        scan = Scan(target_path="/tmp/old", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
        await save_scan(scan)
        async with aiosqlite.connect(db_path) as db:
            await db.execute(
                "UPDATE scans SET scanners_run = NULL, scanners_skipped = NULL WHERE id = ?",
                (scan.id,),
            )
            await db.commit()

        loaded = await get_scan(scan.id)
        assert loaded is not None
        assert loaded.scanners_run == []
        assert loaded.scanners_skipped == []

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# _run_scan integration
# ---------------------------------------------------------------------------


class _StubScanner:
    """Minimal duck-typed scanner: name + scan_type + is_available + scan."""

    def __init__(self, name: str, *, available: bool, install_hint: str | None = None):
        self.name = name
        self.scan_type = ScanType.CODE
        self._available = available
        if install_hint is not None:
            self.install_hint = install_hint

    async def is_available(self) -> bool:
        return self._available

    async def scan(self, target_path, scan_id, **kwargs):
        return []


def _install_stub_scanners(monkeypatch, scanners):
    """Replace get_scanners_for_types in the api.scans module."""
    import securescan.api.scans as scans_module

    def fake_get_scanners_for_types(_types):
        return list(scanners)

    monkeypatch.setattr(scans_module, "get_scanners_for_types", fake_get_scanners_for_types)


def test_scan_records_skipped_scanners_when_unavailable(tmp_path, monkeypatch):
    _set_temp_db(tmp_path)
    target = tmp_path / "proj"
    target.mkdir()

    available = _StubScanner("bandit", available=True)
    skipped_with_hint = _StubScanner("semgrep", available=False, install_hint="pip install semgrep")
    skipped_no_hint = _StubScanner("mystery", available=False)
    _install_stub_scanners(monkeypatch, [skipped_with_hint, available, skipped_no_hint])

    async def _run():
        await init_db()
        scan = Scan(target_path=str(target), scan_types=[ScanType.CODE])
        await save_scan(scan)
        await _run_scan(scan.id)

        loaded = await get_scan(scan.id)
        assert loaded is not None
        assert loaded.status == ScanStatus.COMPLETED
        # scanners_run only contains what was actually available, sorted.
        assert loaded.scanners_run == ["bandit"]
        # scanners_skipped contains both unavailable ones, sorted by name.
        names = [s.name for s in loaded.scanners_skipped]
        assert names == ["mystery", "semgrep"]

        semgrep = next(s for s in loaded.scanners_skipped if s.name == "semgrep")
        assert semgrep.reason == "not installed"
        assert semgrep.install_hint == "pip install semgrep"

        mystery = next(s for s in loaded.scanners_skipped if s.name == "mystery")
        # No install_hint attribute on the scanner -> reason falls back to "unavailable".
        assert mystery.reason == "unavailable"
        assert mystery.install_hint is None

    asyncio.run(_run())


def test_scan_records_run_scanners_sorted(tmp_path, monkeypatch):
    _set_temp_db(tmp_path)
    target = tmp_path / "proj"
    target.mkdir()

    a = _StubScanner("zap", available=True)
    b = _StubScanner("bandit", available=True)
    c = _StubScanner("semgrep", available=True)
    _install_stub_scanners(monkeypatch, [a, b, c])

    async def _run():
        await init_db()
        scan = Scan(target_path=str(target), scan_types=[ScanType.CODE])
        await save_scan(scan)
        await _run_scan(scan.id)

        loaded = await get_scan(scan.id)
        assert loaded is not None
        assert loaded.scanners_run == ["bandit", "semgrep", "zap"]
        assert loaded.scanners_skipped == []

    asyncio.run(_run())


def test_scan_records_skipped_when_all_unavailable(tmp_path, monkeypatch):
    _set_temp_db(tmp_path)
    target = tmp_path / "proj"
    target.mkdir()

    s1 = _StubScanner("bandit", available=False, install_hint="pip install bandit")
    s2 = _StubScanner("semgrep", available=False, install_hint="pip install semgrep")
    _install_stub_scanners(monkeypatch, [s1, s2])

    async def _run():
        await init_db()
        scan = Scan(target_path=str(target), scan_types=[ScanType.CODE])
        await save_scan(scan)
        await _run_scan(scan.id)

        loaded = await get_scan(scan.id)
        assert loaded is not None
        # No scanner ran but the scan still completes -- no exception path.
        assert loaded.status == ScanStatus.COMPLETED
        assert loaded.scanners_run == []
        assert [s.name for s in loaded.scanners_skipped] == ["bandit", "semgrep"]

    asyncio.run(_run())
