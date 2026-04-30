"""Tests for scan-lifecycle logging on the `securescan.scan` logger.

The orchestrator (``securescan.api.scans._run_scan``) emits structured
INFO lines at scan + scanner lifecycle points so ``tail -f`` on the
backend log is useful while a long scan is in flight.

These tests pin the *contract* of which events fire and what fields
they carry; they don't depend on the textual layout of the message
beyond the leading event token, so the formatter helper can evolve
without breaking them.
"""

from __future__ import annotations

import asyncio
import logging

from securescan.api.scans import _run_scan
from securescan.database import (
    get_scan,
    init_db,
    save_scan,
    set_db_path,
)
from securescan.models import (
    Finding,
    Scan,
    ScanType,
    Severity,
)

_SCAN_LOGGER = "securescan.scan"


def _set_temp_db(tmp_path) -> None:
    set_db_path(str(tmp_path / "logging.db"))


class _StubScanner:
    """Minimal duck-typed scanner used by ``_run_scan``."""

    def __init__(
        self,
        name: str,
        *,
        available: bool = True,
        findings: int = 0,
        raises: BaseException | None = None,
        install_hint: str | None = None,
    ) -> None:
        self.name = name
        self.scan_type = ScanType.CODE
        self._available = available
        self._findings = findings
        self._raises = raises
        if install_hint is not None:
            self.install_hint = install_hint

    async def is_available(self) -> bool:
        return self._available

    async def scan(self, target_path, scan_id, **kwargs):
        if self._raises is not None:
            raise self._raises
        return [
            Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=ScanType.CODE,
                severity=Severity.LOW,
                title=f"{self.name} finding {i}",
                description="stub",
            )
            for i in range(self._findings)
        ]


def _install_stub_scanners(monkeypatch, scanners) -> None:
    import securescan.api.scans as scans_module

    monkeypatch.setattr(
        scans_module,
        "get_scanners_for_types",
        lambda _types: list(scanners),
    )


def _events(records: list[logging.LogRecord]) -> list[str]:
    """Extract the event token (first whitespace-separated word) from each."""
    return [rec.getMessage().split(" ", 1)[0] for rec in records]


def _records_for(records: list[logging.LogRecord], event: str) -> list[logging.LogRecord]:
    return [r for r in records if r.getMessage().split(" ", 1)[0] == event]


def test_scan_lifecycle_emits_start_per_scanner_and_complete(tmp_path, monkeypatch, caplog):
    _set_temp_db(tmp_path)
    target = tmp_path / "proj"
    target.mkdir()

    available_a = _StubScanner("alpha", available=True, findings=2)
    available_b = _StubScanner("bravo", available=True, findings=3)
    skipped = _StubScanner("charlie", available=False, install_hint="apt install charlie")
    _install_stub_scanners(monkeypatch, [available_a, skipped, available_b])

    async def _run():
        await init_db()
        scan = Scan(target_path=str(target), scan_types=[ScanType.CODE])
        await save_scan(scan)
        with caplog.at_level(logging.INFO, logger=_SCAN_LOGGER):
            await _run_scan(scan.id)
        return scan.id

    scan_id = asyncio.run(_run())
    records = [r for r in caplog.records if r.name == _SCAN_LOGGER]
    events = _events(records)

    # scan.start fires before any scanner work; scan.complete fires at the end.
    assert "scan.start" in events
    assert "scan.complete" in events
    assert events.index("scan.start") < events.index("scan.complete")

    # Two scanners ran -> one start/complete pair each (order between the two
    # scanners is not pinned, but each one's start precedes its complete).
    starts = _records_for(records, "scanner.start")
    completes = _records_for(records, "scanner.complete")
    started_names = {r.scanner for r in starts}
    completed_names = {r.scanner for r in completes}
    assert started_names == {"alpha", "bravo"}
    assert completed_names == {"alpha", "bravo"}
    for name in ("alpha", "bravo"):
        s_idx = next(
            i
            for i, r in enumerate(records)
            if r.getMessage().startswith("scanner.start") and r.scanner == name
        )
        c_idx = next(
            i
            for i, r in enumerate(records)
            if r.getMessage().startswith("scanner.complete") and r.scanner == name
        )
        assert s_idx < c_idx, f"{name}: start must precede complete"

    # The unavailable one logs scanner.skipped with a reason.
    skipped_records = _records_for(records, "scanner.skipped")
    assert len(skipped_records) == 1
    assert skipped_records[0].scanner == "charlie"
    assert skipped_records[0].reason == "not installed"

    # scan.start carries scanner_count = total selected (3, including skipped).
    start = _records_for(records, "scan.start")[0]
    assert start.scan_id == scan_id
    assert start.target == str(target)
    assert start.scanner_count == 3

    # scanner.complete carries findings_count and a numeric duration_s.
    by_name = {r.scanner: r for r in completes}
    assert by_name["alpha"].findings_count == 2
    assert by_name["bravo"].findings_count == 3
    for r in completes:
        assert isinstance(r.duration_s, (int, float))
        assert r.duration_s >= 0

    # scan.complete carries the rolled-up totals.
    complete = _records_for(records, "scan.complete")[0]
    assert complete.scan_id == scan_id
    assert complete.scanner_count == 2  # alpha + bravo (charlie was skipped)
    assert complete.findings_count == 5
    assert isinstance(complete.duration_s, (int, float))
    assert complete.duration_s >= 0


def test_scan_failed_event_emitted_with_truncated_error(tmp_path, monkeypatch, caplog):
    _set_temp_db(tmp_path)
    target = tmp_path / "proj"
    target.mkdir()

    # A scanner that crashes hard would normally log scanner.failed and the
    # outer try/except absorbs it via gather(return_exceptions=True). To
    # exercise the *scan.failed* branch we monkeypatch deduplicate_findings
    # to raise a long error message after scanners have run.
    crashing = _StubScanner("alpha", available=True, findings=1)
    _install_stub_scanners(monkeypatch, [crashing])

    long_error = "boom! " * 200  # ~1200 chars, well over the 200-char cap
    import securescan.api.scans as scans_module

    def _explode(_):
        raise RuntimeError(long_error)

    monkeypatch.setattr(scans_module, "deduplicate_findings", _explode)

    async def _run():
        await init_db()
        scan = Scan(target_path=str(target), scan_types=[ScanType.CODE])
        await save_scan(scan)
        with caplog.at_level(logging.INFO, logger=_SCAN_LOGGER):
            await _run_scan(scan.id)
        return scan.id

    scan_id = asyncio.run(_run())
    records = [r for r in caplog.records if r.name == _SCAN_LOGGER]
    failed = _records_for(records, "scan.failed")
    assert len(failed) == 1
    assert failed[0].scan_id == scan_id
    # Error is truncated to ~200 chars (no precise upper bound contract -
    # just confirm it's shorter than the original and the cap holds).
    assert 0 < len(failed[0].error) <= 200

    # The DB row reflects FAILED status (sanity: the lifecycle log matches reality).
    persisted = asyncio.run(get_scan(scan_id))
    assert persisted is not None
    assert persisted.status.value == "failed"


def test_scan_cancelled_before_start_emits_cancelled_event(tmp_path, monkeypatch, caplog):
    _set_temp_db(tmp_path)
    target = tmp_path / "proj"
    target.mkdir()

    _install_stub_scanners(monkeypatch, [_StubScanner("alpha", available=True)])

    async def _run():
        await init_db()
        # Pre-cancelled: _run_scan should short-circuit and emit scan.cancelled.
        from securescan.models import ScanStatus

        scan = Scan(
            target_path=str(target), scan_types=[ScanType.CODE], status=ScanStatus.CANCELLED
        )
        await save_scan(scan)
        with caplog.at_level(logging.INFO, logger=_SCAN_LOGGER):
            await _run_scan(scan.id)
        return scan.id

    scan_id = asyncio.run(_run())
    records = [r for r in caplog.records if r.name == _SCAN_LOGGER]
    events = _events(records)
    assert events == ["scan.cancelled"]
    assert records[0].scan_id == scan_id


def test_scan_event_message_is_human_readable(tmp_path, monkeypatch, caplog):
    """Pin the spec's example format: `event k=v k=v scan_id=...`."""
    _set_temp_db(tmp_path)
    target = tmp_path / "proj"
    target.mkdir()

    _install_stub_scanners(monkeypatch, [_StubScanner("alpha", available=True, findings=1)])

    async def _run():
        await init_db()
        scan = Scan(target_path=str(target), scan_types=[ScanType.CODE])
        await save_scan(scan)
        with caplog.at_level(logging.INFO, logger=_SCAN_LOGGER):
            await _run_scan(scan.id)

    asyncio.run(_run())
    records = [r for r in caplog.records if r.name == _SCAN_LOGGER]
    completes = _records_for(records, "scanner.complete")
    msg = completes[0].getMessage()
    # Format contract: starts with the event token, contains key=value pairs,
    # and the scan_id is emitted last (per the spec's example).
    assert msg.startswith("scanner.complete ")
    assert " scanner=alpha" in msg
    assert " findings_count=1" in msg
    assert " duration_s=" in msg
    assert msg.rstrip().split(" ")[-1].startswith("scan_id=")
