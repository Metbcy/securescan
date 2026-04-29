"""Tests for the per-scan-id SSE event bus and the
``/api/scans/{scan_id}/events`` endpoint added in v0.7.0.

The bus is exercised at unit level for replay / overflow / cleanup
semantics, then the FastAPI endpoint is exercised end-to-end with an
ASGI transport so the wire format and HTTP-level behaviour (404, SSE
content-type, terminal-state short-circuit) are pinned too.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from securescan.api.scans import _log_scan_event
from securescan.database import init_db, save_scan, set_db_path
from securescan.events import TERMINAL, ScanEventBus, bus
from securescan.main import app
from securescan.models import Scan, ScanStatus, ScanType


# ---------------------------------------------------------------------------
# Bus unit tests
# ---------------------------------------------------------------------------


@pytest.fixture
def fresh_bus() -> ScanEventBus:
    """A throwaway bus instance per test so state is isolated."""
    return ScanEventBus()


@pytest.fixture(autouse=True)
def _isolate_module_bus():
    """Make sure the module-level ``bus`` singleton starts each test
    empty, even when prior tests left replay buffers / cleanup tasks
    lying around. Tests that go through the FastAPI endpoint share
    that singleton with the production code path."""
    bus.reset()
    yield
    bus.reset()


@pytest.mark.asyncio
async def test_subscribe_get_replay(fresh_bus: ScanEventBus) -> None:
    """A subscriber that arrives after publish() sees prior events
    via the replay buffer (the central use case: frontend mounts
    after the scan has already started)."""
    sid = "scan-A"
    await fresh_bus.publish(sid, "scan.start", {"target": "/x"})
    await fresh_bus.publish(sid, "scanner.start", {"scanner": "alpha"})

    q = fresh_bus.subscribe(sid)
    e1, p1 = await asyncio.wait_for(q.get(), timeout=1.0)
    e2, p2 = await asyncio.wait_for(q.get(), timeout=1.0)
    assert (e1, p1) == ("scan.start", {"target": "/x"})
    assert (e2, p2) == ("scanner.start", {"scanner": "alpha"})


@pytest.mark.asyncio
async def test_terminal_event_never_dropped(fresh_bus: ScanEventBus) -> None:
    """A subscriber whose queue is full STILL receives terminal
    events — losing scan.complete would leave the UI stuck on
    'running' forever."""
    sid = "scan-B"
    q = fresh_bus.subscribe(sid)
    # Saturate the queue with non-terminal events.
    for i in range(ScanEventBus.QUEUE_CAP):
        await fresh_bus.publish(sid, "scanner.complete", {"i": i})
    assert q.qsize() == ScanEventBus.QUEUE_CAP

    await fresh_bus.publish(sid, "scan.complete", {"findings_count": 7})

    drained = []
    while not q.empty():
        drained.append(q.get_nowait())
    events = [e for e, _ in drained]
    assert "scan.complete" in events
    # And the final terminal payload is intact.
    terminal = next(p for e, p in drained if e == "scan.complete")
    assert terminal == {"findings_count": 7}


@pytest.mark.asyncio
async def test_oldest_nonterminal_evicted_on_overflow(fresh_bus: ScanEventBus) -> None:
    """When a queue is full of non-terminal events, publishing one
    more drops the OLDEST non-terminal — preserving the head order
    of any terminal events (none here, but the semantics are pinned)."""
    sid = "scan-C"
    q = fresh_bus.subscribe(sid)
    for i in range(ScanEventBus.QUEUE_CAP):
        await fresh_bus.publish(sid, "scanner.complete", {"i": i})

    # Overflow with a non-terminal event.
    await fresh_bus.publish(sid, "scanner.complete", {"i": "overflow"})

    items = []
    while not q.empty():
        items.append(q.get_nowait())
    # The very first item (i=0) was evicted; the last item is the new one.
    indices = [p["i"] for _, p in items]
    assert 0 not in indices
    assert indices[-1] == "overflow"
    assert len(items) == ScanEventBus.QUEUE_CAP


@pytest.mark.asyncio
async def test_replay_cap(fresh_bus: ScanEventBus) -> None:
    """Replay buffer is capped at ``REPLAY_CAP``; oldest events
    fall off as new ones come in."""
    sid = "scan-D"
    extra = 5
    for i in range(ScanEventBus.REPLAY_CAP + extra):
        await fresh_bus.publish(sid, "scanner.complete", {"i": i})

    q = fresh_bus.subscribe(sid)
    drained = []
    while not q.empty():
        drained.append(q.get_nowait())
    assert len(drained) == ScanEventBus.REPLAY_CAP
    indices = [p["i"] for _, p in drained]
    # The oldest `extra` events were dropped; the newest survive.
    assert indices[0] == extra
    assert indices[-1] == ScanEventBus.REPLAY_CAP + extra - 1


@pytest.mark.asyncio
async def test_replay_cleanup_after_terminal(
    fresh_bus: ScanEventBus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After a terminal event, the replay buffer is dropped after
    the configured grace window. We monkey-patch the grace to a tiny
    value so the test doesn't actually sleep 30 seconds."""
    monkeypatch.setattr(fresh_bus, "RETAIN_AFTER_TERMINAL_S", 0.01)
    sid = "scan-E"
    await fresh_bus.publish(sid, "scan.start", {})
    await fresh_bus.publish(sid, "scan.complete", {"findings_count": 0})
    assert fresh_bus.has_replay(sid)

    # Yield to the loop so the cleanup task gets a chance to run.
    await asyncio.sleep(0.05)
    assert not fresh_bus.has_replay(sid), "replay buffer should be GC'd after grace"


@pytest.mark.asyncio
async def test_subscribe_after_terminal_within_grace(fresh_bus: ScanEventBus) -> None:
    """Within the grace window after a terminal event, a brand new
    subscriber STILL gets the full replay (browser tab refresh during
    the closing seconds of a scan)."""
    sid = "scan-F"
    await fresh_bus.publish(sid, "scan.start", {})
    await fresh_bus.publish(sid, "scanner.start", {"scanner": "alpha"})
    await fresh_bus.publish(sid, "scan.complete", {"findings_count": 0})

    q = fresh_bus.subscribe(sid)
    drained = []
    while not q.empty():
        drained.append(q.get_nowait())
    events = [e for e, _ in drained]
    assert events == ["scan.start", "scanner.start", "scan.complete"]


# ---------------------------------------------------------------------------
# Bridge from synchronous _log_scan_event to async bus.publish
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_log_scan_event_publishes_to_bus() -> None:
    """``_log_scan_event`` schedules a publish onto the running event
    loop. We yield once so the scheduled task drains, then assert the
    replay buffer reflects the call."""
    sid = "scan-bridge"
    _log_scan_event(
        "scan.start",
        scan_id=sid,
        target="/proj",
        scanner_count=3,
    )
    # Let the scheduled bus.publish task run.
    await asyncio.sleep(0)
    # publish() awaits nothing internally, so a single yield is
    # enough — but go around once more just in case.
    await asyncio.sleep(0)

    replay = bus.replay_for(sid)
    assert len(replay) == 1
    event, payload = replay[0]
    assert event == "scan.start"
    assert payload == {"target": "/proj", "scanner_count": 3}


def test_log_scan_event_no_event_loop_does_not_crash() -> None:
    """Calling the helper outside an asyncio context (CLI tools,
    legacy sync tests) must not raise — the fallback path silently
    skips the publish."""
    # Sanity: there is no running loop here (plain sync test).
    with pytest.raises(RuntimeError):
        asyncio.get_running_loop()

    # Should not raise.
    _log_scan_event("scan.start", scan_id="scan-no-loop")


# ---------------------------------------------------------------------------
# HTTP endpoint tests (ASGI transport)
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "sse.db")
    set_db_path(db_path)
    asyncio.run(init_db())
    monkeypatch.delenv("SECURESCAN_API_KEY", raising=False)
    return db_path


@pytest.mark.asyncio
async def test_sse_endpoint_404_on_unknown_scan(temp_db) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/scans/does-not-exist/events")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_sse_endpoint_streams_events(temp_db) -> None:
    """Open the SSE stream, push events through the bus from a
    background task, and assert the wire bytes carry the expected
    event names ending with a terminal event that closes the stream."""
    scan = Scan(target_path="/", scan_types=[ScanType.CODE])
    await save_scan(scan)

    async def _producer() -> None:
        # Give the client a moment to subscribe before we publish so
        # we exercise both replay and live-fanout paths. Even a
        # zero-sleep yield is sufficient because subscribe() is
        # synchronous.
        await asyncio.sleep(0.02)
        await bus.publish(scan.id, "scan.start", {"target": "/"})
        await bus.publish(scan.id, "scanner.start", {"scanner": "alpha"})
        await bus.publish(
            scan.id,
            "scan.complete",
            {"findings_count": 0, "scanner_count": 1, "duration_s": 0.01},
        )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        producer = asyncio.create_task(_producer())
        async with client.stream(
            "GET", f"/api/v1/scans/{scan.id}/events", timeout=5.0
        ) as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            chunks: list[str] = []
            async for chunk in resp.aiter_text():
                chunks.append(chunk)
                if "event: scan.complete" in "".join(chunks):
                    break
        await producer

    body = "".join(chunks)
    assert "event: scan.start" in body
    assert "event: scanner.start" in body
    assert "event: scan.complete" in body
    # JSON payload survived the wire intact.
    assert '"findings_count": 0' in body or '"findings_count":0' in body


@pytest.mark.asyncio
async def test_sse_endpoint_terminal_state_immediate_close(temp_db) -> None:
    """For an already-completed scan with NO replay buffer (e.g.,
    backend was restarted), the endpoint synthesizes ONE terminal
    event from DB state and closes — no hang waiting for a replay
    that will never come."""
    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)
    # No replay buffer for this scan_id.
    assert not bus.has_replay(scan.id)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream(
            "GET", f"/api/v1/scans/{scan.id}/events", timeout=5.0
        ) as resp:
            assert resp.status_code == 200
            body = ""
            async for chunk in resp.aiter_text():
                body += chunk

    assert "event: scan.complete" in body
    assert '"status": "completed"' in body or '"status":"completed"' in body
    # Exactly one event frame, no keepalives, no double-emission.
    assert body.count("event: ") == 1


@pytest.mark.asyncio
async def test_sse_endpoint_terminal_state_failed_synthesized(temp_db) -> None:
    """The synthesized-terminal path covers all three terminal
    statuses, not just ``completed``."""
    scan = Scan(
        target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.FAILED, error="boom"
    )
    await save_scan(scan)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream(
            "GET", f"/api/v1/scans/{scan.id}/events", timeout=5.0
        ) as resp:
            assert resp.status_code == 200
            body = ""
            async for chunk in resp.aiter_text():
                body += chunk

    assert "event: scan.failed" in body
    assert '"status": "failed"' in body or '"status":"failed"' in body


@pytest.mark.asyncio
async def test_sse_endpoint_legacy_alias_routes(temp_db) -> None:
    """The legacy ``/api/scans/...`` mount works in addition to the
    canonical ``/api/v1/scans/...`` path (versioning alias contract)."""
    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream(
            "GET", f"/api/scans/{scan.id}/events", timeout=5.0
        ) as resp:
            assert resp.status_code == 200
            body = ""
            async for chunk in resp.aiter_text():
                body += chunk
    assert "event: scan.complete" in body


def test_terminal_constant_matches_log_event_names() -> None:
    """The bus's TERMINAL set must match the lifecycle events
    ``_run_scan`` actually emits, otherwise terminal protection
    breaks silently when an event is renamed."""
    assert TERMINAL == frozenset({"scan.complete", "scan.failed", "scan.cancelled"})
