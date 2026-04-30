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
        async with client.stream("GET", f"/api/v1/scans/{scan.id}/events", timeout=5.0) as resp:
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
        async with client.stream("GET", f"/api/v1/scans/{scan.id}/events", timeout=5.0) as resp:
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
    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.FAILED, error="boom")
    await save_scan(scan)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream("GET", f"/api/v1/scans/{scan.id}/events", timeout=5.0) as resp:
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
        async with client.stream("GET", f"/api/scans/{scan.id}/events", timeout=5.0) as resp:
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


# ---------------------------------------------------------------------------
# Event-token integration (BE-SSE-TOKEN)
#
# EventSource can't send X-API-Key, so authenticated deployments mint
# a short-lived signed token via POST .../event-token then attach it
# as ?event_token=... on the SSE GET. These tests pin the end-to-end
# auth path: token honored on /events, rejected elsewhere, revocation
# takes effect immediately.
# ---------------------------------------------------------------------------

from datetime import datetime  # noqa: E402  (kept here for the BE-SSE-TOKEN block)

from securescan import api_keys as ak  # noqa: E402
from securescan import auth as _auth  # noqa: E402
from securescan import event_tokens  # noqa: E402
from securescan.database import insert_api_key, revoke_api_key  # noqa: E402


@pytest.fixture
def signing_secret(monkeypatch):
    """Pin a known signing secret for the event-token tests.

    Without this the lazy resolver would mint an ephemeral one,
    which works but is harder to reason about across the
    mint/verify boundary.
    """
    monkeypatch.setenv("SECURESCAN_EVENT_TOKEN_SECRET", "sse-token-test-secret-xyz")
    event_tokens.reset_for_tests()
    yield
    event_tokens.reset_for_tests()


@pytest.fixture
def env_auth(monkeypatch):
    """Run the SSE tests under env-var auth so X-API-Key would
    normally be required and the token path actually has work to do."""
    monkeypatch.setenv(_auth.ENV_VAR, "env-test-key")
    yield "env-test-key"


@pytest.mark.asyncio
async def test_mint_endpoint_returns_no_store(temp_db, signing_secret, env_auth) -> None:
    scan = Scan(target_path="/", scan_types=[ScanType.CODE])
    await save_scan(scan)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            f"/api/v1/scans/{scan.id}/event-token",
            headers={"X-API-Key": env_auth},
        )
    assert resp.status_code == 200
    assert resp.headers["cache-control"] == "no-store"
    body = resp.json()
    assert "token" in body and isinstance(body["token"], str) and body["token"]
    assert body["expires_in"] == event_tokens.TOKEN_TTL_SECONDS


@pytest.mark.asyncio
async def test_mint_endpoint_404_unknown_scan(temp_db, signing_secret, env_auth) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/scans/no-such-scan/event-token",
            headers={"X-API-Key": env_auth},
        )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_event_token_query_param_accepted_on_sse_route(
    temp_db, signing_secret, env_auth
) -> None:
    """POST mint, then GET /events with ?event_token=... and NO
    X-API-Key — proves EventSource can connect."""
    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)

    token, _ = event_tokens.mint(scan.id, "env")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream(
            "GET",
            f"/api/v1/scans/{scan.id}/events?event_token={token}",
            timeout=5.0,
        ) as resp:
            assert resp.status_code == 200
            body = ""
            async for chunk in resp.aiter_text():
                body += chunk
    assert "event: scan.complete" in body


@pytest.mark.asyncio
async def test_event_token_rejected_on_non_sse_route(temp_db, signing_secret, env_auth) -> None:
    """A leaked token MUST NOT be usable on any non-/events route.
    The auth dependency only consults event_token when the request
    path ends in /events, so the token here is ignored and the
    missing X-API-Key wins → 401."""
    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)
    token, _ = event_tokens.mint(scan.id, "env")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/scans/{scan.id}?event_token={token}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_dev_mode_token_round_trips(temp_db, signing_secret) -> None:
    """In dev mode (no env-var, no DB keys), the mint endpoint binds
    the token to a 'dev' sentinel rather than 'env'. The verifier
    accepts these only while the system remains in dev mode — once
    auth is enabled (env-var set or DB key created), dev tokens are
    invalidated.

    Regression for a bug where the v0.9.0 mint endpoint set
    key_id='env' for dev-mode callers, then verification rejected the
    token because no env-var was actually configured.
    """
    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # Mint without any auth (dev mode).
        mint_resp = await client.post(f"/api/v1/scans/{scan.id}/event-token")
        assert mint_resp.status_code == 200
        token = mint_resp.json()["token"]

        # Verify the token works on the SSE endpoint.
        async with client.stream(
            "GET",
            f"/api/v1/scans/{scan.id}/events?event_token={token}",
            timeout=5.0,
        ) as resp:
            assert resp.status_code == 200


@pytest.mark.asyncio
async def test_dev_mode_token_invalidated_when_auth_enabled(
    temp_db, signing_secret, monkeypatch
) -> None:
    """A dev-mode token issued before credentials existed must be
    rejected once the system is no longer in dev mode."""
    from securescan import auth

    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)

    # Mint while in dev mode.
    token, _ = event_tokens.mint(scan.id, "dev")

    # Now enable auth by setting the env-var; the dev-mode token must
    # no longer be honored.
    monkeypatch.setenv(auth.ENV_VAR, "production-key")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/scans/{scan.id}/events?event_token={token}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_token_bound_to_scan_id_and_key_id(temp_db, signing_secret, env_auth) -> None:
    """A token minted for scan A is rejected when used against scan B.
    The auth dependency cross-checks the URL scan_id against the
    token binding."""
    scan_a = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    scan_b = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan_a)
    await save_scan(scan_b)

    token_for_a, _ = event_tokens.mint(scan_a.id, "env")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/scans/{scan_b.id}/events?event_token={token_for_a}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_event_token_invalid_returns_401(temp_db, signing_secret, env_auth) -> None:
    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/scans/{scan.id}/events?event_token=garbage")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_revoked_key_token_rejected_at_connect(temp_db, signing_secret, monkeypatch) -> None:
    """Mint a token bound to a DB key, revoke the key, try SSE.
    The token's HMAC is still valid AND not yet expired, but
    rehydration sees revoked_at and refuses the connection."""
    monkeypatch.delenv(_auth.ENV_VAR, raising=False)

    # Seed a DB key with read scope so /events is reachable.
    gk = ak.generate_key()
    await insert_api_key(
        gk.id,
        "sse-key",
        gk.key_hash,
        gk.prefix,
        ["read"],
        datetime.utcnow(),
    )

    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)

    token, _ = event_tokens.mint(scan.id, gk.id)

    # Sanity: works while key is live.
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream(
            "GET",
            f"/api/v1/scans/{scan.id}/events?event_token={token}",
            timeout=5.0,
        ) as resp:
            assert resp.status_code == 200
            async for _ in resp.aiter_text():
                pass

    # Revoke and re-attempt.
    revoked = await revoke_api_key(gk.id)
    assert revoked is True
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/scans/{scan.id}/events?event_token={token}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_env_token_unset_after_mint_rejected(temp_db, signing_secret, monkeypatch) -> None:
    """Mint with env-var auth, unset the env var, try SSE.
    Rehydration of an "env" principal requires the env-var key to
    still be configured."""
    monkeypatch.setenv(_auth.ENV_VAR, "env-key-soon-gone")

    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)
    token, _ = event_tokens.mint(scan.id, "env")

    monkeypatch.delenv(_auth.ENV_VAR, raising=False)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get(f"/api/v1/scans/{scan.id}/events?event_token={token}")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_mint_endpoint_uses_db_key_id_when_authed_via_db(
    temp_db, signing_secret, monkeypatch
) -> None:
    """When the mint POST is authed via a DB key, the issued token
    is bound to that key's id (not 'env'), so revoking the DB key
    invalidates the token."""
    monkeypatch.delenv(_auth.ENV_VAR, raising=False)
    gk = ak.generate_key()
    await insert_api_key(
        gk.id,
        "mint-key",
        gk.key_hash,
        gk.prefix,
        ["read"],
        datetime.utcnow(),
    )

    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            f"/api/v1/scans/{scan.id}/event-token",
            headers={"X-API-Key": gk.full},
        )
    assert resp.status_code == 200
    payload = event_tokens.verify(resp.json()["token"])
    assert payload is not None
    assert payload.key_id == gk.id


@pytest.mark.asyncio
async def test_event_token_legacy_alias_accepted(temp_db, signing_secret, env_auth) -> None:
    """The query-string token works on the legacy /api/scans/... mount
    too (the SSE path lives behind both v1 and the legacy alias)."""
    scan = Scan(target_path="/", scan_types=[ScanType.CODE], status=ScanStatus.COMPLETED)
    await save_scan(scan)
    token, _ = event_tokens.mint(scan.id, "env")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        async with client.stream(
            "GET",
            f"/api/scans/{scan.id}/events?event_token={token}",
            timeout=5.0,
        ) as resp:
            assert resp.status_code == 200
            body = ""
            async for chunk in resp.aiter_text():
                body += chunk
    assert "event: scan.complete" in body
