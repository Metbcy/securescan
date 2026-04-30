"""Tests for outbound webhooks (BE-WEBHOOKS).

Three layers covered:

* CRUD endpoints (auth, secret-only-once, cascading delete, URL validation).
* Dispatcher (success + retry + max-age + signature + body bytes + FIFO + filter).
* Durability (startup-reset of stale 'delivering' rows; resume after restart).
* Per-receiver formatters (Slack / Discord / generic).
* The synthetic test endpoint.

HTTP transport mocking
----------------------
We don't pull respx into the dev-deps (extra dependency, slower
import); instead we inject a lightweight stub object as
``dispatcher.client``. The stub records every outbound POST and
returns a programmable response (or raises a
:class:`httpx.RequestError`). This is the same boundary
``httpx.AsyncClient`` exposes (``async post(url, content=, headers=)``)
so the dispatcher code under test is identical to production.

Deterministic timing
--------------------
The retry-policy constants on :mod:`securescan.webhook_dispatcher`
are module-level (``MAX_AGE_SECONDS``, ``BASE_BACKOFF_SECONDS``,
``MAX_BACKOFF_SECONDS``, ``POLL_INTERVAL_SECONDS``) precisely so tests
can monkeypatch them down to tiny values and let ``random.uniform``
pick a backoff inside [0, tiny_cap], which we then poll for via
:func:`asyncio.sleep` rather than wall-clock waits. We also drive
the loop one tick at a time via :meth:`WebhookDispatcher.run_once`
so we never need to start the long-running task in unit tests.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from datetime import datetime, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

from securescan import webhook_dispatcher as wd
from securescan.api import scans as scans_api
from securescan.database import (
    get_webhook_delivery,
    init_db,
    insert_webhook,
    insert_webhook_delivery,
    list_deliveries_for_webhook,
    list_pending_deliveries,
    reset_stale_delivering_deliveries,
    set_db_path,
)
from securescan.main import app
from securescan.webhook_dispatcher import WebhookDispatcher
from securescan.webhook_formatters import format_payload

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Fresh DB per test; reset path on teardown so sibling test
    modules see the legacy default. Auth env vars are cleared so the
    /api/webhooks routes are reachable in dev mode without an admin
    key (the scope dependency fails-open when no principal exists)."""
    from securescan.config import settings as _settings

    db_path = str(tmp_path / "webhooks.db")
    original = _settings.database_path
    set_db_path(db_path)
    asyncio.run(init_db())
    monkeypatch.delenv("SECURESCAN_API_KEY", raising=False)
    monkeypatch.delenv("SECURESCAN_AUTH_REQUIRED", raising=False)
    yield db_path
    set_db_path(original)


@pytest.fixture
def client(temp_db) -> TestClient:
    # raise_server_exceptions=False mirrors test_api_keys.py so an
    # internal 500 in a handler under test surfaces as a 500 response
    # instead of being re-raised through the test runner.
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# HTTP-transport stub
# ---------------------------------------------------------------------------


class _Resp:
    """Minimal duck of httpx.Response: status_code + text are all the
    dispatcher reads."""

    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text


class _StubClient:
    """Records POSTs; returns canned responses or raises RequestError.

    `responses` is a list consumed in order; if shorter than the
    number of POSTs, the last entry is repeated (so a single 200
    returned forever is just `[ _Resp(200) ]`). Pass a list element
    that is an Exception instance to make that call raise (transport
    error path).
    """

    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.calls: list[dict] = []
        self._idx = 0
        self._closed = False

    async def post(self, url, content=None, headers=None):
        self.calls.append(
            {
                "url": url,
                "content": content,
                "headers": dict(headers or {}),
            }
        )
        if self._idx < len(self.responses):
            r = self.responses[self._idx]
            self._idx += 1
        else:
            r = self.responses[-1]
        if isinstance(r, BaseException):
            raise r
        return r

    async def aclose(self) -> None:
        self._closed = True


@pytest.fixture
def fresh_dispatcher(monkeypatch):
    """A throwaway WebhookDispatcher per test.

    Tests poke at it via ``run_once()`` to drive a single poll-and-
    dispatch tick; nothing here starts the long-running task. We
    also speed retry timing down so even multi-attempt tests finish
    in well under a second.
    """
    monkeypatch.setattr(wd, "BASE_BACKOFF_SECONDS", 0.001)
    monkeypatch.setattr(wd, "MAX_BACKOFF_SECONDS", 0.005)
    monkeypatch.setattr(wd, "POLL_INTERVAL_SECONDS", 0.01)
    d = WebhookDispatcher()
    return d


async def _seed_webhook(
    *,
    name: str = "test-hook",
    url: str = "https://example.com/hook",
    secret: str = "topsecret",
    events: list[str] | None = None,
    enabled: bool = True,
) -> str:
    import uuid as _uuid

    wh_id = str(_uuid.uuid4())
    await insert_webhook(
        id=wh_id,
        name=name,
        url=url,
        secret=secret,
        event_filter=events or ["scan.complete"],
        enabled=enabled,
        created_at=datetime.utcnow(),
    )
    return wh_id


async def _enqueue(
    webhook_id: str,
    *,
    event: str = "scan.complete",
    payload: dict | None = None,
    next_at: datetime | None = None,
    created_at: datetime | None = None,
) -> str:
    import uuid as _uuid

    delivery_id = str(_uuid.uuid4())
    now = datetime.utcnow()
    await insert_webhook_delivery(
        id=delivery_id,
        webhook_id=webhook_id,
        event=event,
        payload=json.dumps(payload or {"scan_id": "abc", "findings_count": 1}),
        next_attempt_at=next_at or now,
        created_at=created_at or now,
    )
    return delivery_id


async def _wait_for(predicate, *, timeout: float = 2.0, interval: float = 0.01):
    """Poll a predicate until it returns truthy or timeout expires.

    Used in place of `time.sleep` to wait for asyncio-driven side
    effects (delivery row status flips). The interval is much smaller
    than the test timeout so even tightly-timed retries are caught.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        if await predicate() if asyncio.iscoroutinefunction(predicate) else predicate():
            return True
        await asyncio.sleep(interval)
    return False


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def test_create_webhook_returns_secret_once(client):
    body = {
        "name": "deploy-bot",
        "url": "https://example.com/hook",
        "event_filter": ["scan.complete"],
    }
    res = client.post("/api/v1/webhooks", json=body)
    assert res.status_code == 201, res.text
    data = res.json()
    assert data["name"] == "deploy-bot"
    assert data["url"] == "https://example.com/hook"
    assert data["enabled"] is True
    assert "secret" in data and len(data["secret"]) >= 32
    wh_id = data["id"]

    # Subsequent GET strips the secret.
    res2 = client.get(f"/api/v1/webhooks/{wh_id}")
    assert res2.status_code == 200
    assert "secret" not in res2.json()


def test_list_webhooks_excludes_secret(client):
    res = client.post(
        "/api/v1/webhooks",
        json={
            "name": "a",
            "url": "https://a.example.com/hook",
            "event_filter": ["scan.complete"],
        },
    )
    assert res.status_code == 201
    res = client.get("/api/v1/webhooks")
    assert res.status_code == 200
    items = res.json()
    assert len(items) == 1
    assert "secret" not in items[0]


def test_patch_webhook_does_not_rotate_secret(client):
    res = client.post(
        "/api/v1/webhooks",
        json={
            "name": "a",
            "url": "https://a.example.com/hook",
            "event_filter": ["scan.complete"],
        },
    )
    wh_id = res.json()["id"]
    original_secret = res.json()["secret"]

    # Try to PATCH with a `secret` field -- it must be ignored
    # silently (extra keys not allowed in our model would 422; we
    # just check the field cannot make it into the row).
    res = client.patch(
        f"/api/v1/webhooks/{wh_id}",
        json={"name": "renamed", "enabled": False},
    )
    assert res.status_code == 200
    assert res.json()["name"] == "renamed"
    assert res.json()["enabled"] is False

    # The body model has no `secret` field; confirm DB still has the
    # original by reading via the dispatcher path (get_webhook_row).
    from securescan.database import get_webhook_row

    row = asyncio.run(get_webhook_row(wh_id))
    assert row["secret"] == original_secret


def test_delete_cascades_deliveries(client, temp_db):
    res = client.post(
        "/api/v1/webhooks",
        json={
            "name": "a",
            "url": "https://a.example.com/hook",
            "event_filter": ["scan.complete"],
        },
    )
    wh_id = res.json()["id"]

    # Seed two delivery rows directly via the DB layer (cheaper than
    # going through the test endpoint twice).
    asyncio.run(_enqueue(wh_id))
    asyncio.run(_enqueue(wh_id))

    deliveries = asyncio.run(list_deliveries_for_webhook(wh_id))
    assert len(deliveries) == 2

    res = client.delete(f"/api/v1/webhooks/{wh_id}")
    assert res.status_code == 204

    # Row is gone.
    assert client.get(f"/api/v1/webhooks/{wh_id}").status_code == 404
    # Cascaded -- no delivery rows survive.
    deliveries = asyncio.run(list_deliveries_for_webhook(wh_id))
    assert deliveries == []


@pytest.mark.parametrize(
    "bad_url",
    [
        "file:///etc/passwd",
        "ftp://example.com/hook",
        "javascript:alert(1)",
        "gopher://example.com/",
        "//example.com/hook",
        "example.com/hook",
        "http ://example.com/hook",
    ],
)
def test_invalid_url_rejected(client, bad_url):
    res = client.post(
        "/api/v1/webhooks",
        json={
            "name": "bad",
            "url": bad_url,
            "event_filter": ["scan.complete"],
        },
    )
    assert res.status_code == 422, (bad_url, res.text)


def test_create_requires_at_least_one_event(client):
    res = client.post(
        "/api/v1/webhooks",
        json={
            "name": "no-events",
            "url": "https://example.com/hook",
            "event_filter": [],
        },
    )
    assert res.status_code == 422


def test_get_unknown_returns_404(client):
    assert client.get("/api/v1/webhooks/does-not-exist").status_code == 404
    assert client.patch("/api/v1/webhooks/does-not-exist", json={"name": "x"}).status_code == 404
    assert client.delete("/api/v1/webhooks/does-not-exist").status_code == 404


# ---------------------------------------------------------------------------
# Delivery (dispatcher)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delivery_succeeds_marks_succeeded(temp_db, fresh_dispatcher):
    wh_id = await _seed_webhook()
    delivery_id = await _enqueue(wh_id)

    fresh_dispatcher.client = _StubClient([_Resp(204)])
    scheduled = await fresh_dispatcher.run_once()
    assert scheduled == 1

    async def _ready():
        row = await get_webhook_delivery(delivery_id)
        return row["status"] == "succeeded"

    assert await _wait_for(_ready), "delivery never reached 'succeeded'"
    row = await get_webhook_delivery(delivery_id)
    assert row["response_code"] == 204
    assert row["attempt"] == 1


@pytest.mark.asyncio
async def test_delivery_5xx_retries(temp_db, fresh_dispatcher):
    wh_id = await _seed_webhook()
    delivery_id = await _enqueue(wh_id)

    stub = _StubClient([_Resp(503, "down"), _Resp(200, "ok")])
    fresh_dispatcher.client = stub

    # Tick 1: 503 -> rescheduled to 'pending' with a tiny backoff.
    await fresh_dispatcher.run_once()

    async def _retry_pending():
        row = await get_webhook_delivery(delivery_id)
        return row["status"] == "pending" and row["attempt"] >= 1

    assert await _wait_for(_retry_pending)

    # Wait for next_attempt_at to elapse (BASE_BACKOFF * jitter is
    # at most ~5ms here) then tick the loop again. We retry in a
    # short loop because a) the backoff floor is 0 so usually the
    # first re-tick succeeds, but b) jitter could land at the cap.
    async def _eventually_succeeded():
        await fresh_dispatcher.run_once()
        await asyncio.sleep(0.02)
        row = await get_webhook_delivery(delivery_id)
        return row["status"] == "succeeded"

    assert await _wait_for(_eventually_succeeded, timeout=2.0)
    row = await get_webhook_delivery(delivery_id)
    assert row["status"] == "succeeded"
    assert row["attempt"] == 2
    assert len(stub.calls) == 2


@pytest.mark.asyncio
async def test_delivery_5xx_max_age_fails(temp_db, fresh_dispatcher, monkeypatch):
    """Past MAX_AGE_SECONDS the row terminal-fails on next attempt."""
    monkeypatch.setattr(wd, "MAX_AGE_SECONDS", 0.0)
    wh_id = await _seed_webhook()
    delivery_id = await _enqueue(wh_id)

    fresh_dispatcher.client = _StubClient([_Resp(503, "down")])

    await fresh_dispatcher.run_once()

    async def _failed():
        row = await get_webhook_delivery(delivery_id)
        return row["status"] == "failed"

    assert await _wait_for(_failed, timeout=2.0)
    row = await get_webhook_delivery(delivery_id)
    assert row["response_code"] == 503


@pytest.mark.asyncio
async def test_delivery_transport_error_retries(temp_db, fresh_dispatcher):
    wh_id = await _seed_webhook()
    delivery_id = await _enqueue(wh_id)

    fresh_dispatcher.client = _StubClient(
        [
            httpx.ConnectError("boom"),
            _Resp(200, "ok"),
        ]
    )

    await fresh_dispatcher.run_once()

    async def _pending_after_transport_err():
        row = await get_webhook_delivery(delivery_id)
        return row["status"] == "pending" and (row["response_body"] or "").startswith("transport:")

    assert await _wait_for(_pending_after_transport_err)

    async def _eventually_succeeds():
        await fresh_dispatcher.run_once()
        await asyncio.sleep(0.02)
        row = await get_webhook_delivery(delivery_id)
        return row["status"] == "succeeded"

    assert await _wait_for(_eventually_succeeds, timeout=2.0)


@pytest.mark.asyncio
async def test_delivery_signature_correct(temp_db, fresh_dispatcher):
    """The X-SecureScan-Signature must verify against `t.body`."""
    secret = "shhh-its-a-secret"
    wh_id = await _seed_webhook(secret=secret)
    await _enqueue(wh_id, payload={"scan_id": "abc", "findings_count": 7})

    stub = _StubClient([_Resp(200, "ok")])
    fresh_dispatcher.client = stub
    await fresh_dispatcher.run_once()

    async def _called():
        return len(stub.calls) == 1

    assert await _wait_for(_called)
    call = stub.calls[0]

    sig_header = call["headers"]["X-SecureScan-Signature"]
    # Format: "t=<unix>,v1=<hex>"
    assert sig_header.startswith("t=")
    parts = dict(p.split("=", 1) for p in sig_header.split(","))
    ts = parts["t"]
    sig_v1 = parts["v1"]

    # Recompute and compare.
    body = call["content"]
    expected = hmac.new(
        secret.encode(),
        f"{ts}.".encode() + body,
        hashlib.sha256,
    ).hexdigest()
    assert hmac.compare_digest(expected, sig_v1)

    # Convenience headers.
    assert call["headers"]["X-SecureScan-Event"] == "scan.complete"
    assert call["headers"]["X-SecureScan-Webhook-Id"] == wh_id
    assert call["headers"]["Content-Type"] == "application/json"
    assert call["headers"]["User-Agent"].startswith("SecureScan-Webhook/")


@pytest.mark.asyncio
async def test_delivery_body_uses_json_dumps_separators(temp_db, fresh_dispatcher):
    """Body must be compact JSON (no whitespace) -- this is the bytes
    we sign, so any drift between dumps args here and in production
    breaks signatures."""
    wh_id = await _seed_webhook()
    await _enqueue(wh_id)

    stub = _StubClient([_Resp(200, "ok")])
    fresh_dispatcher.client = stub
    await fresh_dispatcher.run_once()

    async def _called():
        return len(stub.calls) == 1

    assert await _wait_for(_called)
    body: bytes = stub.calls[0]["content"]
    text = body.decode()
    # Compact JSON: no ", " separator, no ": " separator.
    assert ", " not in text
    assert ": " not in text
    # Must still be valid JSON.
    decoded = json.loads(text)
    assert decoded["event"] == "scan.complete"


@pytest.mark.asyncio
async def test_event_filter_drops_unmatched_events(temp_db):
    """A webhook whose filter does NOT include the event must not
    receive a delivery row.

    We exercise the same enqueue helper that ``_log_scan_event``
    uses, so this also pins the routing decision."""
    wh_id = await _seed_webhook(events=["scan.complete"])

    await scans_api._enqueue_webhook_deliveries(
        "scanner.failed", "scan-xyz", {"scanner": "bandit", "error": "boom"}
    )

    pending = await list_pending_deliveries(limit=10)
    assert pending == [], pending

    # And the matching event DOES enqueue.
    await scans_api._enqueue_webhook_deliveries("scan.complete", "scan-xyz", {"findings_count": 3})
    pending = await list_pending_deliveries(limit=10)
    assert len(pending) == 1
    assert pending[0]["webhook_id"] == wh_id
    assert pending[0]["event"] == "scan.complete"


@pytest.mark.asyncio
async def test_disabled_webhook_does_not_receive(temp_db):
    """An `enabled=0` subscription is invisible to the enqueuer."""
    await _seed_webhook(events=["scan.complete"], enabled=False)
    await scans_api._enqueue_webhook_deliveries("scan.complete", "scan-xyz", {"findings_count": 3})
    pending = await list_pending_deliveries(limit=10)
    assert pending == []


# ---------------------------------------------------------------------------
# Durability
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_startup_resets_stale_delivering_rows(temp_db):
    """A 'delivering' row left over from a crash flips to 'pending'."""
    wh_id = await _seed_webhook()
    delivery_id = await _enqueue(wh_id)

    # Simulate the worker having claimed the row right before crash.
    from securescan.database import mark_delivery_delivering

    claimed = await mark_delivery_delivering(delivery_id)
    assert claimed
    row = await get_webhook_delivery(delivery_id)
    assert row["status"] == "delivering"

    n = await reset_stale_delivering_deliveries()
    assert n == 1
    row = await get_webhook_delivery(delivery_id)
    assert row["status"] == "pending"


@pytest.mark.asyncio
async def test_dispatcher_resumes_after_restart(temp_db, fresh_dispatcher):
    """A pending row whose next_attempt_at is in the past is picked
    up and dispatched on the first poll tick after start()."""
    wh_id = await _seed_webhook()
    past = datetime.utcnow() - timedelta(seconds=60)
    delivery_id = await _enqueue(wh_id, next_at=past, created_at=past)

    # Inject the stub client BEFORE start() so reset_stale + first
    # tick run with it in place.
    fresh_dispatcher.client = _StubClient([_Resp(200, "ok")])
    await fresh_dispatcher.start()

    async def _delivered():
        row = await get_webhook_delivery(delivery_id)
        return row["status"] == "succeeded"

    assert await _wait_for(_delivered, timeout=2.0)
    await fresh_dispatcher.stop()


@pytest.mark.asyncio
async def test_fifo_per_webhook(temp_db, fresh_dispatcher):
    """Two pending rows for the same webhook must dispatch sequentially.

    We block the first delivery's HTTP call on an asyncio.Event and
    confirm the second hasn't been attempted yet, then unblock and
    assert both eventually succeed.
    """
    wh_id = await _seed_webhook()
    first = await _enqueue(
        wh_id,
        payload={"scan_id": "first"},
        created_at=datetime.utcnow() - timedelta(seconds=2),
    )
    second = await _enqueue(
        wh_id,
        payload={"scan_id": "second"},
        created_at=datetime.utcnow(),
    )

    gate = asyncio.Event()
    call_count = 0

    class _GatedClient:
        async def post(self, url, content=None, headers=None):
            nonlocal call_count
            call_count += 1
            await gate.wait()
            return _Resp(200, "ok")

        async def aclose(self):
            pass

    fresh_dispatcher.client = _GatedClient()
    scheduled = await fresh_dispatcher.run_once()
    # Both are eligible by next_attempt_at, but only one is scheduled
    # because of the FIFO guard.
    assert scheduled == 1

    # Give the first dispatch task a chance to actually call .post.
    async def _first_in_flight():
        return call_count == 1

    assert await _wait_for(_first_in_flight)

    # Second tick: still blocked on the gate, FIFO guard rejects.
    scheduled2 = await fresh_dispatcher.run_once()
    assert scheduled2 == 0
    # And the second row is still 'pending' (untouched, attempt=0).
    second_row = await get_webhook_delivery(second)
    assert second_row["status"] == "pending"
    assert second_row["attempt"] == 0

    # Release the first; assert it succeeds, then the second goes through.
    gate.set()

    async def _first_done():
        row = await get_webhook_delivery(first)
        return row["status"] == "succeeded"

    assert await _wait_for(_first_done, timeout=2.0)

    async def _second_done():
        await fresh_dispatcher.run_once()
        await asyncio.sleep(0.02)
        row = await get_webhook_delivery(second)
        return row["status"] == "succeeded"

    assert await _wait_for(_second_done, timeout=2.0)
    assert call_count == 2


@pytest.mark.asyncio
async def test_mark_delivering_is_atomic(temp_db):
    """Two concurrent claims on the same row: only one wins."""
    wh_id = await _seed_webhook()
    delivery_id = await _enqueue(wh_id)

    from securescan.database import mark_delivery_delivering

    a, b = await asyncio.gather(
        mark_delivery_delivering(delivery_id),
        mark_delivery_delivering(delivery_id),
    )
    # Exactly one True, one False.
    assert sorted([a, b]) == [False, True]


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def test_slack_url_uses_slack_formatter():
    out = format_payload(
        "https://hooks.slack.com/services/T/B/X",
        "scan.complete",
        {"scan_id": "deadbeefcafe", "findings_count": 5},
    )
    assert "text" in out and "blocks" in out
    assert "Scan deadbeef" in out["text"]
    assert "5 findings" in out["text"]


def test_discord_url_uses_discord_formatter():
    out = format_payload(
        "https://discord.com/api/webhooks/123/abc",
        "scan.failed",
        {"scan_id": "deadbeefcafe", "error": "boom"},
    )
    assert "content" in out and "embeds" in out
    assert "deadbeef" in out["content"]
    assert "boom" in out["content"]
    assert out["embeds"][0]["color"] == 0xFF8C00


def test_generic_url_uses_generic_payload():
    out = format_payload(
        "https://example.com/internal/hook",
        "scan.complete",
        {"scan_id": "x", "findings_count": 0},
    )
    assert set(out.keys()) == {"event", "data", "delivered_at"}
    assert out["event"] == "scan.complete"
    assert out["data"] == {"scan_id": "x", "findings_count": 0}


def test_test_event_summary_text():
    out = format_payload(
        "https://hooks.slack.com/services/T/B/X",
        "webhook.test",
        {"message": "hi"},
    )
    assert "webhook test" in out["text"].lower()


# ---------------------------------------------------------------------------
# Test endpoint
# ---------------------------------------------------------------------------


def test_webhook_test_creates_synthetic_delivery(client):
    res = client.post(
        "/api/v1/webhooks",
        json={
            "name": "tester",
            "url": "https://example.com/hook",
            "event_filter": ["scan.complete"],  # NOTE: webhook.test bypasses filter
        },
    )
    wh_id = res.json()["id"]

    res = client.post(f"/api/v1/webhooks/{wh_id}/test")
    assert res.status_code == 202
    delivery_id = res.json()["delivery_id"]

    # The delivery row exists and references this webhook.
    deliveries = asyncio.run(list_deliveries_for_webhook(wh_id))
    assert len(deliveries) == 1
    assert deliveries[0].id == delivery_id
    assert deliveries[0].event == "webhook.test"
    assert deliveries[0].status == "pending"


def test_webhook_test_unknown_404(client):
    assert client.post("/api/v1/webhooks/does-not-exist/test").status_code == 404
