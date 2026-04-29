"""Tests for the rate-limit middleware (FEAT3).

The middleware is mounted globally on ``securescan.main.app``, but it
re-reads the rate-limit env vars on each request, so individual tests
can flip ``SECURESCAN_RATE_LIMIT_*`` with ``monkeypatch`` and get a
fresh limiter (and therefore an empty bucket dict) without reloading
the app.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from securescan.database import init_db, set_db_path
from securescan.main import app
from securescan.middleware.rate_limit import RateLimiter


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "rate_limit.db")
    set_db_path(db_path)
    asyncio.get_event_loop().run_until_complete(init_db()) if False else None
    asyncio.run(init_db())
    monkeypatch.delenv("SECURESCAN_API_KEY", raising=False)
    return db_path


@pytest.fixture
def scan_dir(tmp_path):
    target = tmp_path / "project"
    target.mkdir()
    (target / "main.py").write_text("print('hi')\n")
    return str(target)


def _post_scan(client: TestClient, target: str, **headers):
    return client.post(
        "/api/scans",
        json={"target_path": target, "scan_types": ["code"]},
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Unit-level RateLimiter tests
# ---------------------------------------------------------------------------


def test_rate_limiter_capacity_uses_max_of_per_min_and_burst():
    rl = RateLimiter(per_min=2, burst=1)
    assert rl.capacity == 2.0
    assert rl.limit_per_min == 2

    rl2 = RateLimiter(per_min=5, burst=20)
    assert rl2.capacity == 20.0
    assert rl2.refill_per_sec == pytest.approx(5.0 / 60.0)


def test_rate_limiter_allows_then_blocks():
    rl = RateLimiter(per_min=2, burst=1)

    async def run():
        a, _, _, _ = await rl.acquire("k1")
        b, _, _, _ = await rl.acquire("k1")
        c, _, retry, _ = await rl.acquire("k1")
        return a, b, c, retry

    a, b, c, retry = asyncio.run(run())
    assert a is True
    assert b is True
    assert c is False
    assert retry > 0


def test_rate_limiter_per_key_isolation():
    rl = RateLimiter(per_min=1, burst=1)

    async def run():
        a1, _, _, _ = await rl.acquire("alice")
        a2, _, _, _ = await rl.acquire("alice")
        b1, _, _, _ = await rl.acquire("bob")
        return a1, a2, b1

    a1, a2, b1 = asyncio.run(run())
    assert a1 is True
    assert a2 is False
    assert b1 is True


# ---------------------------------------------------------------------------
# Middleware integration tests via TestClient
# ---------------------------------------------------------------------------


def test_rate_limit_allows_within_burst(monkeypatch, temp_db, scan_dir):
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_PER_MIN", "60")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_BURST", "10")

    client = TestClient(app, raise_server_exceptions=False)
    headers = {"X-API-Key": "burst-test-key"}
    statuses = []
    for _ in range(5):
        r = _post_scan(client, scan_dir, **headers)
        statuses.append(r.status_code)
    assert all(s != 429 for s in statuses), f"got rate-limited within burst: {statuses}"
    assert all(200 <= s < 300 for s in statuses), f"unexpected statuses: {statuses}"


def test_rate_limit_blocks_excess(monkeypatch, temp_db, scan_dir):
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_PER_MIN", "2")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_BURST", "1")

    client = TestClient(app, raise_server_exceptions=False)
    headers = {"X-API-Key": "excess-test-key"}

    r1 = _post_scan(client, scan_dir, **headers)
    r2 = _post_scan(client, scan_dir, **headers)
    r3 = _post_scan(client, scan_dir, **headers)

    assert r1.status_code != 429
    assert r2.status_code != 429
    assert r3.status_code == 429

    body = r3.json()
    assert body["detail"] == "Rate limit exceeded"
    assert body["limit_per_min"] == 2
    assert body["retry_after"] >= 1

    assert "Retry-After" in r3.headers
    assert int(r3.headers["Retry-After"]) >= 1
    assert r3.headers["X-RateLimit-Limit"] == "2"
    assert r3.headers["X-RateLimit-Remaining"] == "0"
    assert "X-RateLimit-Reset" in r3.headers


def test_rate_limit_per_key_isolation(monkeypatch, temp_db, scan_dir):
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_PER_MIN", "1")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_BURST", "1")

    client = TestClient(app, raise_server_exceptions=False)

    r_alice_1 = _post_scan(client, scan_dir, **{"X-API-Key": "alice"})
    r_alice_2 = _post_scan(client, scan_dir, **{"X-API-Key": "alice"})
    r_bob_1 = _post_scan(client, scan_dir, **{"X-API-Key": "bob"})

    assert r_alice_1.status_code != 429
    assert r_alice_2.status_code == 429
    assert r_bob_1.status_code != 429, (
        f"bob should have his own bucket; got {r_bob_1.status_code}"
    )


def test_rate_limit_disabled(monkeypatch, temp_db, scan_dir):
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_PER_MIN", "1")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_BURST", "1")

    client = TestClient(app, raise_server_exceptions=False)
    headers = {"X-API-Key": "disabled-key"}

    statuses = [_post_scan(client, scan_dir, **headers).status_code for _ in range(5)]
    assert all(s != 429 for s in statuses), (
        f"limiter disabled but got 429 in {statuses}"
    )

    last = _post_scan(client, scan_dir, **headers)
    assert "X-RateLimit-Limit" not in last.headers, (
        "should not emit rate-limit headers when disabled"
    )


def test_rate_limit_bypass_get(monkeypatch, temp_db):
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_PER_MIN", "1")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_BURST", "1")

    client = TestClient(app, raise_server_exceptions=False)
    headers = {"X-API-Key": "get-bypass-key"}

    statuses = [client.get("/api/scans", headers=headers).status_code for _ in range(5)]
    assert all(s != 429 for s in statuses), (
        f"GET /api/scans must never be rate-limited, got {statuses}"
    )


def test_rate_limit_headers_present(monkeypatch, temp_db, scan_dir):
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_PER_MIN", "60")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_BURST", "10")

    client = TestClient(app, raise_server_exceptions=False)
    headers = {"X-API-Key": "headers-test-key"}

    r = _post_scan(client, scan_dir, **headers)
    assert r.status_code != 429
    assert r.headers.get("X-RateLimit-Limit") == "60"
    remaining = int(r.headers["X-RateLimit-Remaining"])
    assert 0 <= remaining < 60
    reset = int(r.headers["X-RateLimit-Reset"])
    assert reset > 0


def test_rate_limit_v1_path_also_limited(monkeypatch, temp_db, scan_dir):
    """Same bucket should apply to /api/v1/scans path (forward-compat
    with the /api/v1 mount FEAT2 is adding -- the regex matches both)."""
    from securescan.middleware.rate_limit import RateLimitMiddleware

    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_PER_MIN", "60")
    monkeypatch.setenv("SECURESCAN_RATE_LIMIT_BURST", "10")

    class _Req:
        def __init__(self, method: str, path: str) -> None:
            self.method = method

            class _URL:
                pass

            self.url = _URL()
            self.url.path = path

    assert RateLimitMiddleware._is_rate_limited_route(_Req("POST", "/api/scans")) is True
    assert RateLimitMiddleware._is_rate_limited_route(_Req("POST", "/api/scans/")) is True
    assert RateLimitMiddleware._is_rate_limited_route(_Req("POST", "/api/v1/scans")) is True
    assert RateLimitMiddleware._is_rate_limited_route(_Req("POST", "/api/v1/scans/")) is True
    assert RateLimitMiddleware._is_rate_limited_route(_Req("GET", "/api/scans")) is False
    assert RateLimitMiddleware._is_rate_limited_route(_Req("POST", "/api/scans/abc/cancel")) is False
    assert RateLimitMiddleware._is_rate_limited_route(_Req("POST", "/api/dashboard/status")) is False


def test_rate_limit_falls_back_to_client_ip(monkeypatch):
    """When no X-API-Key, identity should fall back to client IP."""
    from securescan.middleware.rate_limit import _identity

    class _Client:
        host = "10.0.0.1"

    class _Req:
        def __init__(self, headers: dict, client) -> None:
            self.headers = headers
            self.client = client

    assert _identity(_Req({}, _Client())).endswith(":10.0.0.1")
    assert _identity(_Req({"x-api-key": "k"}, _Client())).endswith(":k")
    assert _identity(_Req({}, None)) == "anonymous"
