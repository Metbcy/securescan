"""Tests for the in-app notifications backend (BE-NOTIFY).

Covers:
- CRUD: insert, list (newest-first), unread filter, mark_read (with
  idempotency), mark_all_read, count_unread, pagination + 200-cap.
- Auto-creation: filtering rules in `_log_scan_event` for
  scan.complete (count-gated), scan.failed (always), scanner.failed
  (always), and a representative "no notification" event.
- Pruning: deletes only read notifications past the cutoff; never
  touches unread rows.
- HTTP API: GET list, GET unread-count, PATCH 404 on unknown id.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import aiosqlite
import pytest
from fastapi.testclient import TestClient

from securescan.api.scans import _create_notification_for_event
from securescan.database import (
    count_unread_notifications,
    init_db,
    insert_notification,
    list_notifications,
    mark_all_notifications_read,
    mark_notification_read,
    prune_old_notifications,
    set_db_path,
)
from securescan.main import app
from securescan.models import NotificationSeverity

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Fresh DB + cleared auth env per test.

    Reset the global `_db_path` on teardown so tables created in this
    file's tmp file don't leak into sibling test modules whose fixtures
    rely on the production default.
    """
    from securescan.config import settings as _settings

    db_path = str(tmp_path / "notifications.db")
    original = _settings.database_path
    set_db_path(db_path)
    asyncio.run(init_db())
    monkeypatch.delenv("SECURESCAN_API_KEY", raising=False)
    yield db_path
    set_db_path(original)


@pytest.fixture
def client(temp_db) -> TestClient:
    with TestClient(app) as c:
        yield c


def _run(coro):
    return asyncio.run(coro)


async def _backdate_notification(
    db_path: str, notification_id: str, *, created_at: datetime, read_at: datetime | None
) -> None:
    """Reach into the DB to rewrite created_at / read_at for one row.

    The CRUD layer always stamps `created_at = utcnow()`, which is fine
    for the happy-path tests but useless when we need to simulate a row
    that's 31 days old. This helper is the test-only escape hatch; do
    NOT use it in production code.
    """
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "UPDATE notifications SET created_at = ?, read_at = ? WHERE id = ?",
            (
                created_at.isoformat(),
                read_at.isoformat() if read_at else None,
                notification_id,
            ),
        )
        await db.commit()


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def test_insert_and_list(temp_db):
    async def _go():
        a = await insert_notification(type="scan.complete", title="A")
        # Force a microsecond gap so created_at is strictly later for
        # the second insert; iso strings compare lexicographically.
        await asyncio.sleep(0.01)
        b = await insert_notification(type="scan.failed", title="B")
        rows = await list_notifications()
        return a, b, rows

    a, b, rows = _run(_go())
    assert [r.id for r in rows] == [b.id, a.id], "newest first"
    assert all(r.read_at is None for r in rows)


def test_unread_only_filter(temp_db):
    async def _go():
        a = await insert_notification(type="t", title="A")
        await asyncio.sleep(0.01)
        b = await insert_notification(type="t", title="B")
        await asyncio.sleep(0.01)
        c = await insert_notification(type="t", title="C")
        # Mark the middle one read.
        ok = await mark_notification_read(b.id)
        unread = await list_notifications(unread_only=True)
        return a, b, c, ok, unread

    a, b, c, ok, unread = _run(_go())
    assert ok is True
    ids = {n.id for n in unread}
    assert ids == {a.id, c.id}


def test_unread_count(temp_db):
    async def _go():
        for i in range(5):
            await insert_notification(type="t", title=f"n{i}")
        all_rows = await list_notifications()
        # Mark first three as read.
        for n in all_rows[:3]:
            await mark_notification_read(n.id)
        return await count_unread_notifications()

    count = _run(_go())
    assert count == 2


def test_mark_read_idempotent(temp_db):
    async def _go():
        n = await insert_notification(type="t", title="x")
        first = await mark_notification_read(n.id)
        second = await mark_notification_read(n.id)
        return first, second

    first, second = _run(_go())
    assert first is True, "first call marks the row"
    assert second is False, "second call is a no-op (no exception)"


def test_mark_all_read(temp_db):
    async def _go():
        for i in range(4):
            await insert_notification(type="t", title=f"n{i}")
        marked = await mark_all_notifications_read()
        unread = await count_unread_notifications()
        # A second call returns 0 — idempotent.
        again = await mark_all_notifications_read()
        return marked, unread, again

    marked, unread, again = _run(_go())
    assert marked == 4
    assert unread == 0
    assert again == 0


def test_pagination_limit(temp_db):
    async def _go():
        for i in range(100):
            await insert_notification(type="t", title=f"n{i}")
        rows = await list_notifications(limit=10)
        return rows

    rows = _run(_go())
    assert len(rows) == 10


def test_limit_capped(temp_db, client):
    """The API layer caps `limit` at 200 even when a caller asks for more.

    Going through the HTTP endpoint here (not the DB function) — the
    cap lives in the router on purpose: the DB layer trusts its caller
    so a future internal user can ask for more rows if needed.
    """

    async def _seed():
        for i in range(205):
            await insert_notification(type="t", title=f"n{i}")

    _run(_seed())
    res = client.get("/api/v1/notifications", params={"limit": 99999})
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 200


# ---------------------------------------------------------------------------
# Auto-creation hooks (filtered)
# ---------------------------------------------------------------------------


def test_scan_complete_with_findings_creates_notification(temp_db):
    async def _go():
        await _create_notification_for_event(
            "scan.complete",
            "scan-1",
            {"findings_count": 5, "target": "/proj"},
        )
        return await list_notifications()

    rows = _run(_go())
    assert len(rows) == 1
    n = rows[0]
    assert n.type == "scan.complete"
    assert n.title == "Scan complete"
    assert "5 findings" in (n.body or "")
    assert "/proj" in (n.body or "")
    assert n.link == "/scan/scan-1"
    # Per the simplified rule: any findings -> warning.
    assert n.severity == NotificationSeverity.WARNING


def test_scan_complete_zero_findings_no_notification(temp_db):
    async def _go():
        await _create_notification_for_event(
            "scan.complete",
            "scan-2",
            {"findings_count": 0, "target": "/proj"},
        )
        return await list_notifications()

    rows = _run(_go())
    assert rows == [], "a clean scan should not buzz the bell"


def test_scan_failed_always_notifies(temp_db):
    async def _go():
        await _create_notification_for_event(
            "scan.failed",
            "scan-3",
            {"error": "boom: something went wrong"},
        )
        return await list_notifications()

    rows = _run(_go())
    assert len(rows) == 1
    n = rows[0]
    assert n.type == "scan.failed"
    assert n.severity == NotificationSeverity.ERROR
    assert n.link == "/scan/scan-3"
    assert "boom" in (n.body or "")


def test_scan_failed_truncates_long_error(temp_db):
    """Long stack traces get capped to 200 chars in the body."""
    long_err = "x" * 500

    async def _go():
        await _create_notification_for_event("scan.failed", "scan-3b", {"error": long_err})
        return await list_notifications()

    rows = _run(_go())
    assert rows[0].body is not None
    assert len(rows[0].body) <= 200


def test_scanner_failed_always_notifies(temp_db):
    async def _go():
        await _create_notification_for_event(
            "scanner.failed",
            "scan-4",
            {"scanner": "bandit", "error": "pip exploded"},
        )
        return await list_notifications()

    rows = _run(_go())
    assert len(rows) == 1
    n = rows[0]
    assert n.type == "scanner.failed"
    assert n.severity == NotificationSeverity.WARNING
    assert "bandit" in (n.body or "")


def test_scanner_start_does_not_notify(temp_db):
    async def _go():
        await _create_notification_for_event(
            "scanner.start",
            "scan-5",
            {"scanner": "bandit"},
        )
        # And a few other no-op events for good measure.
        await _create_notification_for_event("scan.start", "scan-5", {"target": "/x"})
        await _create_notification_for_event(
            "scanner.complete",
            "scan-5",
            {"scanner": "bandit", "findings_count": 0},
        )
        return await list_notifications()

    rows = _run(_go())
    assert rows == [], "lifecycle/progress events must not buzz the bell"


# ---------------------------------------------------------------------------
# Pruning
# ---------------------------------------------------------------------------


def test_prune_old_read_notifications(temp_db):
    """Only read rows past the cutoff are deleted; unread rows are
    preserved regardless of age."""
    now = datetime.utcnow()

    async def _go():
        old_read = await insert_notification(type="t", title="old-read")
        recent_read = await insert_notification(type="t", title="recent-read")
        old_unread = await insert_notification(type="t", title="old-unread")
        # Backdate timestamps to bracket the 30-day cutoff.
        await _backdate_notification(
            temp_db,
            old_read.id,
            created_at=now - timedelta(days=45),
            read_at=now - timedelta(days=31),
        )
        await _backdate_notification(
            temp_db,
            recent_read.id,
            created_at=now - timedelta(days=10),
            read_at=now - timedelta(days=5),
        )
        await _backdate_notification(
            temp_db,
            old_unread.id,
            created_at=now - timedelta(days=45),
            read_at=None,
        )
        deleted = await prune_old_notifications(older_than_days=30)
        remaining = await list_notifications()
        return deleted, remaining, old_read.id, recent_read.id, old_unread.id

    deleted, remaining, old_read_id, recent_read_id, old_unread_id = _run(_go())
    assert deleted == 1
    remaining_ids = {n.id for n in remaining}
    assert old_read_id not in remaining_ids
    assert recent_read_id in remaining_ids
    assert old_unread_id in remaining_ids, "unread rows are NEVER pruned"


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------


def test_get_notifications_endpoint(temp_db, client):
    async def _seed():
        await insert_notification(type="t", title="alpha")
        await asyncio.sleep(0.01)
        await insert_notification(type="t", title="beta")

    _run(_seed())
    res = client.get("/api/v1/notifications")
    assert res.status_code == 200
    body = res.json()
    assert [n["title"] for n in body] == ["beta", "alpha"]


def test_get_notifications_unread_only(temp_db, client):
    async def _seed():
        a = await insert_notification(type="t", title="alpha")
        await insert_notification(type="t", title="beta")
        await mark_notification_read(a.id)

    _run(_seed())
    res = client.get("/api/v1/notifications", params={"unread_only": True})
    assert res.status_code == 200
    titles = [n["title"] for n in res.json()]
    assert titles == ["beta"]


def test_unread_count_endpoint(temp_db, client):
    async def _seed():
        for i in range(3):
            await insert_notification(type="t", title=f"n{i}")
        rows = await list_notifications()
        await mark_notification_read(rows[0].id)

    _run(_seed())
    res = client.get("/api/v1/notifications/unread-count")
    assert res.status_code == 200
    assert res.json() == {"count": 2}


def test_mark_read_endpoint_404_unknown_id(client, temp_db):
    res = client.patch("/api/v1/notifications/no-such-id/read")
    assert res.status_code == 404


def test_mark_read_endpoint_round_trip(client, temp_db):
    async def _seed():
        n = await insert_notification(type="t", title="alpha")
        return n.id

    nid = _run(_seed())
    res = client.patch(f"/api/v1/notifications/{nid}/read")
    assert res.status_code == 200
    body = res.json()
    assert body["id"] == nid
    assert body["read_at"] is not None

    # Idempotent: a second PATCH still 200s with the same row.
    res2 = client.patch(f"/api/v1/notifications/{nid}/read")
    assert res2.status_code == 200
    assert res2.json()["read_at"] == body["read_at"]


def test_mark_all_read_endpoint(client, temp_db):
    async def _seed():
        for i in range(3):
            await insert_notification(type="t", title=f"n{i}")

    _run(_seed())
    res = client.patch("/api/v1/notifications/read-all")
    assert res.status_code == 200
    assert res.json() == {"marked_read": 3}

    # Second call -> 0.
    res2 = client.patch("/api/v1/notifications/read-all")
    assert res2.json() == {"marked_read": 0}


def test_legacy_alias_reaches_handler(client, temp_db):
    """The legacy /api/notifications mount must hit the same handler
    as /api/v1/notifications, with the deprecation header attached."""
    res = client.get("/api/notifications/unread-count")
    assert res.status_code == 200
    assert res.json() == {"count": 0}
    assert res.headers.get("Deprecation") == "true"
