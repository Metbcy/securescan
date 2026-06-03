"""Tests for per-event notification thresholds (issue #6).

Covers:
- DB defaults: with no row in `notification_settings`, helpers return
  the application defaults.
- DB upsert: writes persist and override defaults on the next read.
- API: GET returns defaults on a fresh DB; PATCH updates and the
  follow-up GET reflects the new value.
- Dispatcher integration: with the threshold set high a medium
  finding does NOT create a notification, and a critical one does.
- Backward compatibility: with no settings rows configured the
  dispatcher's behavior matches the pre-issue-6 hard-coded rules
  (scan.complete with findings -> notify; clean scan -> no notify;
  scan.failed / scanner.failed -> always notify).
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from securescan.api.scans import _create_notification_for_event
from securescan.database import (
    NOTIFICATION_THRESHOLD_DEFAULTS,
    get_notification_settings,
    get_notification_threshold,
    init_db,
    list_notifications,
    set_db_path,
    upsert_notification_threshold,
)
from securescan.main import app
from securescan.models import (
    NotificationEventType,
    Severity,
)


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Fresh DB per test; reset global path on teardown."""
    from securescan.config import settings as _settings

    db_path = str(tmp_path / "notif_settings.db")
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


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------


def test_defaults_returned_when_table_empty(temp_db):
    rows = _run(get_notification_settings())
    by_event = {r.event_type.value: r for r in rows}
    # Every known event type appears in the response.
    assert set(by_event) == {e.value for e in NotificationEventType}
    # Defaults match the documented rule set.
    assert by_event["scan.complete"].min_severity == Severity.MEDIUM
    assert by_event["scan.failed"].min_severity == Severity.INFO
    assert by_event["scanner.failed"].min_severity == Severity.INFO
    # No row in the table yet -> updated_at is None on every entry.
    assert all(r.updated_at is None for r in rows)


def test_get_notification_threshold_uses_default(temp_db):
    sev = _run(get_notification_threshold("scan.complete"))
    assert sev == NOTIFICATION_THRESHOLD_DEFAULTS["scan.complete"]


def test_upsert_persists_and_overrides_default(temp_db):
    async def _go():
        await upsert_notification_threshold("scan.complete", Severity.HIGH)
        return await get_notification_threshold("scan.complete")

    assert _run(_go()) == Severity.HIGH


def test_upsert_idempotent_on_same_key(temp_db):
    async def _go():
        await upsert_notification_threshold("scan.complete", Severity.HIGH)
        await upsert_notification_threshold("scan.complete", Severity.LOW)
        rows = await get_notification_settings()
        return [(r.event_type.value, r.min_severity) for r in rows]

    rows = _run(_go())
    by_event = dict(rows)
    assert by_event["scan.complete"] == Severity.LOW
    # Untouched events keep their defaults.
    assert by_event["scan.failed"] == Severity.INFO


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------


def test_get_settings_returns_defaults(client):
    res = client.get("/api/v1/settings/notifications")
    assert res.status_code == 200
    data = res.json()
    by_event = {row["event_type"]: row for row in data["thresholds"]}
    assert by_event["scan.complete"]["min_severity"] == "medium"
    assert by_event["scan.failed"]["min_severity"] == "info"
    assert by_event["scanner.failed"]["min_severity"] == "info"


def test_patch_updates_and_persists(client):
    res = client.patch(
        "/api/v1/settings/notifications",
        json={
            "thresholds": [
                {"event_type": "scan.complete", "min_severity": "critical"},
            ]
        },
    )
    assert res.status_code == 200
    data = res.json()
    by_event = {row["event_type"]: row for row in data["thresholds"]}
    assert by_event["scan.complete"]["min_severity"] == "critical"
    # Other events remain at defaults.
    assert by_event["scan.failed"]["min_severity"] == "info"

    # Persisted: a follow-up GET sees the new value.
    res2 = client.get("/api/v1/settings/notifications")
    by_event2 = {row["event_type"]: row for row in res2.json()["thresholds"]}
    assert by_event2["scan.complete"]["min_severity"] == "critical"


def test_patch_rejects_unknown_event(client):
    res = client.patch(
        "/api/v1/settings/notifications",
        json={
            "thresholds": [
                {"event_type": "scan.bogus", "min_severity": "low"},
            ]
        },
    )
    assert res.status_code == 422


def test_patch_rejects_unknown_severity(client):
    res = client.patch(
        "/api/v1/settings/notifications",
        json={
            "thresholds": [
                {"event_type": "scan.complete", "min_severity": "blocker"},
            ]
        },
    )
    assert res.status_code == 422


def test_patch_empty_body_is_noop(client):
    res = client.patch(
        "/api/v1/settings/notifications",
        json={"thresholds": []},
    )
    assert res.status_code == 200
    by_event = {r["event_type"]: r for r in res.json()["thresholds"]}
    assert by_event["scan.complete"]["min_severity"] == "medium"


# ---------------------------------------------------------------------------
# Dispatcher integration
# ---------------------------------------------------------------------------


def test_dispatcher_suppresses_below_threshold(temp_db):
    """Threshold=high; a medium finding event must not create a notification."""

    async def _go():
        await upsert_notification_threshold("scan.complete", Severity.HIGH)
        await _create_notification_for_event(
            "scan.complete",
            "scan-low",
            {
                "findings_count": 3,
                "max_severity": "medium",
                "target": "/proj",
            },
        )
        return await list_notifications()

    assert _run(_go()) == []


def test_dispatcher_fires_at_or_above_threshold(temp_db):
    """Threshold=high; a critical event creates a notification."""

    async def _go():
        await upsert_notification_threshold("scan.complete", Severity.HIGH)
        await _create_notification_for_event(
            "scan.complete",
            "scan-crit",
            {
                "findings_count": 1,
                "max_severity": "critical",
                "target": "/proj",
            },
        )
        return await list_notifications()

    rows = _run(_go())
    assert len(rows) == 1
    assert rows[0].type == "scan.complete"


def test_dispatcher_clean_scan_never_notifies(temp_db):
    """Even with threshold=info, a clean scan must not buzz the bell."""

    async def _go():
        await upsert_notification_threshold("scan.complete", Severity.INFO)
        await _create_notification_for_event(
            "scan.complete",
            "scan-clean",
            {"findings_count": 0, "max_severity": None, "target": "/proj"},
        )
        return await list_notifications()

    assert _run(_go()) == []


# ---------------------------------------------------------------------------
# Backward compatibility (no rows in notification_settings)
# ---------------------------------------------------------------------------


def test_backcompat_scan_complete_with_findings_fires_with_no_settings(temp_db):
    """No settings row + findings_count>0 -> notification fires (default medium).

    Legacy publish sites that don't pass `max_severity` get the
    "assume worst case" treatment so behavior matches pre-issue-6.
    """

    async def _go():
        await _create_notification_for_event(
            "scan.complete",
            "scan-1",
            {"findings_count": 5, "target": "/proj"},
        )
        return await list_notifications()

    rows = _run(_go())
    assert len(rows) == 1
    assert rows[0].type == "scan.complete"


def test_backcompat_scan_failed_always_fires_with_no_settings(temp_db):
    async def _go():
        await _create_notification_for_event(
            "scan.failed",
            "scan-2",
            {"error": "boom"},
        )
        return await list_notifications()

    rows = _run(_go())
    assert len(rows) == 1
    assert rows[0].type == "scan.failed"


def test_backcompat_scanner_failed_always_fires_with_no_settings(temp_db):
    async def _go():
        await _create_notification_for_event(
            "scanner.failed",
            "scan-3",
            {"scanner": "bandit", "error": "boom"},
        )
        return await list_notifications()

    rows = _run(_go())
    assert len(rows) == 1
    assert rows[0].type == "scanner.failed"
