"""Tests for scheduled scans (FEAT-SCHEDULES).

Three layers:
* CRUD endpoints (create, list, get, patch, delete, runs).
* Scheduler: a schedule firing creates a scan run (apscheduler mocked).
* Redis lock: two concurrent fires produce exactly one scan (skipped without Redis).
"""

from __future__ import annotations

import asyncio
import os
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from securescan.database import (
    get_schedule,
    init_db,
    insert_schedule,
    insert_schedule_run,
    list_schedule_runs,
    list_schedules,
    set_db_path,
)
from securescan.main import app

REDIS_URL = os.environ.get("SECURESCAN_REDIS_URL")

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    from securescan.config import settings as _settings

    db_path = str(tmp_path / "schedules_test.db")
    original = _settings.database_path
    set_db_path(db_path)
    asyncio.run(init_db())
    monkeypatch.delenv("SECURESCAN_API_KEY", raising=False)
    monkeypatch.delenv("SECURESCAN_AUTH_REQUIRED", raising=False)
    yield db_path
    set_db_path(original)


@pytest.fixture
def client(temp_db) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


async def _seed_schedule(
    *,
    name: str = "nightly",
    target_path: str = "/tmp/repo",
    scan_types: list[str] | None = None,
    cron_expression: str = "0 2 * * *",
    enabled: bool = True,
) -> str:
    sched_id = str(uuid.uuid4())
    await insert_schedule(
        id=sched_id,
        name=name,
        target_path=target_path,
        scan_types=scan_types or ["code", "dependency"],
        cron_expression=cron_expression,
        enabled=enabled,
        created_at=datetime.utcnow(),
    )
    return sched_id


# ---------------------------------------------------------------------------
# DB layer: basic CRUD
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_insert_and_get_schedule(temp_db):
    sched_id = await _seed_schedule(name="test-sched")
    sched = await get_schedule(sched_id)
    assert sched is not None
    assert sched.name == "test-sched"
    assert sched.enabled is True
    assert sched.cron_expression == "0 2 * * *"


@pytest.mark.asyncio
async def test_list_schedules(temp_db):
    await _seed_schedule(name="a")
    await _seed_schedule(name="b")
    scheds = await list_schedules()
    assert len(scheds) == 2


@pytest.mark.asyncio
async def test_list_schedule_runs(temp_db):
    sched_id = await _seed_schedule()
    run_id = str(uuid.uuid4())
    scan_id = str(uuid.uuid4())
    await insert_schedule_run(
        id=run_id,
        schedule_id=sched_id,
        scan_id=scan_id,
        triggered_at=datetime.utcnow(),
    )
    runs = await list_schedule_runs(sched_id)
    assert len(runs) == 1
    assert runs[0].scan_id == scan_id


# ---------------------------------------------------------------------------
# API: POST (create)
# ---------------------------------------------------------------------------


def test_create_schedule_201(client):
    with patch("securescan.api.schedules._scheduler") as mock_svc:
        resp = client.post(
            "/api/v1/schedules",
            json={
                "name": "Daily",
                "target_path": "/tmp/proj",
                "scan_types": ["code"],
                "cron_expression": "0 3 * * *",
            },
        )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "Daily"
    assert data["enabled"] is True
    assert data["cron_expression"] == "0 3 * * *"
    mock_svc.add.assert_called_once()


def test_create_schedule_invalid_cron_422(client):
    resp = client.post(
        "/api/v1/schedules",
        json={
            "name": "Bad",
            "target_path": "/tmp",
            "cron_expression": "not-a-cron",
        },
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# API: GET list
# ---------------------------------------------------------------------------


def test_list_schedules_empty(client):
    resp = client.get("/api/v1/schedules")
    assert resp.status_code == 200
    assert resp.json() == []


def test_list_schedules_returns_rows(client):
    with patch("securescan.api.schedules._scheduler"):
        client.post(
            "/api/v1/schedules",
            json={"name": "S1", "target_path": "/tmp", "cron_expression": "0 1 * * *"},
        )
        client.post(
            "/api/v1/schedules",
            json={"name": "S2", "target_path": "/tmp", "cron_expression": "0 2 * * *"},
        )
    resp = client.get("/api/v1/schedules")
    assert resp.status_code == 200
    assert len(resp.json()) == 2


# ---------------------------------------------------------------------------
# API: GET one
# ---------------------------------------------------------------------------


def test_get_schedule_404(client):
    resp = client.get(f"/api/v1/schedules/{uuid.uuid4()}")
    assert resp.status_code == 404


def test_get_schedule_found(client):
    with patch("securescan.api.schedules._scheduler"):
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "X", "target_path": "/tmp", "cron_expression": "5 * * * *"},
        )
    sched_id = create_resp.json()["id"]
    resp = client.get(f"/api/v1/schedules/{sched_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == sched_id


# ---------------------------------------------------------------------------
# API: PATCH
# ---------------------------------------------------------------------------


def test_patch_schedule_name(client):
    with patch("securescan.api.schedules._scheduler"):
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "Old", "target_path": "/tmp", "cron_expression": "0 0 * * *"},
        )
        sched_id = create_resp.json()["id"]
        resp = client.patch(f"/api/v1/schedules/{sched_id}", json={"name": "New"})
    assert resp.status_code == 200
    assert resp.json()["name"] == "New"


def test_patch_schedule_disable(client):
    with patch("securescan.api.schedules._scheduler"):
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "Disable me", "target_path": "/tmp", "cron_expression": "0 0 * * *"},
        )
        sched_id = create_resp.json()["id"]
        resp = client.patch(f"/api/v1/schedules/{sched_id}", json={"enabled": False})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_patch_schedule_404(client):
    with patch("securescan.api.schedules._scheduler"):
        resp = client.patch(f"/api/v1/schedules/{uuid.uuid4()}", json={"name": "X"})
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API: DELETE
# ---------------------------------------------------------------------------


def test_delete_schedule_204(client):
    with patch("securescan.api.schedules._scheduler"):
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "Del", "target_path": "/tmp", "cron_expression": "0 0 * * *"},
        )
        sched_id = create_resp.json()["id"]
        resp = client.delete(f"/api/v1/schedules/{sched_id}")
    assert resp.status_code == 204
    assert client.get(f"/api/v1/schedules/{sched_id}").status_code == 404


def test_delete_schedule_404(client):
    with patch("securescan.api.schedules._scheduler"):
        resp = client.delete(f"/api/v1/schedules/{uuid.uuid4()}")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# API: GET runs
# ---------------------------------------------------------------------------


def test_get_runs_empty(client):
    with patch("securescan.api.schedules._scheduler"):
        create_resp = client.post(
            "/api/v1/schedules",
            json={"name": "R", "target_path": "/tmp", "cron_expression": "0 0 * * *"},
        )
    sched_id = create_resp.json()["id"]
    resp = client.get(f"/api/v1/schedules/{sched_id}/runs")
    assert resp.status_code == 200
    assert resp.json() == []


def test_get_runs_404_for_missing_schedule(client):
    resp = client.get(f"/api/v1/schedules/{uuid.uuid4()}/runs")
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Scheduler: firing creates a scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_schedule_creates_scan(temp_db):
    """_fire_schedule() creates a Scan and a ScheduleRun row."""
    from securescan.scheduler import _fire_schedule

    sched_id = await _seed_schedule()

    with (
        patch("securescan.scheduler._acquire_lock", new=AsyncMock(return_value=True)),
        patch("securescan.scheduler.asyncio.create_task") as mock_task,
    ):
        await _fire_schedule(sched_id)

    # scan task was scheduled
    mock_task.assert_called_once()

    # schedule_run row was created
    runs = await list_schedule_runs(sched_id)
    assert len(runs) == 1
    assert runs[0].scan_id is not None

    # last_run was updated
    sched = await get_schedule(sched_id)
    assert sched is not None
    assert sched.last_run is not None


@pytest.mark.asyncio
async def test_fire_schedule_lock_blocks_double_fire(temp_db):
    """When the lock is NOT acquired, no scan run row is created."""
    from securescan.scheduler import _fire_schedule

    sched_id = await _seed_schedule()

    with patch("securescan.scheduler._acquire_lock", new=AsyncMock(return_value=False)):
        await _fire_schedule(sched_id)

    runs = await list_schedule_runs(sched_id)
    assert len(runs) == 0


# ---------------------------------------------------------------------------
# Redis lock: cross-instance double-fire prevention (requires Redis)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not REDIS_URL, reason="SECURESCAN_REDIS_URL not set")
@pytest.mark.asyncio
async def test_redis_lock_prevents_double_fire(temp_db):
    """Two concurrent _fire_schedule() calls with Redis produce exactly one run."""
    import redis.asyncio as aioredis

    from securescan.scheduler import _fire_schedule

    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    try:
        await redis.ping()
    except Exception as e:
        pytest.skip(f"Redis unreachable: {e}")
    finally:
        await redis.close()

    import securescan.pubsub as pubsub_mod
    from securescan.pubsub import RedisBackend

    real_backend = pubsub_mod._backend
    try:
        pubsub_mod._backend = RedisBackend(REDIS_URL, prefix="ss-sched-test:")
        sched_id = await _seed_schedule()

        created_tasks = []

        def _fake_create_task(coro):
            # Don't actually run the scan -- just record the call.
            coro.close()
            created_tasks.append(True)

        with patch("securescan.scheduler.asyncio.create_task", side_effect=_fake_create_task):
            # Fire twice concurrently -- only one should win the lock.
            await asyncio.gather(
                _fire_schedule(sched_id),
                _fire_schedule(sched_id),
            )

        runs = await list_schedule_runs(sched_id)
        assert len(runs) == 1, f"Expected 1 run, got {len(runs)}"

        # Clean up lock key so it doesn't bleed into other tests.
        r2 = aioredis.from_url(REDIS_URL, decode_responses=True)
        await r2.delete(f"ss-sched-test:sched:lock:{sched_id}")
        await r2.close()
    finally:
        pubsub_mod._backend = real_backend
