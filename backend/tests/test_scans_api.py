"""Tests for DELETE /api/v1/scans/{scan_id} (BE-DEL).

Pinned contract:
- 204 No Content on a successful delete; the scan and every finding row
  carrying that scan_id are removed in one transaction (no orphans).
- 404 when the id does not exist (and on the second DELETE of the same
  id -- gone is gone).
- 409 when the scan is still live (`pending` or `running`); caller must
  POST /cancel first. Matches the 409 precedent set by cancel_scan.
- The legacy `/api/scans/{id}` and `/api/v1/scans/{id}` paths must both
  reach the handler (single source of truth via alias_router_at_v1).
"""
from __future__ import annotations

import asyncio

import aiosqlite
import pytest
from fastapi.testclient import TestClient

from securescan.database import (
    delete_scan_cascade,
    get_scan,
    init_db,
    save_findings,
    save_scan,
    set_db_path,
)
from securescan.main import app
from securescan.models import (
    Finding,
    Scan,
    ScanStatus,
    ScanType,
    Severity,
)


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Point the DB at a tmp file and clear API auth so the dev-mode
    /api/* paths are reachable without an X-API-Key header."""
    db_path = str(tmp_path / "delete_scan.db")
    set_db_path(db_path)
    asyncio.run(init_db())
    monkeypatch.delenv("SECURESCAN_API_KEY", raising=False)
    return db_path


@pytest.fixture
def client(temp_db) -> TestClient:
    with TestClient(app) as c:
        yield c


def _make_finding(scan_id: str, *, suffix: str) -> Finding:
    return Finding(
        scan_id=scan_id,
        scanner="bandit",
        scan_type=ScanType.CODE,
        severity=Severity.MEDIUM,
        title=f"Issue {suffix}",
        description=f"Synthetic finding {suffix}",
        file_path=f"/tmp/proj/{suffix}.py",
        line_start=1,
        line_end=2,
        rule_id=f"R-{suffix}",
        cwe="CWE-79",
    )


def _seed_scan(status: ScanStatus, *, findings: int = 0) -> tuple[str, list[str]]:
    """Persist a scan in the requested status with N findings.
    Returns (scan_id, [finding_ids])."""
    scan = Scan(
        target_path="/tmp/proj",
        scan_types=[ScanType.CODE],
        status=status,
    )

    async def _setup() -> tuple[str, list[str]]:
        await save_scan(scan)
        finding_models = [_make_finding(scan.id, suffix=str(i)) for i in range(findings)]
        if finding_models:
            await save_findings(finding_models)
        return scan.id, [f.id for f in finding_models]

    return asyncio.run(_setup())


async def _count_findings(db_path: str, scan_id: str) -> int:
    async with aiosqlite.connect(db_path) as db:
        cursor = await db.execute(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_id,)
        )
        row = await cursor.fetchone()
        return row[0]


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_delete_scan_completed(client: TestClient, temp_db):
    scan_id, finding_ids = _seed_scan(ScanStatus.COMPLETED, findings=3)
    assert len(finding_ids) == 3
    assert asyncio.run(_count_findings(temp_db, scan_id)) == 3

    res = client.delete(f"/api/v1/scans/{scan_id}")
    assert res.status_code == 204
    assert res.content == b""

    follow = client.get(f"/api/v1/scans/{scan_id}")
    assert follow.status_code == 404

    assert asyncio.run(get_scan(scan_id)) is None
    assert asyncio.run(_count_findings(temp_db, scan_id)) == 0


def test_delete_scan_with_no_findings_succeeds(client: TestClient):
    scan_id, _ = _seed_scan(ScanStatus.COMPLETED, findings=0)
    res = client.delete(f"/api/v1/scans/{scan_id}")
    assert res.status_code == 204
    assert asyncio.run(get_scan(scan_id)) is None


def test_delete_scan_failed_status_succeeds(client: TestClient):
    """Failed and cancelled are terminal states -- both must be deletable."""
    failed_id, _ = _seed_scan(ScanStatus.FAILED, findings=1)
    cancelled_id, _ = _seed_scan(ScanStatus.CANCELLED, findings=1)

    assert client.delete(f"/api/v1/scans/{failed_id}").status_code == 204
    assert client.delete(f"/api/v1/scans/{cancelled_id}").status_code == 204
    assert asyncio.run(get_scan(failed_id)) is None
    assert asyncio.run(get_scan(cancelled_id)) is None


# ---------------------------------------------------------------------------
# 404
# ---------------------------------------------------------------------------


def test_delete_scan_not_found(client: TestClient):
    res = client.delete("/api/v1/scans/00000000-0000-0000-0000-000000000000")
    assert res.status_code == 404
    body = res.json()
    assert body["detail"] == "Scan not found"


def test_delete_scan_idempotent_second_call_is_404(client: TestClient):
    scan_id, _ = _seed_scan(ScanStatus.COMPLETED, findings=1)
    first = client.delete(f"/api/v1/scans/{scan_id}")
    assert first.status_code == 204
    second = client.delete(f"/api/v1/scans/{scan_id}")
    assert second.status_code == 404


# ---------------------------------------------------------------------------
# 409 -- live scans must be cancelled first
# ---------------------------------------------------------------------------


def test_delete_scan_running_refused(client: TestClient, temp_db):
    scan_id, _ = _seed_scan(ScanStatus.RUNNING, findings=2)
    res = client.delete(f"/api/v1/scans/{scan_id}")
    assert res.status_code == 409
    assert "running" in res.json()["detail"].lower()

    # Scan and findings still in DB.
    still_there = asyncio.run(get_scan(scan_id))
    assert still_there is not None
    assert still_there.status == ScanStatus.RUNNING
    assert asyncio.run(_count_findings(temp_db, scan_id)) == 2


def test_delete_scan_pending_refused(client: TestClient, temp_db):
    scan_id, _ = _seed_scan(ScanStatus.PENDING, findings=0)
    res = client.delete(f"/api/v1/scans/{scan_id}")
    assert res.status_code == 409
    assert "pending" in res.json()["detail"].lower()
    assert asyncio.run(get_scan(scan_id)) is not None


# ---------------------------------------------------------------------------
# Versioning -- both legacy and v1 paths reach the handler
# ---------------------------------------------------------------------------


def test_delete_scan_legacy_path_also_works(client: TestClient):
    scan_id, _ = _seed_scan(ScanStatus.COMPLETED, findings=1)
    res = client.delete(f"/api/scans/{scan_id}")
    assert res.status_code == 204
    assert asyncio.run(get_scan(scan_id)) is None


def test_delete_scan_does_not_touch_other_scans(client: TestClient, temp_db):
    keep_id, _ = _seed_scan(ScanStatus.COMPLETED, findings=2)
    drop_id, _ = _seed_scan(ScanStatus.COMPLETED, findings=2)

    res = client.delete(f"/api/v1/scans/{drop_id}")
    assert res.status_code == 204

    assert asyncio.run(get_scan(keep_id)) is not None
    assert asyncio.run(_count_findings(temp_db, keep_id)) == 2
    assert asyncio.run(get_scan(drop_id)) is None
    assert asyncio.run(_count_findings(temp_db, drop_id)) == 0


# ---------------------------------------------------------------------------
# DB-layer cascade helper -- exercised directly so the contract is pinned
# even if the API wiring changes.
# ---------------------------------------------------------------------------


def test_delete_scan_cascade_returns_false_for_unknown_id(temp_db):
    assert asyncio.run(delete_scan_cascade("does-not-exist")) is False


def test_delete_scan_cascade_returns_true_and_clears_rows(temp_db):
    scan_id, _ = _seed_scan(ScanStatus.COMPLETED, findings=4)
    assert asyncio.run(_count_findings(temp_db, scan_id)) == 4
    assert asyncio.run(delete_scan_cascade(scan_id)) is True
    assert asyncio.run(get_scan(scan_id)) is None
    assert asyncio.run(_count_findings(temp_db, scan_id)) == 0
