"""Tests for the triage state + comments backend (BE-TRIAGE).

Covers:
- PATCH /findings/{fp}/state — create + update + invalid status
- GET /scans/{id}/findings — joins state on enriched response, leaves
  bare-Finding exporters untouched
- State persistence across scan deletion + sharing across scans of the
  same fingerprint (the whole reason the table is keyed on fingerprint
  rather than finding.id)
- Comments — POST/GET/DELETE, ordering, isolation, idempotency-of-404
- Legacy /api/findings/... alias still reaches the same handler
"""
from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from securescan.database import (
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


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    db_path = str(tmp_path / "triage.db")
    set_db_path(db_path)
    asyncio.run(init_db())
    monkeypatch.delenv("SECURESCAN_API_KEY", raising=False)
    return db_path


@pytest.fixture
def client(temp_db) -> TestClient:
    with TestClient(app) as c:
        yield c


def _make_finding(scan_id: str, *, suffix: str, fingerprint: str = "") -> Finding:
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
        fingerprint=fingerprint or f"fp-{suffix}",
    )


def _seed_scan(*, status: ScanStatus = ScanStatus.COMPLETED, findings: list[Finding] | None = None) -> str:
    scan = Scan(target_path="/tmp/proj", scan_types=[ScanType.CODE], status=status)

    async def _inner() -> str:
        await save_scan(scan)
        if findings:
            for f in findings:
                f.scan_id = scan.id
            await save_findings(findings)
        return scan.id

    return asyncio.run(_inner())


# ---------------------------------------------------------------------------
# PATCH /findings/{fp}/state
# ---------------------------------------------------------------------------


def test_patch_state_creates(client: TestClient):
    fp = "fp-creates"
    res = client.patch(
        f"/api/v1/findings/{fp}/state",
        json={"status": "false_positive", "note": "test framework code", "updated_by": "amir"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["fingerprint"] == fp
    assert body["status"] == "false_positive"
    assert body["note"] == "test framework code"
    assert body["updated_by"] == "amir"
    # updated_at is server-assigned; just assert presence + ISO-parseable.
    assert body["updated_at"]
    from datetime import datetime
    datetime.fromisoformat(body["updated_at"])


def test_patch_state_updates(client: TestClient):
    fp = "fp-updates"
    first = client.patch(
        f"/api/v1/findings/{fp}/state",
        json={"status": "triaged", "note": "looking into it"},
    )
    assert first.status_code == 200
    first_ts = first.json()["updated_at"]

    # Sleep a hair so updated_at moves; iso strings compare lexicographically.
    time.sleep(0.01)
    second = client.patch(
        f"/api/v1/findings/{fp}/state",
        json={"status": "accepted_risk", "note": "approved by sec lead"},
    )
    assert second.status_code == 200
    body = second.json()
    assert body["status"] == "accepted_risk"
    assert body["note"] == "approved by sec lead"
    assert body["updated_at"] >= first_ts

    # GET via the join endpoint will return only the latest state -- no
    # history kept by design (use comments for that).
    state_via_get = client.get(f"/api/v1/findings/{fp}/comments")
    assert state_via_get.status_code == 200  # smoke check: route is up


def test_patch_state_status_validation(client: TestClient):
    res = client.patch(
        "/api/v1/findings/fp-bad/state",
        json={"status": "definitely-not-a-status"},
    )
    assert res.status_code == 422


def test_patch_state_note_defaults_to_null_when_omitted(client: TestClient):
    fp = "fp-no-note"
    res = client.patch(
        f"/api/v1/findings/{fp}/state",
        json={"status": "fixed"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "fixed"
    assert body["note"] is None
    assert body["updated_by"] is None


# ---------------------------------------------------------------------------
# GET /scans/{id}/findings -- enriched with state
# ---------------------------------------------------------------------------


def test_get_findings_with_state_joins(client: TestClient):
    f1 = _make_finding("placeholder", suffix="a", fingerprint="fp-A")
    f2 = _make_finding("placeholder", suffix="b", fingerprint="fp-B")
    scan_id = _seed_scan(findings=[f1, f2])

    # Triage only the first finding.
    res = client.patch(
        "/api/v1/findings/fp-A/state",
        json={"status": "false_positive", "note": "n/a"},
    )
    assert res.status_code == 200

    res = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 2

    by_fp = {f["fingerprint"]: f for f in body}
    assert by_fp["fp-A"]["state"] is not None
    assert by_fp["fp-A"]["state"]["status"] == "false_positive"
    assert by_fp["fp-A"]["state"]["note"] == "n/a"
    assert by_fp["fp-B"]["state"] is None


def test_get_findings_with_state_preserves_finding_fields(client: TestClient):
    """The enriched response must still carry every Finding field --
    inheriting FindingWithState from Finding rather than wrapping it."""
    f = _make_finding("placeholder", suffix="full", fingerprint="fp-full")
    scan_id = _seed_scan(findings=[f])

    res = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 1
    item = body[0]
    # Every Finding-side field is present.
    for key in (
        "id", "scan_id", "scanner", "scan_type", "severity", "title",
        "description", "file_path", "line_start", "line_end", "rule_id",
        "cwe", "remediation", "metadata", "compliance_tags", "fingerprint",
    ):
        assert key in item, f"missing field: {key}"
    assert item["state"] is None


def test_state_survives_scan_delete(client: TestClient):
    """Deleting a scan must NOT cascade into finding_states."""
    f = _make_finding("placeholder", suffix="surv", fingerprint="fp-survives")
    scan_id = _seed_scan(findings=[f])

    res = client.patch(
        "/api/v1/findings/fp-survives/state",
        json={"status": "false_positive"},
    )
    assert res.status_code == 200

    # v0.6.1 delete endpoint -- 204 on terminal scans.
    delete_res = client.delete(f"/api/v1/scans/{scan_id}")
    assert delete_res.status_code == 204

    # State row is still present in the DB. We assert via direct SQL so
    # the test is not coupled to any HTTP "get state" route (there isn't
    # one -- state is only ever read via the scan-findings join).
    import aiosqlite
    from securescan.config import settings as _settings  # noqa: F401
    from securescan import database as _db_module

    async def _state_count() -> int:
        async with aiosqlite.connect(_db_module._db_path) as db:
            cursor = await db.execute(
                "SELECT COUNT(*) FROM finding_states WHERE fingerprint = ?",
                ("fp-survives",),
            )
            row = await cursor.fetchone()
            return row[0]

    assert asyncio.run(_state_count()) == 1


def test_state_shared_across_scans(client: TestClient):
    """Two scans of the same target produce findings with the same
    fingerprint; a verdict on scan A must surface on scan B too."""
    fp = "fp-shared"
    f_a = _make_finding("placeholder", suffix="A", fingerprint=fp)
    scan_a = _seed_scan(findings=[f_a])

    res = client.patch(
        f"/api/v1/findings/{fp}/state",
        json={"status": "wont_fix", "note": "legacy code, scheduled for rewrite"},
    )
    assert res.status_code == 200

    # A second scan of the same target produces a finding with the same
    # fingerprint. Different scan_id, different finding.id, same fingerprint.
    f_b = _make_finding("placeholder", suffix="B", fingerprint=fp)
    scan_b = _seed_scan(findings=[f_b])

    res = client.get(f"/api/v1/scans/{scan_b}/findings")
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 1
    assert body[0]["fingerprint"] == fp
    assert body[0]["state"] is not None
    assert body[0]["state"]["status"] == "wont_fix"
    assert body[0]["state"]["note"] == "legacy code, scheduled for rewrite"

    # Scan A's response is consistent too.
    res_a = client.get(f"/api/v1/scans/{scan_a}/findings")
    assert res_a.status_code == 200
    assert res_a.json()[0]["state"]["status"] == "wont_fix"


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------


def test_add_comment(client: TestClient):
    fp = "fp-add"
    res = client.post(
        f"/api/v1/findings/{fp}/comments",
        json={"text": "looks suspicious", "author": "amir"},
    )
    assert res.status_code == 201
    body = res.json()
    assert body["fingerprint"] == fp
    assert body["text"] == "looks suspicious"
    assert body["author"] == "amir"
    assert body["id"]  # uuid assigned server-side
    from datetime import datetime
    datetime.fromisoformat(body["created_at"])  # server-assigned + parseable


def test_list_comments_ordered(client: TestClient):
    fp = "fp-ordered"
    # Three comments in sequence; assert the listing returns them in
    # created_at ASC order (i.e. insertion order).
    posted_ids = []
    for i in range(3):
        res = client.post(
            f"/api/v1/findings/{fp}/comments",
            json={"text": f"comment {i}", "author": "u"},
        )
        assert res.status_code == 201
        posted_ids.append(res.json()["id"])
        time.sleep(0.005)  # ensure created_at strictly increases

    res = client.get(f"/api/v1/findings/{fp}/comments")
    assert res.status_code == 200
    body = res.json()
    assert len(body) == 3
    assert [c["text"] for c in body] == ["comment 0", "comment 1", "comment 2"]
    assert [c["id"] for c in body] == posted_ids


def test_list_comments_empty(client: TestClient):
    res = client.get("/api/v1/findings/fp-never-commented/comments")
    assert res.status_code == 200
    assert res.json() == []


def test_delete_comment(client: TestClient):
    fp = "fp-del"
    create = client.post(
        f"/api/v1/findings/{fp}/comments",
        json={"text": "delete me"},
    )
    assert create.status_code == 201
    cid = create.json()["id"]

    first = client.delete(f"/api/v1/findings/{fp}/comments/{cid}")
    assert first.status_code == 204
    assert first.content == b""

    second = client.delete(f"/api/v1/findings/{fp}/comments/{cid}")
    assert second.status_code == 404


def test_delete_comment_isolation(client: TestClient):
    """Deleting one comment must not touch any other comment."""
    fp_x = "fp-X"
    fp_y = "fp-Y"
    a = client.post(f"/api/v1/findings/{fp_x}/comments", json={"text": "X-A"}).json()["id"]
    b = client.post(f"/api/v1/findings/{fp_x}/comments", json={"text": "X-B"}).json()["id"]
    c = client.post(f"/api/v1/findings/{fp_y}/comments", json={"text": "Y-C"}).json()["id"]

    # Delete A on fingerprint X.
    res = client.delete(f"/api/v1/findings/{fp_x}/comments/{a}")
    assert res.status_code == 204

    # B (same fingerprint) and C (different fingerprint) still present.
    x_list = client.get(f"/api/v1/findings/{fp_x}/comments").json()
    y_list = client.get(f"/api/v1/findings/{fp_y}/comments").json()
    assert [c["id"] for c in x_list] == [b]
    assert [c["id"] for c in y_list] == [c]


# ---------------------------------------------------------------------------
# Legacy /api alias contract
# ---------------------------------------------------------------------------


def test_legacy_path_alias(client: TestClient):
    """PATCH /api/findings/... (no /v1) reaches the same handler and
    carries the deprecation header."""
    fp = "fp-legacy"
    res = client.patch(
        f"/api/findings/{fp}/state",
        json={"status": "triaged"},
    )
    assert res.status_code == 200
    assert res.json()["fingerprint"] == fp
    assert res.json()["status"] == "triaged"
    assert res.headers.get("Deprecation") == "true"
    assert "/api/v1/findings" in res.headers.get("Link", "")

    # And the v1 path on the same fingerprint sees the legacy-set state.
    f = _make_finding("placeholder", suffix="leg", fingerprint=fp)
    scan_id = _seed_scan(findings=[f])
    res2 = client.get(f"/api/v1/scans/{scan_id}/findings")
    assert res2.status_code == 200
    body = res2.json()
    assert body[0]["state"]["status"] == "triaged"


def test_legacy_comments_alias(client: TestClient):
    fp = "fp-legacy-comments"
    res = client.post(f"/api/findings/{fp}/comments", json={"text": "via legacy"})
    assert res.status_code == 201
    assert res.headers.get("Deprecation") == "true"
    cid = res.json()["id"]

    # Same comment surfaces under /api/v1.
    listed = client.get(f"/api/v1/findings/{fp}/comments").json()
    assert [c["id"] for c in listed] == [cid]
