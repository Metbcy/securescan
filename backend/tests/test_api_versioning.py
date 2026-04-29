"""Tests for the /api/v1 versioning alias and deprecation headers (FEAT2)."""
from __future__ import annotations

from email.utils import parsedate_to_datetime

import pytest
from fastapi.testclient import TestClient

from securescan.main import app


@pytest.fixture(scope="module")
def client() -> TestClient:
    # No SECURESCAN_API_KEY set => dev mode, /api/* reachable without a header.
    # Use the context-manager form so FastAPI fires startup events (init_db).
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# Legacy /api/* paths
# ---------------------------------------------------------------------------

def test_legacy_scans_path_still_works(client: TestClient) -> None:
    res = client.get("/api/scans")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_legacy_path_carries_deprecation_header(client: TestClient) -> None:
    res = client.get("/api/scans")
    assert res.headers.get("Deprecation") == "true"


def test_legacy_path_link_header_points_at_v1_successor(client: TestClient) -> None:
    res = client.get("/api/scans")
    link = res.headers.get("Link", "")
    assert "</api/v1/scans>" in link
    assert 'rel="successor-version"' in link


def test_legacy_path_sunset_header_is_valid_http_date(client: TestClient) -> None:
    res = client.get("/api/scans")
    sunset = res.headers.get("Sunset")
    assert sunset, "Sunset header missing on legacy /api/* response"
    parsed = parsedate_to_datetime(sunset)
    assert parsed is not None
    # Must be in the future relative to v0.6.0 release timeframe.
    assert parsed.year >= 2026


# ---------------------------------------------------------------------------
# Versioned /api/v1/* paths
# ---------------------------------------------------------------------------

def test_v1_scans_path_works(client: TestClient) -> None:
    res = client.get("/api/v1/scans")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_v1_path_has_no_deprecation_headers(client: TestClient) -> None:
    res = client.get("/api/v1/scans")
    assert "Deprecation" not in res.headers
    assert "Sunset" not in res.headers
    # Only the deprecation Link rel="successor-version" should be filtered;
    # the v1 response shouldn't carry that either.
    assert 'rel="successor-version"' not in res.headers.get("Link", "")


def test_legacy_and_v1_bodies_are_identical(client: TestClient) -> None:
    legacy = client.get("/api/scans")
    versioned = client.get("/api/v1/scans")
    assert legacy.status_code == versioned.status_code == 200
    assert legacy.json() == versioned.json()


def test_v1_alias_covers_other_routers(client: TestClient) -> None:
    # Spot-check that the alias didn't only apply to scans.
    for path in (
        "/api/v1/dashboard/status",
        "/api/v1/compliance/frameworks",
        "/api/v1/sbom/history",
    ):
        res = client.get(path)
        assert res.status_code == 200, f"{path} -> {res.status_code}"
        assert "Deprecation" not in res.headers, f"{path} got deprecation header"


# ---------------------------------------------------------------------------
# Non-/api paths
# ---------------------------------------------------------------------------

def test_health_has_no_deprecation_headers(client: TestClient) -> None:
    res = client.get("/health")
    assert res.status_code == 200
    assert "Deprecation" not in res.headers
    assert "Sunset" not in res.headers


def test_root_has_no_deprecation_headers(client: TestClient) -> None:
    res = client.get("/")
    assert res.status_code == 200
    assert "Deprecation" not in res.headers


# ---------------------------------------------------------------------------
# OpenAPI: both paths must be discoverable
# ---------------------------------------------------------------------------

def test_openapi_lists_both_legacy_and_v1_paths(client: TestClient) -> None:
    res = client.get("/openapi.json")
    assert res.status_code == 200
    paths = res.json()["paths"]
    assert "/api/scans" in paths
    assert "/api/v1/scans" in paths
