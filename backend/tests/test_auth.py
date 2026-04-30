"""Tests for optional API key auth (PG4)."""

from __future__ import annotations

import importlib
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from securescan import auth


@pytest.fixture
def app_client(monkeypatch):
    """Build a fresh FastAPI app under whatever env the test set up.

    We import securescan.main after the env is patched so the configured
    key is read at routing time. The auth dependency itself reads
    os.environ on each call, but importing main is still useful to wire
    the routers."""
    monkeypatch.setenv("SECURESCAN_TESTING", "1")
    main = importlib.import_module("securescan.main")
    importlib.reload(main)
    return TestClient(main.app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Helpers / unit-level tests
# ---------------------------------------------------------------------------


def test_dev_mode_when_env_unset(monkeypatch):
    monkeypatch.delenv(auth.ENV_VAR, raising=False)
    assert auth.is_dev_mode() is True
    assert auth.get_configured_key() is None


def test_dev_mode_when_env_blank(monkeypatch):
    monkeypatch.setenv(auth.ENV_VAR, "   ")
    assert auth.is_dev_mode() is True
    assert auth.get_configured_key() is None


def test_configured_key_strips_whitespace(monkeypatch):
    monkeypatch.setenv(auth.ENV_VAR, "  topsecret  ")
    assert auth.is_dev_mode() is False
    assert auth.get_configured_key() == "topsecret"


@pytest.mark.asyncio
async def test_require_api_key_returns_none_in_dev_mode(monkeypatch):
    monkeypatch.delenv(auth.ENV_VAR, raising=False)

    class _Req:
        headers: dict[str, str] = {}

    result = await auth.require_api_key(_Req())  # type: ignore[arg-type]
    assert result is None


# ---------------------------------------------------------------------------
# End-to-end tests via FastAPI TestClient
# ---------------------------------------------------------------------------


def test_dev_mode_request_passes_without_header(monkeypatch, app_client):
    monkeypatch.delenv(auth.ENV_VAR, raising=False)
    res = app_client.get("/api/scans")
    assert res.status_code != 401
    assert res.status_code in (200, 404, 500)  # 200 expected; tolerate empty


def test_configured_mode_rejects_missing_header(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "secret")
    res = app_client.get("/api/scans")
    assert res.status_code == 401
    assert res.json()["detail"] == "X-API-Key header required"
    assert res.headers.get("WWW-Authenticate") == "Bearer"


def test_configured_mode_accepts_x_api_key(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "secret")
    res = app_client.get("/api/scans", headers={"X-API-Key": "secret"})
    assert res.status_code != 401
    assert res.status_code in (200, 404, 500)


def test_configured_mode_accepts_authorization_bearer(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "secret")
    res = app_client.get(
        "/api/scans",
        headers={"Authorization": "Bearer secret"},
    )
    assert res.status_code != 401
    assert res.status_code in (200, 404, 500)


def test_configured_mode_rejects_wrong_key(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "secret")
    res = app_client.get("/api/scans", headers={"X-API-Key": "wrong"})
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid API key"


def test_configured_mode_rejects_wrong_bearer(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "secret")
    res = app_client.get(
        "/api/scans",
        headers={"Authorization": "Bearer nope"},
    )
    assert res.status_code == 401


def test_health_remains_public_in_configured_mode(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "secret")
    res = app_client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_root_remains_public_in_configured_mode(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "secret")
    res = app_client.get("/")
    assert res.status_code == 200


def test_dashboard_endpoint_protected(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "topsecret")
    res = app_client.get("/api/dashboard/status")
    assert res.status_code == 401


def test_compliance_endpoint_protected(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "topsecret")
    res = app_client.get("/api/compliance/frameworks")
    assert res.status_code == 401


def test_sbom_endpoint_protected(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "topsecret")
    res = app_client.get("/api/sbom/history")
    assert res.status_code == 401


def test_browse_endpoint_protected(monkeypatch, app_client):
    monkeypatch.setenv(auth.ENV_VAR, "topsecret")
    res = app_client.get("/api/browse")
    assert res.status_code == 401


def test_compare_digest_used_for_constant_time(monkeypatch, app_client):
    """Verify secrets.compare_digest is used (timing-safe comparison),
    not raw == on the user-provided key."""
    monkeypatch.setenv(auth.ENV_VAR, "secret")
    with patch(
        "securescan.auth.secrets.compare_digest", wraps=__import__("secrets").compare_digest
    ) as spy:
        res = app_client.get("/api/scans", headers={"X-API-Key": "secret"})
        assert res.status_code != 401
        spy.assert_called()
        called_args = spy.call_args.args
        assert "secret" in called_args
