"""Tests for the /ready readiness probe.

The /ready endpoint is distinct from /health: liveness vs readiness.
Production probes (Kubernetes readinessProbe, ALB target-group health
checks) need a "fully initialized" signal that is gated on real
dependencies (DB schema, scanner registry) but is NEVER auth-gated
(probes don't carry headers).
"""

import sys
import types

from fastapi.testclient import TestClient

from securescan import main as main_module
from securescan.main import app

client = TestClient(app)


def test_ready_returns_200_when_db_and_scanners_ok():
    response = client.get("/ready")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert "checks" in payload


def test_ready_response_includes_db_check():
    response = client.get("/ready")
    assert response.status_code == 200
    payload = response.json()
    assert "db" in payload["checks"]
    assert payload["checks"]["db"]["status"] == "ok"


def test_ready_response_includes_scanner_count():
    response = client.get("/ready")
    assert response.status_code == 200
    payload = response.json()
    assert "scanners" in payload["checks"]
    assert payload["checks"]["scanners"]["status"] == "ok"
    count = payload["checks"]["scanners"]["count"]
    assert isinstance(count, int)
    assert count > 0


def test_ready_returns_503_when_init_db_fails(monkeypatch):
    async def boom():
        raise RuntimeError("database is unreachable")

    monkeypatch.setattr(main_module, "init_db", boom)

    response = client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    detail = body["detail"]
    assert detail["status"] == "not_ready"
    assert detail["checks"]["db"]["status"] == "fail"
    assert "database is unreachable" in detail["checks"]["db"]["error"]
    assert detail["checks"]["scanners"]["status"] == "ok"


def test_ready_returns_503_when_scanner_registry_fails(monkeypatch):
    class _BrokenScannersModule(types.ModuleType):
        def __getattr__(self, name):
            raise RuntimeError(f"scanner registry import failed: {name}")

    broken = _BrokenScannersModule("securescan.scanners")
    monkeypatch.setitem(sys.modules, "securescan.scanners", broken)

    response = client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    detail = body["detail"]
    assert detail["status"] == "not_ready"
    assert detail["checks"]["scanners"]["status"] == "fail"
    assert "scanner registry import failed" in detail["checks"]["scanners"]["error"]
    assert detail["checks"]["db"]["status"] == "ok"


def test_ready_does_not_require_api_key(monkeypatch):
    # Even when an API key is configured, /ready must remain public so
    # external probes (Kubernetes readinessProbe, ALB target groups)
    # without auth headers can still reach it. This test guards against
    # /api/*-style auth dependencies leaking to /ready.
    monkeypatch.setenv("SECURESCAN_API_KEY", "secret-key-not-sent-by-probes")

    response = client.get("/ready")
    assert response.status_code == 200, (
        "/ready must be public; probes do not carry X-API-Key headers"
    )
    assert response.json()["status"] == "ready"


def test_health_and_ready_are_distinct():
    health_response = client.get("/health")
    ready_response = client.get("/ready")

    assert health_response.status_code == 200
    assert ready_response.status_code == 200

    health_body = health_response.json()
    ready_body = ready_response.json()

    assert health_body == {"status": "ok"}
    assert ready_body != health_body
    assert "checks" in ready_body
    assert "checks" not in health_body
    assert ready_body["status"] == "ready"
