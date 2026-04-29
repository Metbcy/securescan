"""Scope enforcement tests + the regression-guard sweep (BE-AUTH-KEYS).

The end-of-file ``test_all_routes_have_explicit_scope`` is the
critical defense: every new ``/api/*`` route must declare an explicit
``Depends(require_scope(...))`` dependency or be added to the
allowlist. A failure here means a route shipped without scope
enforcement -- a security regression.
"""
from __future__ import annotations

import asyncio
from datetime import datetime

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from securescan import api_keys as ak
from securescan import auth
from securescan.database import init_db, insert_api_key, set_db_path
from securescan.main import app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Fresh DB + cleared auth env vars per test (reset path on teardown
    so the global `_db_path` doesn't leak into sibling test modules)."""
    from securescan.config import settings as _settings
    db_path = str(tmp_path / "scopes.db")
    original = _settings.database_path
    set_db_path(db_path)
    asyncio.run(init_db())
    monkeypatch.delenv(auth.ENV_VAR, raising=False)
    monkeypatch.delenv(auth.AUTH_REQUIRED_ENV, raising=False)
    yield db_path
    set_db_path(original)


@pytest.fixture
def client(temp_db) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


async def _seed_key(name: str, scopes: list[str]) -> str:
    """Insert a fresh key with the given scopes; return the plaintext."""
    gk = ak.generate_key()
    await insert_api_key(
        gk.id, name, gk.key_hash, gk.prefix, scopes, datetime.utcnow()
    )
    return gk.full


# ---------------------------------------------------------------------------
# Per-scope behavior
# ---------------------------------------------------------------------------

def test_read_scope_can_get_scans(temp_db, client):
    full = asyncio.run(_seed_key("reader", ["read"]))
    res = client.get("/api/v1/scans", headers={"X-API-Key": full})
    assert res.status_code == 200


def test_read_scope_cannot_post_scans(temp_db, client):
    full = asyncio.run(_seed_key("reader", ["read"]))
    res = client.post(
        "/api/v1/scans",
        json={"target_path": "/tmp", "scan_types": ["code"]},
        headers={"X-API-Key": full},
    )
    assert res.status_code == 403
    assert "scope" in res.json()["detail"].lower()


def test_write_only_key_cannot_get_scans(temp_db, client):
    """Documented design choice: scopes are independent (no implicit
    hierarchy). A WRITE-only key must NOT be able to GET /scans -- if
    a future change wants RW to imply read, that's an additive policy
    on the route and this test will need updating to match."""
    full = asyncio.run(_seed_key("writer", ["write"]))
    res = client.get("/api/v1/scans", headers={"X-API-Key": full})
    assert res.status_code == 403


def test_write_scope_can_post_scans(temp_db, client, tmp_path):
    full = asyncio.run(_seed_key("writer", ["write"]))
    # Use a real path so the create_scan handler doesn't 400 on a
    # non-existent directory (would mask a 403 vs 200 distinction).
    res = client.post(
        "/api/v1/scans",
        json={"target_path": str(tmp_path), "scan_types": ["code"]},
        headers={"X-API-Key": full},
    )
    # Anything other than 401/403 means the scope check passed.
    assert res.status_code not in (401, 403)


def test_admin_scope_can_create_keys(temp_db, client):
    full = asyncio.run(_seed_key("admin", ["admin"]))
    res = client.post(
        "/api/v1/keys",
        json={"name": "issued", "scopes": ["read"]},
        headers={"X-API-Key": full},
    )
    assert res.status_code == 201


def test_non_admin_cannot_create_keys(temp_db, client):
    full = asyncio.run(_seed_key("writer", ["write"]))
    res = client.post(
        "/api/v1/keys",
        json={"name": "should-fail", "scopes": ["read"]},
        headers={"X-API-Key": full},
    )
    assert res.status_code == 403


def test_admin_scope_can_install_scanner(temp_db, client):
    full = asyncio.run(_seed_key("admin", ["admin"]))
    # Use an unknown scanner so we get a 400 (validation) not a real
    # install -- but the scope check still has to pass first.
    res = client.post(
        "/api/v1/dashboard/install/not-a-real-scanner",
        headers={"X-API-Key": full},
    )
    assert res.status_code != 403


def test_read_scope_cannot_install_scanner(temp_db, client):
    full = asyncio.run(_seed_key("reader", ["read"]))
    res = client.post(
        "/api/v1/dashboard/install/checkov",
        headers={"X-API-Key": full},
    )
    assert res.status_code == 403


def test_dev_mode_passes_through_scope_checks(temp_db, client):
    """No env-var key, no DB keys, AUTH_REQUIRED unset -> dev mode.

    Per spec, scopes must fail-open in dev mode so local development
    isn't blocked. require_api_key returns None, principal is None,
    require_scope sees None -> allows. This test exists so a future
    refactor that makes require_scope fail-closed in dev mode will
    fail loudly here.
    """
    res = client.get("/api/v1/scans")
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# Regression guard: every /api/* route declares an explicit scope.
# ---------------------------------------------------------------------------
#
# Public allowlist -- routes that intentionally have NO scope dependency.
# Add to this list ONLY with a comment explaining why. Default-deny is
# the right policy: forgetting Depends(require_scope(...)) on a new
# route should fail this test, not silently ship.
PUBLIC_ALLOWLIST = frozenset({
    "/",                          # root banner
    "/health",                    # k8s liveness probe
    "/ready",                     # k8s readiness probe
    "/openapi.json",              # FastAPI default
    "/docs",                      # FastAPI default
    "/docs/oauth2-redirect",      # FastAPI default
    "/redoc",                     # FastAPI default
    # /me lets any authenticated DB key introspect itself, regardless
    # of scope. Documented in api/keys.py.
    "/api/keys/me",
    "/api/v1/keys/me",
})


def _route_has_scope_dependency(route: APIRoute) -> bool:
    """Walk the dependant tree looking for the require_scope marker.

    `require_scope(...)` returns a wrapper function carrying
    ``__securescan_scope__``; walking sub-dependants catches both
    route-level and (theoretical) router-level scope decorations.
    """
    seen: set[int] = set()
    stack = list(route.dependant.dependencies)
    while stack:
        dep = stack.pop()
        if id(dep) in seen:
            continue
        seen.add(id(dep))
        call = getattr(dep, "call", None)
        if call is not None and getattr(call, "__securescan_scope__", None) is not None:
            return True
        stack.extend(dep.dependencies)
    return False


def test_all_routes_have_explicit_scope():
    missing: list[str] = []
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue
        path = route.path
        if path in PUBLIC_ALLOWLIST:
            continue
        # Only scope-check the API surface; non-/api/ routes are app
        # plumbing (root, health, docs) covered by the allowlist above.
        if not path.startswith("/api"):
            continue
        if not _route_has_scope_dependency(route):
            methods = sorted(route.methods or [])
            missing.append(f"{methods} {path}")

    assert missing == [], (
        "API routes missing explicit Depends(require_scope(...)):\n  "
        + "\n  ".join(missing)
        + "\n\nEither attach a scope dependency or add the route to "
        "PUBLIC_ALLOWLIST with a comment explaining why."
    )


def test_keys_me_is_in_public_allowlist():
    """Sanity check the allowlist itself: /me MUST be unprotected."""
    paths = {r.path for r in app.routes if isinstance(r, APIRoute)}
    assert "/api/keys/me" in paths
    assert "/api/v1/keys/me" in paths
    assert "/api/keys/me" in PUBLIC_ALLOWLIST
    assert "/api/v1/keys/me" in PUBLIC_ALLOWLIST
