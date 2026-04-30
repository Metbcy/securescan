"""Tests for hashed API keys backend (BE-AUTH-KEYS).

Covers the helper module (`api_keys.py`), the auth integration
(`auth.py`), and the `/api/keys` router (`api/keys.py`). Lockout
protection on DELETE is covered here; per-scope route enforcement
lives in ``test_scopes.py``.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from securescan import api_keys as ak
from securescan import auth
from securescan.database import (
    count_admin_keys_active,
    get_api_key_by_id,
    has_unrevoked_api_key,
    init_db,
    insert_api_key,
    revoke_api_key,
    set_db_path,
)
from securescan.main import app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Fresh DB + cleared auth env vars per test.

    `set_db_path` is process-global, so we MUST reset it on teardown
    or sibling test modules (test_auth.py, test_api_versioning.py) -
    which expect the legacy default DB - will see this fixture's
    populated tmp DB and fail.
    """
    from securescan.config import settings as _settings

    db_path = str(tmp_path / "auth_keys.db")
    original = _settings.database_path
    set_db_path(db_path)
    asyncio.run(init_db())
    monkeypatch.delenv(auth.ENV_VAR, raising=False)
    monkeypatch.delenv(auth.AUTH_REQUIRED_ENV, raising=False)
    yield db_path
    set_db_path(original)


@pytest.fixture
def client(temp_db) -> TestClient:
    # NOT using `with TestClient(...)` -- avoids running the startup
    # SystemExit check while still allowing real HTTP requests through.
    # Lifespan-dependent tests (the SystemExit one) drive the helper
    # function directly instead.
    return TestClient(app, raise_server_exceptions=False)


async def _seed_admin_key(name: str = "admin-bootstrap") -> tuple[str, str]:
    """Insert a fresh admin-with-everything key directly via the DB layer.

    Returns ``(id, full_plaintext_key)``. The key carries
    ``[admin, read, write]`` so the bootstrap operator can also drive
    the read/write endpoints (matches a realistic first-run workflow).
    Lockout-protection logic still keys off the ``admin`` scope. Used
    by tests that can't bootstrap via the HTTP API because doing so
    would itself require an admin key.
    """
    gk = ak.generate_key()
    await insert_api_key(
        gk.id,
        name,
        gk.key_hash,
        gk.prefix,
        ["admin", "read", "write"],
        datetime.utcnow(),
    )
    return gk.id, gk.full


# ---------------------------------------------------------------------------
# api_keys.py: generation / hashing helpers
# ---------------------------------------------------------------------------


def test_generate_key_format():
    gk = ak.generate_key()
    assert gk.full.startswith("ssk_")
    assert len(gk.id) == ak.ID_LENGTH
    assert "-" not in gk.id and "_" not in gk.id  # post substitution
    # full = "ssk_" + id + "_" + secret
    assert gk.full == f"ssk_{gk.id}_{gk.secret}"
    assert len(gk.secret) == ak.SECRET_LENGTH
    assert gk.prefix == gk.full[:16]
    # key_hash is "<salt-hex>$<digest-hex>"
    assert "$" in gk.key_hash
    salt_hex, digest_hex = gk.key_hash.split("$", 1)
    assert len(salt_hex) == 32  # 16 bytes -> 32 hex chars
    assert len(digest_hex) == 64  # sha256 -> 64 hex chars


def test_parse_key_id_round_trip():
    gk = ak.generate_key()
    assert ak.parse_key_id(gk.full) == gk.id


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "no-prefix",
        "ssk_short",  # missing separator
        "ssk_tooshort_xxx",  # id length wrong
        "ssk_" + "a" * 9 + "_xxx",  # id length wrong
        "ssk_" + "a" * 11 + "_xxx",  # id length wrong
    ],
)
def test_parse_key_id_rejects_malformed(bad):
    assert ak.parse_key_id(bad) is None


def test_parse_key_id_handles_non_string():
    assert ak.parse_key_id(None) is None  # type: ignore[arg-type]
    assert ak.parse_key_id(12345) is None  # type: ignore[arg-type]


def test_hash_verify_round_trip():
    gk = ak.generate_key()
    assert ak.verify_key(gk.full, gk.key_hash) is True


def test_verify_key_rejects_wrong_key():
    gk = ak.generate_key()
    other = ak.generate_key()
    assert ak.verify_key(other.full, gk.key_hash) is False


def test_verify_key_rejects_corrupted_hash():
    gk = ak.generate_key()
    # Missing salt separator -> graceful False (no exception).
    assert ak.verify_key(gk.full, "garbage") is False
    assert ak.verify_key(gk.full, "nothex$" + "a" * 64) is False


def test_hash_uses_fresh_salt_each_call():
    """Two hashes of the same plaintext must differ (salt is random)."""
    gk = ak.generate_key()
    h1 = ak._hash_key(gk.full)
    h2 = ak._hash_key(gk.full)
    assert h1 != h2  # different salts
    assert ak.verify_key(gk.full, h1)
    assert ak.verify_key(gk.full, h2)


# ---------------------------------------------------------------------------
# Database CRUD
# ---------------------------------------------------------------------------


def test_insert_and_get_api_key(temp_db):
    gk = ak.generate_key()

    async def _go():
        await insert_api_key(
            gk.id, "ci-bot", gk.key_hash, gk.prefix, ["read", "write"], datetime.utcnow()
        )
        row = await get_api_key_by_id(gk.id)
        assert row is not None
        assert row["name"] == "ci-bot"
        assert json.loads(row["scopes"]) == ["read", "write"]
        assert row["revoked_at"] is None

    asyncio.run(_go())


def test_revoke_api_key_marks_row(temp_db):
    gk = ak.generate_key()

    async def _go():
        await insert_api_key(gk.id, "k", gk.key_hash, gk.prefix, ["read"], datetime.utcnow())
        assert await revoke_api_key(gk.id) is True
        row = await get_api_key_by_id(gk.id)
        assert row["revoked_at"] is not None
        # second revoke is a no-op
        assert await revoke_api_key(gk.id) is False

    asyncio.run(_go())


def test_count_admin_keys_active(temp_db):
    async def _go():
        assert await count_admin_keys_active() == 0
        a = ak.generate_key()
        b = ak.generate_key()
        c = ak.generate_key()
        await insert_api_key(a.id, "a", a.key_hash, a.prefix, ["admin"], datetime.utcnow())
        await insert_api_key(b.id, "b", b.key_hash, b.prefix, ["admin", "read"], datetime.utcnow())
        await insert_api_key(c.id, "c", c.key_hash, c.prefix, ["read"], datetime.utcnow())
        assert await count_admin_keys_active() == 2
        await revoke_api_key(a.id)
        assert await count_admin_keys_active() == 1

    asyncio.run(_go())


def test_has_unrevoked_api_key(temp_db):
    async def _go():
        assert await has_unrevoked_api_key() is False
        gk = ak.generate_key()
        await insert_api_key(gk.id, "k", gk.key_hash, gk.prefix, ["read"], datetime.utcnow())
        assert await has_unrevoked_api_key() is True
        await revoke_api_key(gk.id)
        assert await has_unrevoked_api_key() is False

    asyncio.run(_go())


# ---------------------------------------------------------------------------
# Auth integration: env-var legacy + DB key + dev mode
# ---------------------------------------------------------------------------


def test_legacy_env_var_still_works(temp_db, client, monkeypatch):
    monkeypatch.setenv(auth.ENV_VAR, "envsecret")
    res = client.get("/api/scans", headers={"X-API-Key": "envsecret"})
    assert res.status_code == 200


def test_legacy_env_var_rejects_wrong_key(temp_db, client, monkeypatch):
    monkeypatch.setenv(auth.ENV_VAR, "envsecret")
    res = client.get("/api/scans", headers={"X-API-Key": "wrong"})
    assert res.status_code == 401


def test_authenticated_request_with_db_key(temp_db, client):
    key_id, full = asyncio.run(_seed_admin_key())
    res = client.get("/api/scans", headers={"X-API-Key": full})
    assert res.status_code == 200

    # last_used_at was updated
    row = asyncio.run(get_api_key_by_id(key_id))
    assert row["last_used_at"] is not None


def test_db_key_rejected_with_wrong_secret(temp_db, client):
    key_id, full = asyncio.run(_seed_admin_key())
    # mangle the secret part but keep the id
    bad = full[:18] + "X" * (len(full) - 18)
    res = client.get("/api/scans", headers={"X-API-Key": bad})
    assert res.status_code == 401


def test_revoked_db_key_rejected(temp_db, client, monkeypatch):
    """A revoked key must 401. Seed a second key so auth stays
    enforced after we revoke the first -- otherwise the system would
    drop into dev mode (no creds at all) and we'd get a misleading
    200 from the dev-mode passthrough rather than the real 401."""
    monkeypatch.setenv(auth.ENV_VAR, "always-on")  # keep auth required

    key_id, full = asyncio.run(_seed_admin_key())
    # confirm it works first
    assert client.get("/api/scans", headers={"X-API-Key": full}).status_code == 200
    asyncio.run(revoke_api_key(key_id))
    res = client.get("/api/scans", headers={"X-API-Key": full})
    assert res.status_code == 401


def test_unknown_db_key_id_rejected(temp_db, client, monkeypatch):
    """A well-formed key whose id isn't in the DB must 401. The env
    var fallback ensures auth is enforced (otherwise dev mode would
    short-circuit and pass the unknown key through)."""
    monkeypatch.setenv(auth.ENV_VAR, "always-on")
    fake = f"ssk_{'a' * ak.ID_LENGTH}_{'b' * ak.SECRET_LENGTH}"
    res = client.get("/api/scans", headers={"X-API-Key": fake})
    assert res.status_code == 401


def test_revoked_db_key_rejected_when_no_env_var(temp_db, client, monkeypatch):
    """Regression: revoking the last DB key must NOT silently flip the
    system back to dev mode for a caller that's still presenting the
    revoked key. Otherwise, the legacy single-key dev workflow
    (``ssk_xxx`` only, no env var) lets revoked keys keep working as
    soon as the operator revokes them all.

    The fix: any explicit-but-bogus key always gets a 401, even when
    the system would otherwise fall into dev mode for an
    unauthenticated request.
    """
    monkeypatch.delenv(auth.ENV_VAR, raising=False)  # NO env-var fallback
    key_id, full = asyncio.run(_seed_admin_key())
    assert client.get("/api/scans", headers={"X-API-Key": full}).status_code == 200

    asyncio.run(revoke_api_key(key_id))

    # With the only DB key revoked AND no env var, the system would
    # naively drop to dev mode -- but the explicit revoked key in the
    # request must still be treated as a credential failure.
    res = client.get("/api/scans", headers={"X-API-Key": full})
    assert res.status_code == 401

    # An unauthenticated request from this state IS allowed (dev mode),
    # since no caller-provided key triggers strict validation. This
    # documents the asymmetry: presenting a bad key fails closed,
    # presenting no key passes through dev mode.
    assert client.get("/api/scans").status_code == 200


def test_authorization_bearer_with_db_key(temp_db, client):
    _id, full = asyncio.run(_seed_admin_key())
    res = client.get("/api/scans", headers={"Authorization": f"Bearer {full}"})
    assert res.status_code == 200


# ---------------------------------------------------------------------------
# /api/keys endpoints
# ---------------------------------------------------------------------------


def test_create_key_returns_full_secret_once(temp_db, client):
    # Bootstrap an admin key first (POST /keys requires admin scope).
    _id, admin_full = asyncio.run(_seed_admin_key())

    res = client.post(
        "/api/v1/keys",
        json={"name": "ci-bot", "scopes": ["read"]},
        headers={"X-API-Key": admin_full},
    )
    assert res.status_code == 201
    body = res.json()
    assert body["name"] == "ci-bot"
    assert body["scopes"] == ["read"]
    assert body["key"].startswith("ssk_")
    assert body["prefix"] == body["key"][:16]
    assert body["revoked_at"] is None

    # Subsequent GET must NEVER include the secret.
    list_res = client.get("/api/v1/keys", headers={"X-API-Key": admin_full})
    assert list_res.status_code == 200
    rows = list_res.json()
    new_row = next(r for r in rows if r["id"] == body["id"])
    assert "key" not in new_row


def test_list_keys_excludes_secret(temp_db, client):
    _id, admin_full = asyncio.run(_seed_admin_key())
    res = client.get("/api/v1/keys", headers={"X-API-Key": admin_full})
    assert res.status_code == 200
    for row in res.json():
        assert "key" not in row
        assert "key_hash" not in row


def test_list_keys_includes_revoked(temp_db, client):
    _id, admin_full = asyncio.run(_seed_admin_key())
    create = client.post(
        "/api/v1/keys",
        json={"name": "tmp", "scopes": ["read"]},
        headers={"X-API-Key": admin_full},
    )
    new_id = create.json()["id"]
    client.delete(
        f"/api/v1/keys/{new_id}",
        headers={"X-API-Key": admin_full},
    )

    res = client.get("/api/v1/keys", headers={"X-API-Key": admin_full})
    rows = res.json()
    revoked_row = next(r for r in rows if r["id"] == new_id)
    assert revoked_row["revoked_at"] is not None


def test_get_me_returns_db_principal_info(temp_db, client):
    key_id, full = asyncio.run(_seed_admin_key("self-test"))
    res = client.get("/api/v1/keys/me", headers={"X-API-Key": full})
    assert res.status_code == 200
    body = res.json()
    assert body["id"] == key_id
    assert body["name"] == "self-test"
    assert "key" not in body


def test_get_me_404_for_env_principal(temp_db, client, monkeypatch):
    monkeypatch.setenv(auth.ENV_VAR, "envonly")
    res = client.get("/api/v1/keys/me", headers={"X-API-Key": "envonly"})
    assert res.status_code == 404


def test_revoke_key_returns_204(temp_db, client):
    _id, admin_full = asyncio.run(_seed_admin_key())
    create = client.post(
        "/api/v1/keys",
        json={"name": "rev", "scopes": ["read"]},
        headers={"X-API-Key": admin_full},
    )
    new_id = create.json()["id"]
    res = client.delete(
        f"/api/v1/keys/{new_id}",
        headers={"X-API-Key": admin_full},
    )
    assert res.status_code == 204


def test_revoke_key_idempotent(temp_db, client):
    _id, admin_full = asyncio.run(_seed_admin_key())
    create = client.post(
        "/api/v1/keys",
        json={"name": "idem", "scopes": ["read"]},
        headers={"X-API-Key": admin_full},
    )
    new_id = create.json()["id"]
    r1 = client.delete(f"/api/v1/keys/{new_id}", headers={"X-API-Key": admin_full})
    r2 = client.delete(f"/api/v1/keys/{new_id}", headers={"X-API-Key": admin_full})
    assert r1.status_code == 204
    assert r2.status_code == 204  # idempotent


def test_revoke_unknown_key_returns_404(temp_db, client):
    _id, admin_full = asyncio.run(_seed_admin_key())
    res = client.delete(
        "/api/v1/keys/nonexistent",
        headers={"X-API-Key": admin_full},
    )
    assert res.status_code == 404


# ---------------------------------------------------------------------------
# Lockout protection on DELETE (last admin under AUTH_REQUIRED=1)
# ---------------------------------------------------------------------------


def test_cannot_revoke_last_admin_when_auth_required(temp_db, client, monkeypatch):
    key_id, admin_full = asyncio.run(_seed_admin_key())
    # No env-var fallback, AUTH_REQUIRED=1: this admin is the only key.
    monkeypatch.setenv(auth.AUTH_REQUIRED_ENV, "1")
    res = client.delete(
        f"/api/v1/keys/{key_id}",
        headers={"X-API-Key": admin_full},
    )
    assert res.status_code == 409
    # Key is still active.
    row = asyncio.run(get_api_key_by_id(key_id))
    assert row["revoked_at"] is None


def test_can_revoke_admin_when_other_admin_exists(temp_db, client, monkeypatch):
    a_id, a_full = asyncio.run(_seed_admin_key("admin-1"))
    b_id, _b_full = asyncio.run(_seed_admin_key("admin-2"))
    monkeypatch.setenv(auth.AUTH_REQUIRED_ENV, "1")

    # Revoke the second admin while the first is still around.
    res = client.delete(
        f"/api/v1/keys/{b_id}",
        headers={"X-API-Key": a_full},
    )
    assert res.status_code == 204


def test_can_revoke_admin_when_env_key_set(temp_db, client, monkeypatch):
    key_id, admin_full = asyncio.run(_seed_admin_key())
    monkeypatch.setenv(auth.AUTH_REQUIRED_ENV, "1")
    monkeypatch.setenv(auth.ENV_VAR, "fallbacksecret")

    res = client.delete(
        f"/api/v1/keys/{key_id}",
        headers={"X-API-Key": admin_full},
    )
    assert res.status_code == 204


def test_can_revoke_non_admin_even_when_only_one_admin(temp_db, client, monkeypatch):
    """Only ADMIN keys are protected by lockout logic. Revoking a
    read-only key when one admin remains must succeed."""
    _admin_id, admin_full = asyncio.run(_seed_admin_key())
    # Create a read-only key via the API.
    create = client.post(
        "/api/v1/keys",
        json={"name": "read", "scopes": ["read"]},
        headers={"X-API-Key": admin_full},
    )
    new_id = create.json()["id"]
    monkeypatch.setenv(auth.AUTH_REQUIRED_ENV, "1")

    res = client.delete(
        f"/api/v1/keys/{new_id}",
        headers={"X-API-Key": admin_full},
    )
    assert res.status_code == 204


# ---------------------------------------------------------------------------
# Startup safety check
# ---------------------------------------------------------------------------


def test_assert_auth_credentials_configured_raises(monkeypatch):
    monkeypatch.setenv(auth.AUTH_REQUIRED_ENV, "1")
    with pytest.raises(SystemExit) as exc:
        auth.assert_auth_credentials_configured(env_key=None, admin_db_count=0)
    assert exc.value.code == 2


def test_assert_auth_credentials_configured_passes_with_env(monkeypatch):
    monkeypatch.setenv(auth.AUTH_REQUIRED_ENV, "1")
    # Must not raise.
    auth.assert_auth_credentials_configured(env_key="envsecret", admin_db_count=0)


def test_assert_auth_credentials_configured_passes_with_admin_key(monkeypatch):
    monkeypatch.setenv(auth.AUTH_REQUIRED_ENV, "1")
    auth.assert_auth_credentials_configured(env_key=None, admin_db_count=1)


def test_assert_auth_credentials_configured_silent_when_unset(monkeypatch):
    monkeypatch.delenv(auth.AUTH_REQUIRED_ENV, raising=False)
    # Dev mode: no creds, AUTH_REQUIRED unset -> no exit.
    auth.assert_auth_credentials_configured(env_key=None, admin_db_count=0)
