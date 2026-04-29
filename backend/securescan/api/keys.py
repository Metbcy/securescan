"""API-key management endpoints (BE-AUTH-KEYS).

Issue, list, introspect, and revoke hashed API keys with scoped
permissions. The full plaintext secret is returned exactly once on
``POST /api/keys`` -- subsequent ``GET /api/keys`` (or ``GET /me``)
only expose the prefix and metadata. The DB only ever stores the
salted hash, so a lost key cannot be recovered: revoke and re-issue.

Endpoints
---------
* ``POST   /api/keys``           - admin: create a new key
* ``GET    /api/keys``           - admin: list all keys
* ``GET    /api/keys/me``        - any authenticated DB key: introspect self
* ``DELETE /api/keys/{key_id}``  - admin: revoke a key (idempotent)

Lockout protection
~~~~~~~~~~~~~~~~~~
``DELETE`` refuses to revoke the last unrevoked admin key when
``AUTH_REQUIRED=1`` and no ``SECURESCAN_API_KEY`` env-var fallback
exists -- otherwise the next request would 503 and the operator
would have no way to issue a replacement.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Optional

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..api_keys import generate_key
from ..auth import (
    AUTH_REQUIRED_ENV,
    Principal,
    _bool_env,
    get_configured_key,
    require_scope,
)
from ..database import (
    count_admin_keys_active,
    get_api_key_by_id,
    insert_api_key,
    list_api_keys,
    revoke_api_key,
)
from ..models import ApiKeyCreated, ApiKeyScope, ApiKeyView


router = APIRouter(prefix="/api/keys", tags=["auth"])


class CreateKeyBody(BaseModel):
    """Request body for ``POST /api/keys``.

    `scopes` defaults to a single ``read`` so that an operator who
    creates a key without thinking about scopes gets the least
    privileged option.
    """
    name: str = Field(min_length=1, max_length=200)
    scopes: list[ApiKeyScope] = Field(
        default_factory=lambda: [ApiKeyScope.READ]
    )


def _row_to_view(row: dict) -> ApiKeyView:
    """Project a raw `api_keys` row dict to the public ApiKeyView model.

    Used by `GET /keys`, `GET /me`, and the create handler (which then
    layers the plaintext `key` on top to build ApiKeyCreated).
    """
    scopes_raw = json.loads(row["scopes"]) if row["scopes"] else []
    return ApiKeyView(
        id=row["id"],
        name=row["name"],
        prefix=row["prefix"],
        scopes=[ApiKeyScope(s) for s in scopes_raw],
        created_at=datetime.fromisoformat(row["created_at"]),
        last_used_at=(
            datetime.fromisoformat(row["last_used_at"])
            if row["last_used_at"]
            else None
        ),
        revoked_at=(
            datetime.fromisoformat(row["revoked_at"])
            if row["revoked_at"]
            else None
        ),
    )


@router.post(
    "",
    response_model=ApiKeyCreated,
    status_code=201,
    dependencies=[Depends(require_scope("admin"))],
)
async def create_key(body: CreateKeyBody) -> ApiKeyCreated:
    """Issue a new API key. Returns the full plaintext secret ONCE.

    Retries up to 5x on a primary-key collision -- with a 60-bit id
    space the probability after one collision is still ~2^-60, but
    looping is cheap and avoids surfacing the error to the caller.
    """
    scopes = [s.value for s in body.scopes]
    for _ in range(5):
        gk = generate_key()
        created_at = datetime.utcnow()
        try:
            await insert_api_key(
                gk.id, body.name, gk.key_hash, gk.prefix, scopes, created_at
            )
        except aiosqlite.IntegrityError:
            continue
        return ApiKeyCreated(
            id=gk.id,
            name=body.name,
            prefix=gk.prefix,
            scopes=body.scopes,
            created_at=created_at,
            key=gk.full,
        )
    raise HTTPException(500, "Could not generate unique key id; please retry")


@router.get(
    "",
    response_model=list[ApiKeyView],
    dependencies=[Depends(require_scope("admin"))],
)
async def get_keys() -> list[ApiKeyView]:
    """List all keys (revoked included) newest-first.

    Including revoked rows in the default response gives admin UIs a
    clear audit trail; a `?include_revoked=false` toggle is left to
    a future PR if/when the list grows large enough to need it.
    """
    rows = await list_api_keys(include_revoked=True)
    return [_row_to_view(r) for r in rows]


@router.get("/me", response_model=ApiKeyView)
async def get_me(request: Request) -> ApiKeyView:
    """Return the caller's own key info.

    Intentionally NOT wrapped in ``require_scope`` -- a DB-issued key
    of any scope can introspect itself. Returns 404 (not 401) when the
    caller authenticated via the legacy env-var path or via dev mode,
    because there is no DB row to describe.
    """
    principal: Optional[Principal] = getattr(request.state, "principal", None)
    if principal is None or principal.source != "db":
        raise HTTPException(404, "Not authenticated via DB key")
    row = await get_api_key_by_id(principal.id)
    if row is None:
        raise HTTPException(404, "Key not found")
    return _row_to_view(row)


@router.delete(
    "/{key_id}",
    status_code=204,
    dependencies=[Depends(require_scope("admin"))],
)
async def delete_key(key_id: str) -> None:
    """Revoke a key by id.

    Idempotent: revoking an already-revoked key returns 204 with no
    body change. Refuses to revoke the last admin key when
    ``AUTH_REQUIRED=1`` and no env-var fallback is configured (would
    permanently lock the operator out).
    """
    target = await get_api_key_by_id(key_id)
    if target is None:
        raise HTTPException(404, "Key not found")

    # Already revoked -> idempotent no-op. The 204 with empty body is
    # indistinguishable from a fresh revoke, which is fine: the caller
    # only cares that the key is now revoked.
    if target["revoked_at"] is not None:
        return

    target_scopes = set(json.loads(target["scopes"]))
    if "admin" in target_scopes:
        auth_required = _bool_env(AUTH_REQUIRED_ENV)
        env_has = get_configured_key() is not None
        if auth_required and not env_has:
            # `count_admin_keys_active()` includes the target itself
            # (we haven't revoked yet); subtract 1 to count "others".
            other_admins = await count_admin_keys_active() - 1
            if other_admins <= 0:
                raise HTTPException(
                    409,
                    "Cannot revoke the last admin key when AUTH_REQUIRED=1",
                )

    await revoke_api_key(key_id)
