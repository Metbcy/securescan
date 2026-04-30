"""API key auth with scopes (BE-AUTH-KEYS).

Two credential sources are supported, in this order:

1. ``SECURESCAN_API_KEY`` env var (legacy single-key auth, all scopes).
2. Hashed DB-issued keys (``api_keys`` table) with per-key scopes.

When neither is configured AND ``SECURESCAN_AUTH_REQUIRED`` is unset,
the API runs in dev mode: every request passes through and the
per-route ``require_scope`` dependencies fail-open so local development
is not blocked. When AUTH_REQUIRED=1 is set without any credentials,
startup raises ``SystemExit(2)`` so the operator can't accidentally
ship an unauthenticated production deploy.

``/health`` and ``/ready`` remain public regardless (Kubernetes probes).

Principal attachment
~~~~~~~~~~~~~~~~~~~~
On a successful authentication the resolved :class:`Principal` is
stashed on ``request.state.principal``. We use ``request.state``
instead of relying solely on the dependency return value so that:

* Per-route ``require_scope`` dependencies can inspect the principal
  without re-running ``require_api_key`` (it has DB side effects:
  ``last_used_at`` touch).
* Future middleware (per-key rate limiting, audit logging) can read
  the principal off the request without joining FastAPI's dependency
  graph.

``require_api_key`` also returns the principal as the dependency value,
so handlers that take ``principal: Principal = Depends(require_api_key)``
keep working - the two ergonomics coexist.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from dataclasses import dataclass
from datetime import datetime

from fastapi import HTTPException, Request, status
from fastapi.security.utils import get_authorization_scheme_param

from . import event_tokens
from .api_keys import parse_key_id, verify_key
from .database import (
    get_api_key_by_id,
    has_unrevoked_api_key,
    touch_api_key_last_used,
)

logger = logging.getLogger(__name__)

ENV_VAR = "SECURESCAN_API_KEY"
AUTH_REQUIRED_ENV = "SECURESCAN_AUTH_REQUIRED"

# Env-var keys are full-trust by design (legacy contract pre-dating
# scopes); a frozen set keeps the value immutable across requests.
ENV_PRINCIPAL_SCOPES: frozenset[str] = frozenset({"read", "write", "admin"})


@dataclass
class Principal:
    """Authenticated caller identity.

    ``id`` is "env" for the legacy env-var path, otherwise the DB key id.
    ``source`` distinguishes the two so handlers (e.g. ``GET /keys/me``)
    can branch on origin without parsing ``id``.
    """

    id: str
    scopes: set[str]
    source: str  # "env" | "db"


def get_configured_key() -> str | None:
    """Read the API key from env. Returns None when unset (or blank)."""
    key = os.environ.get(ENV_VAR, "")
    return key.strip() or None


def _bool_env(var: str, default: bool = False) -> bool:
    raw = os.environ.get(var, "")
    if not raw:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def is_dev_mode() -> bool:
    """Return True iff the legacy env-var key is unset.

    Kept for back-compat with the v0.7.0 startup banner. The runtime
    auth path also considers DB keys; use ``require_api_key`` for the
    full picture.
    """
    return get_configured_key() is None


def _extract_provided_key(request: Request) -> str | None:
    """Extract the caller's key from X-API-Key or Authorization: Bearer."""
    direct = request.headers.get("X-API-Key", "").strip()
    if direct:
        return direct
    auth = request.headers.get("Authorization", "")
    scheme, param = get_authorization_scheme_param(auth)
    if scheme.lower() == "bearer" and param:
        return param.strip()
    return None


def _attach_principal(request: Request, principal: Principal | None) -> None:
    """Stash ``principal`` on ``request.state``, defensively.

    Real Starlette requests always carry a ``state`` namespace, but
    several unit tests construct minimal mock requests with only a
    ``headers`` attribute - ignoring AttributeError there keeps those
    tests passing without weakening production behavior.
    """
    state = getattr(request, "state", None)
    if state is None:
        return
    try:
        state.principal = principal
    except (AttributeError, TypeError):
        pass


async def _authenticate_via_event_token(request: Request, event_token: str) -> Principal:
    """Validate an SSE event token and rehydrate the bound Principal.

    Performed inside ``require_api_key`` (not as a separate dependency)
    because every ``/api/*`` route is already wrapped in
    ``Depends(require_api_key)`` at mount time — a downstream handler
    check would never run, the request would 401 first.

    Three layers of defense:

    1. HMAC verify + expiry (``event_tokens.verify``).
    2. The ``scan_id`` bound into the token must match the one in the
       URL path. Stops a token minted for scan A being replayed
       against scan B.
    3. Rehydrate the principal from ``key_id``. If the bound DB key
       was revoked, or the env-var key was unset, the connection is
       refused — token TTL alone isn't enough because revocation
       must take effect immediately.
    """
    payload = event_tokens.verify(event_token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired event token",
        )

    # The path is one of:
    #   /api/scans/{scan_id}/events
    #   /api/v1/scans/{scan_id}/events
    # Walk back from "events" to grab the id segment positionally so we
    # don't have to thread the path-param value through Starlette.
    parts = request.url.path.rstrip("/").split("/")
    if "events" not in parts:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid event token route",
        )
    events_idx = parts.index("events")
    if events_idx == 0:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid event token route",
        )
    scan_id_from_url = parts[events_idx - 1]
    if scan_id_from_url != payload.scan_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token does not match scan id",
        )

    # Rehydrate the principal so revocation is honored even if the
    # token isn't yet expired.
    if payload.key_id == "dev":
        # Dev-mode token: minted when the system had no env-var key
        # and no DB keys. Accept only if the system is STILL in dev
        # mode (no creds configured). If credentials have since been
        # added, reject the dev-mode token so it can't bypass auth.
        env_key = get_configured_key()
        if env_key is not None or await has_unrevoked_api_key():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Dev-mode token no longer valid (auth has been enabled)",
            )
        # Construct a synthetic dev principal with all scopes so the
        # downstream require_scope checks pass (matches normal dev-mode
        # passthrough behavior).
        principal = Principal(
            id="dev",
            scopes=set(ENV_PRINCIPAL_SCOPES),
            source="dev",
        )
    elif payload.key_id == "env":
        if get_configured_key() is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Env-var key no longer configured",
            )
        principal = Principal(
            id="env",
            scopes=set(ENV_PRINCIPAL_SCOPES),
            source="env",
        )
    else:
        row = await get_api_key_by_id(payload.key_id)
        if row is None or row["revoked_at"] is not None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bound key is revoked or missing",
            )
        scopes = set(json.loads(row["scopes"]))
        principal = Principal(id=payload.key_id, scopes=scopes, source="db")

    _attach_principal(request, principal)
    return principal


async def require_api_key(request: Request) -> Principal | None:
    """FastAPI dependency: enforce auth via env-var key OR DB-issued key.

    Returns the resolved :class:`Principal` (also stashed on
    ``request.state.principal``) or None in dev mode. Raises:

    * 401 when credentials exist but are missing or wrong.
    * 401 when the caller provided ANY key but it doesn't match a
      configured/unrevoked credential — even if the DB happens to
      have zero unrevoked keys at the moment. We never fall through
      to dev mode for an explicit-but-bogus key, because that would
      let a revoked key keep working as soon as the operator revokes
      every other key.
    * 503 when ``AUTH_REQUIRED=1`` but no credentials are configured
      (defense in depth - startup should have already terminated).
    """
    provided = _extract_provided_key(request)
    auth_required = _bool_env(AUTH_REQUIRED_ENV, default=False)
    env_key = get_configured_key()

    # SSE event-token path: EventSource can't send X-API-Key, so the
    # mint endpoint hands the FE a short-lived signed token that
    # travels in the query string. We accept it ONLY on the SSE
    # ``/events`` route — checking the request path explicitly so a
    # leaked token can't be replayed against any other endpoint.
    #
    # Path-spoofing note: ``request.url.path`` is the post-routing
    # ASGI path that FastAPI/Starlette already used to dispatch this
    # request, so a caller can't lie about being on the SSE route to
    # win the check here while actually hitting a different handler.
    # We additionally re-extract the scan_id from that path and
    # require it to match the token's binding.
    #
    # Defensive against the minimal mock requests some unit tests use
    # (only ``.headers`` is guaranteed there); a missing
    # ``query_params``/``url`` short-circuits to "no event token".
    event_token = None
    is_sse_route = False
    try:
        event_token = request.query_params.get("event_token", "").strip() or None
        is_sse_route = request.url.path.endswith("/events") and "/scans/" in request.url.path
    except AttributeError:
        pass
    if event_token is not None and is_sse_route:
        return await _authenticate_via_event_token(request, event_token)

    # If the caller explicitly sent a key, validate it strictly. We do
    # NOT fall through to dev mode for a bogus / revoked key — that
    # would defeat revocation in the common single-key dev workflow
    # (revoke the only key, system flips to dev mode, the revoked key
    # silently works again).
    if provided is not None:
        if env_key is not None and secrets.compare_digest(provided, env_key):
            principal = Principal(
                id="env",
                scopes=set(ENV_PRINCIPAL_SCOPES),
                source="env",
            )
            _attach_principal(request, principal)
            return principal

        key_id = parse_key_id(provided)
        if key_id is not None:
            row = await get_api_key_by_id(key_id)
            if (
                row is not None
                and row["revoked_at"] is None
                and verify_key(provided, row["key_hash"])
            ):
                scopes = set(json.loads(row["scopes"]))
                await touch_api_key_last_used(key_id, datetime.utcnow())
                principal = Principal(id=key_id, scopes=scopes, source="db")
                _attach_principal(request, principal)
                return principal

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # No key provided. Decide between dev mode and 401 based on whether
    # any credentials are configured at all.
    has_creds = env_key is not None or await has_unrevoked_api_key()

    if not has_creds and not auth_required:
        _attach_principal(request, None)
        return None

    if not has_creds and auth_required:
        # Should be unreachable in practice -- startup raises SystemExit
        # for this case. Kept as defense in depth for hot-reload races.
        raise HTTPException(
            status_code=503,
            detail="Auth required but no credentials configured",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="X-API-Key header required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_scope(*needed: str):
    """FastAPI dependency factory: enforce at least one of ``needed``.

    Scopes are intersected (OR semantics): a route declared
    ``Depends(require_scope("read", "admin"))`` accepts a key with
    either scope. Use a separate dependency for AND semantics.

    Dev-mode behavior: when ``request.state.principal`` is None (no
    creds at all, AUTH_REQUIRED unset), this fails-open so local
    development is not blocked by scope checks. ``require_api_key``
    has already enforced the AUTH_REQUIRED-with-no-creds case as 503,
    so we know "principal is None" really does mean "dev mode".

    The returned callable carries a ``__securescan_scope__`` marker so
    the regression-guard test in ``test_scopes.py`` can introspect
    every ``/api/*`` route and assert an explicit scope is attached.
    """
    needed_set = frozenset(needed)

    async def _dep(request: Request) -> Principal | None:
        principal = getattr(request.state, "principal", None)
        if principal is None:
            return None
        if not (needed_set & principal.scopes):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires scope: {' or '.join(needed)}",
            )
        return principal

    _dep.__securescan_scope__ = tuple(needed)
    return _dep


def assert_auth_credentials_configured(env_key: str | None, admin_db_count: int) -> None:
    """Raise SystemExit(2) when AUTH_REQUIRED=1 with no usable credentials.

    Called from the FastAPI startup hook. Split out so unit tests can
    exercise it without spinning up the whole app: pass the values you
    want, assert SystemExit (or its absence).

    "No usable credentials" means: legacy env-var key unset AND no
    unrevoked admin DB key. A non-admin DB key wouldn't be enough -
    you couldn't issue more keys, so the system would still be
    unmanageable.
    """
    auth_required = _bool_env(AUTH_REQUIRED_ENV)
    if auth_required and env_key is None and admin_db_count == 0:
        logger.critical(
            "SECURESCAN_AUTH_REQUIRED=1 but no credentials configured. "
            "Either set SECURESCAN_API_KEY or create an API key via "
            "/api/v1/keys before requiring auth."
        )
        raise SystemExit(2)
