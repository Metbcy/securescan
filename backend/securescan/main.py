import logging
import os

from .config_loader import load_user_env

# Load ~/.config/securescan/.env (or $XDG_CONFIG_HOME/securescan/.env)
# before any module that instantiates Settings is imported. Shell env
# always wins; a missing file is a silent no-op.
load_user_env()

from fastapi import Depends, HTTPException

from . import event_tokens
from .api import app
from .api.compliance import router as compliance_router
from .api.dashboard import browse_router
from .api.dashboard import router as dashboard_router
from .api.keys import router as keys_router
from .api.notifications import router as notifications_router
from .api.sbom import router as sbom_router
from .api.scans import router as scans_router
from .api.triage import router as triage_router
from .api.versioning import alias_router_at_v1
from .api.webhooks import router as webhooks_router
from .auth import (
    AUTH_REQUIRED_ENV,
    _bool_env,
    assert_auth_credentials_configured,
    get_configured_key,
    is_dev_mode,
    require_api_key,
)
from .database import count_admin_keys_active, init_db, prune_old_notifications
from .middleware.rate_limit import RateLimitMiddleware
from .webhook_dispatcher import dispatcher as webhook_dispatcher

_auth = [Depends(require_api_key)]

# Rate limit first in the chain (added last so starlette's LIFO order
# runs it before the deprecation-header middleware mounted in api).
if not any(mw.cls is RateLimitMiddleware for mw in app.user_middleware):
    app.add_middleware(RateLimitMiddleware)

# Legacy /api/* mount — kept indefinitely for v0.5.0 CLIs and Actions.
# Responses on these paths get a Deprecation header (see api.versioning).
for _r in (
    scans_router,
    dashboard_router,
    browse_router,
    compliance_router,
    sbom_router,
    triage_router,
    keys_router,
    notifications_router,
    webhooks_router,
):
    app.include_router(_r, dependencies=_auth)
    # Parallel /api/v1/* mount — the preferred path going forward. Same
    # handlers, same models, single source of truth.
    alias_router_at_v1(app, _r, dependencies=_auth)


_logger = logging.getLogger(__name__)
if is_dev_mode():
    _logger.warning("SECURESCAN_API_KEY not set; API is unauthenticated (dev mode).")


@app.on_event("startup")
async def startup():
    await init_db()
    # Safety check (BE-AUTH-KEYS): if AUTH_REQUIRED=1 but no creds
    # exist, kill the process with exit 2 instead of booting an
    # unreachable API. Idempotent across reloads -- once the operator
    # creates a key (or sets the env var) the next start succeeds.
    env_key = get_configured_key()
    admin_db_count = await count_admin_keys_active()
    assert_auth_credentials_configured(env_key, admin_db_count)


@app.on_event("startup")
async def _startup_notifications():
    """One-shot prune of old read notifications (BE-NOTIFY).

    Kept as a single pass at startup rather than a recurring schedule
    -- v0.9.0 is single-process, single-worker; we get a sweep on
    every redeploy/reload, which is plenty for the expected volume
    (a handful of scan completions per day).
    """
    pruned = await prune_old_notifications(older_than_days=30)
    if pruned:
        _logger.info("notifications: pruned %d old read notifications", pruned)


@app.on_event("startup")
async def _startup_event_tokens():
    # Event-token signing (BE-SSE-TOKEN): required in auth-required
    # mode so SSE connections survive backend restarts; an ephemeral
    # secret is acceptable in dev because tokens die with the process
    # anyway.
    auth_required = _bool_env(AUTH_REQUIRED_ENV)
    secret_set = bool(os.environ.get("SECURESCAN_EVENT_TOKEN_SECRET", "").strip())
    if auth_required and not secret_set:
        _logger.critical(
            "SECURESCAN_AUTH_REQUIRED=1 requires "
            "SECURESCAN_EVENT_TOKEN_SECRET. Generate one with "
            "`python -c 'import secrets; print(secrets.token_urlsafe(32))'`."
        )
        raise SystemExit(2)
    if not secret_set:
        # Trigger the lazy resolver so the WARN log fires once at
        # startup instead of on the first SSE request.
        event_tokens._resolve_secret()
        if event_tokens._signing_secret_ephemeral:
            _logger.warning(
                "Using ephemeral SSE event-token signing secret — "
                "set SECURESCAN_EVENT_TOKEN_SECRET to persist tokens "
                "across restarts."
            )


@app.on_event("startup")
async def _startup_webhook_dispatcher():
    """Boot the durable outbound-webhook worker (BE-WEBHOOKS).

    On startup the worker resets any 'delivering' rows left over from
    a prior crash back to 'pending', then begins polling. Failures
    here would silently kill the dispatcher; we log + re-raise so an
    unhealthy deploy is loud (the readiness probe will still pass --
    the dispatcher is a side-channel, not request-path).
    """
    try:
        await webhook_dispatcher.start()
    except Exception:
        _logger.exception("webhook dispatcher failed to start")


@app.on_event("shutdown")
async def _shutdown_webhook_dispatcher():
    """Gracefully drain the dispatcher and close its httpx client."""
    try:
        await webhook_dispatcher.stop()
    except Exception:
        _logger.exception("webhook dispatcher shutdown error")


@app.get("/ready", tags=["health"])
async def ready():
    """Readiness probe: returns 200 only when the app is fully ready
    to serve API traffic (database reachable, scanner registry loaded).
    Returns 503 with details when not ready.

    Uses ``db_ping()`` (a single ``SELECT 1``) for the DB check, NOT
    ``init_db()``. The latter issues ~15 DDL statements every call and
    can contend with concurrent scan writes for the SQLite write lock,
    causing the dashboard to falsely flip "Offline" mid-scan. Schema
    initialization is done once at startup; the readiness probe only
    needs to confirm the DB is currently reachable.
    """
    checks = {}

    try:
        from .database import db_ping

        await db_ping()
        checks["db"] = {"status": "ok"}
    except Exception as e:
        checks["db"] = {"status": "fail", "error": str(e)}

    try:
        from .scanners import ALL_SCANNERS

        checks["scanners"] = {"status": "ok", "count": len(ALL_SCANNERS)}
    except Exception as e:
        checks["scanners"] = {"status": "fail", "error": str(e)}

    all_ok = all(c.get("status") == "ok" for c in checks.values())
    payload = {"status": "ready" if all_ok else "not_ready", "checks": checks}

    if not all_ok:
        raise HTTPException(status_code=503, detail=payload)
    return payload
