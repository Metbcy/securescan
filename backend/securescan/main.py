import logging

from .config_loader import load_user_env

# Load ~/.config/securescan/.env (or $XDG_CONFIG_HOME/securescan/.env)
# before any module that instantiates Settings is imported. Shell env
# always wins; a missing file is a silent no-op.
load_user_env()

from fastapi import Depends, HTTPException

from .api import app
from .api.scans import router as scans_router
from .api.dashboard import router as dashboard_router, browse_router
from .api.compliance import router as compliance_router
from .api.sbom import router as sbom_router
from .api.triage import router as triage_router
from .api.versioning import alias_router_at_v1
from .auth import is_dev_mode, require_api_key
from .database import init_db
from .middleware.rate_limit import RateLimitMiddleware

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
):
    app.include_router(_r, dependencies=_auth)
    # Parallel /api/v1/* mount — the preferred path going forward. Same
    # handlers, same models, single source of truth.
    alias_router_at_v1(app, _r, dependencies=_auth)


_logger = logging.getLogger(__name__)
if is_dev_mode():
    _logger.warning(
        "SECURESCAN_API_KEY not set; API is unauthenticated (dev mode)."
    )


@app.on_event("startup")
async def startup():
    await init_db()


@app.get("/ready", tags=["health"])
async def ready():
    """Readiness probe: returns 200 only when the app is fully ready
    to serve API traffic (database openable, scanner registry loaded).
    Returns 503 with details when not ready.
    """
    checks = {}

    try:
        await init_db()
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
