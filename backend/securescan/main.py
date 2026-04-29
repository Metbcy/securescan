import logging

from fastapi import Depends, HTTPException

from .api import app
from .api.scans import router as scans_router
from .api.dashboard import router as dashboard_router, browse_router
from .api.compliance import router as compliance_router
from .api.sbom import router as sbom_router
from .auth import is_dev_mode, require_api_key
from .database import init_db

_auth = [Depends(require_api_key)]

app.include_router(scans_router, dependencies=_auth)
app.include_router(dashboard_router, dependencies=_auth)
app.include_router(browse_router, dependencies=_auth)
app.include_router(compliance_router, dependencies=_auth)
app.include_router(sbom_router, dependencies=_auth)


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
