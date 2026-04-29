from fastapi import HTTPException

from .api import app
from .api.scans import router as scans_router
from .api.dashboard import router as dashboard_router, browse_router
from .api.compliance import router as compliance_router
from .api.sbom import router as sbom_router
from .database import init_db

app.include_router(scans_router)
app.include_router(dashboard_router)
app.include_router(browse_router)
app.include_router(compliance_router)
app.include_router(sbom_router)


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
