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
