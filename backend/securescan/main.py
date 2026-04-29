import logging

from fastapi import Depends

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
