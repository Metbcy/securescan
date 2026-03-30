from .api import app
from .api.scans import router as scans_router
from .api.dashboard import router as dashboard_router
from .database import init_db

app.include_router(scans_router)
app.include_router(dashboard_router)


@app.on_event("startup")
async def startup():
    await init_db()
