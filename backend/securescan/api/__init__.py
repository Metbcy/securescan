import logging
import os
import time
import uuid

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from ..logging_config import configure_logging

configure_logging()

_request_logger = logging.getLogger("securescan.request")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Assign a request id to every request, expose it on the response,
    and emit a single structured log line per request."""

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
            _request_logger.exception(
                "request",
                extra={
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status": 500,
                    "latency_ms": latency_ms,
                },
            )
            raise
        latency_ms = round((time.perf_counter() - started) * 1000.0, 2)
        response.headers["X-Request-ID"] = request_id
        _request_logger.info(
            "request",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "latency_ms": latency_ms,
            },
        )
        return response


app = FastAPI(
    title="SecureScan",
    version="0.1.0",
    description="AI-powered security scanner",
)

allowed_origins = os.environ.get(
    "SECURESCAN_CORS_ORIGINS",
    "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3003,http://127.0.0.1:3003",
).split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestLoggingMiddleware)


@app.get("/")
async def root():
    return {
        "name": "SecureScan API",
        "status": "ok",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
