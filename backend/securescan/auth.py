"""Optional API key auth.

When the SECURESCAN_API_KEY env var is set, every /api/* endpoint
requires `X-API-Key: <key>` (or `Authorization: Bearer <key>`) on
the request. When unset (dev mode), the dependency returns None and
no header is required - startup logs a clear WARN so users see
that the API is unauthenticated.

/health and /ready remain public regardless of auth state (Kubernetes
probes etc. don't carry headers).
"""
from __future__ import annotations

import os
import secrets
from typing import Optional

from fastapi import HTTPException, Request, status
from fastapi.security.utils import get_authorization_scheme_param

ENV_VAR = "SECURESCAN_API_KEY"


def get_configured_key() -> Optional[str]:
    """Read the API key from env. Returns None when unset (dev mode)."""
    key = os.environ.get(ENV_VAR, "")
    return key.strip() or None


def is_dev_mode() -> bool:
    return get_configured_key() is None


def _extract_provided_key(request: Request) -> Optional[str]:
    """Extract the caller's key from X-API-Key or Authorization: Bearer."""
    direct = request.headers.get("X-API-Key", "").strip()
    if direct:
        return direct
    auth = request.headers.get("Authorization", "")
    scheme, param = get_authorization_scheme_param(auth)
    if scheme.lower() == "bearer" and param:
        return param.strip()
    return None


async def require_api_key(request: Request) -> Optional[str]:
    """FastAPI dependency: enforce the configured API key when set.

    Returns the key on success (so handlers can log a hash if needed),
    or None in dev mode. Raises 401 when configured key is set but
    missing or wrong.
    """
    configured = get_configured_key()
    if configured is None:
        return None
    provided = _extract_provided_key(request)
    if provided is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not secrets.compare_digest(provided, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return provided
