"""API versioning helpers.

SecureScan v0.6.0 introduces an `/api/v1/...` mount that mirrors the
existing `/api/...` routes. The legacy unprefixed paths continue to
work (back-compat for v0.5.0 CLIs, GitHub Actions, and dashboards) but
their responses now carry RFC 9745-style deprecation headers so callers
know where to migrate.

This module exposes two pieces:

* :func:`alias_router_at_v1` — given an existing `APIRouter` whose
  prefix is `/api/<area>`, register every route a second time on the
  app under `/api/v1/<area>/...`. The original router instance is left
  untouched; route handlers are shared (single source of truth).

* :class:`DeprecationHeaderMiddleware` — adds `Deprecation`, `Link`,
  and `Sunset` response headers to any request whose path begins with
  `/api/` but not `/api/v1/`.
"""
from __future__ import annotations

from typing import Optional, Sequence

from fastapi import APIRouter, FastAPI
from fastapi.params import Depends
from fastapi.routing import APIRoute
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


LEGACY_PREFIX = "/api"
V1_PREFIX = "/api/v1"

# One year out from the v0.6.0 release. Callers can rely on the legacy
# `/api/*` paths continuing to function up to (and almost certainly
# past) this date — the header just sets an upper bound for planning.
SUNSET_DATE = "Wed, 31 Dec 2026 23:59:59 GMT"


def alias_router_at_v1(
    app: FastAPI,
    router: APIRouter,
    *,
    dependencies: Optional[Sequence[Depends]] = None,
) -> None:
    """Mount a copy of ``router`` on ``app`` under ``/api/v1``.

    The router must already have a prefix of the form ``/api`` or
    ``/api/<area>``; the alias replaces the leading ``/api`` with
    ``/api/v1`` so handlers become reachable at both paths. Endpoint
    callables are shared, so OpenAPI lists each operation under both
    paths and any code change to a handler reflects everywhere.
    """
    if not (router.prefix == LEGACY_PREFIX or router.prefix.startswith(LEGACY_PREFIX + "/")):
        raise ValueError(
            f"router prefix must be '{LEGACY_PREFIX}' or start with "
            f"'{LEGACY_PREFIX}/', got {router.prefix!r}"
        )

    suffix = router.prefix[len(LEGACY_PREFIX):]  # "" or "/scans"
    v1_prefix = V1_PREFIX + suffix
    v1 = APIRouter(prefix=v1_prefix, tags=list(router.tags) if router.tags else None)

    for route in router.routes:
        if not isinstance(route, APIRoute):
            continue
        # route.path was baked with the original prefix at registration
        # time (e.g. "/api/scans/{scan_id}"); strip it back to the
        # router-relative subpath ("/{scan_id}") for re-registration.
        sub = route.path[len(router.prefix):]
        v1.add_api_route(
            sub,
            route.endpoint,
            response_model=route.response_model,
            status_code=route.status_code,
            tags=route.tags,
            dependencies=list(route.dependencies) if route.dependencies else None,
            summary=route.summary,
            description=route.description,
            response_description=route.response_description or "Successful Response",
            responses=route.responses,
            deprecated=route.deprecated,
            methods=list(route.methods or []),
            operation_id=None,
            response_model_include=route.response_model_include,
            response_model_exclude=route.response_model_exclude,
            response_model_by_alias=route.response_model_by_alias,
            response_model_exclude_unset=route.response_model_exclude_unset,
            response_model_exclude_defaults=route.response_model_exclude_defaults,
            response_model_exclude_none=route.response_model_exclude_none,
            include_in_schema=route.include_in_schema,
            response_class=route.response_class,
            name=f"v1_{route.name}" if route.name else None,
            callbacks=route.callbacks,
            openapi_extra=route.openapi_extra,
        )

    app.include_router(v1, dependencies=dependencies)


class DeprecationHeaderMiddleware(BaseHTTPMiddleware):
    """Tag legacy /api/* responses with deprecation metadata.

    Adds ``Deprecation: true``, a ``Link: rel="successor-version"``
    pointing at the matching ``/api/v1/...`` path, and a fixed
    ``Sunset`` date. Requests under ``/api/v1/`` and outside ``/api/``
    (``/health``, ``/ready``, ``/docs``, ``/openapi.json``, ``/``) pass
    through unchanged.
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if (
            path.startswith(LEGACY_PREFIX + "/")
            and not path.startswith(V1_PREFIX + "/")
            and not path == V1_PREFIX
        ):
            successor = V1_PREFIX + path[len(LEGACY_PREFIX):]
            response.headers["Deprecation"] = "true"
            response.headers["Link"] = f'<{successor}>; rel="successor-version"'
            response.headers["Sunset"] = SUNSET_DATE
        return response
