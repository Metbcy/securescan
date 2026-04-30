"""In-memory token-bucket rate limiter for POST /api/scans (FEAT3).

Applied only to ``POST /api/scans`` and ``POST /api/v1/scans`` -- the
read-heavy endpoints (list scans, get findings, dashboard, sbom...) are
intentionally not rate-limited because they are cheap to serve and the
real abuse vector is "kick off lots of expensive scanner runs".

Identity for the bucket key is, in order:

1. ``X-API-Key`` request header (so each issued key gets its own quota).
2. ``request.client.host`` (dev mode, unauthenticated callers).
3. The literal string ``"anonymous"`` if neither is available.

Configurable via env vars:

- ``SECURESCAN_RATE_LIMIT_PER_MIN`` (default ``60``) -- sustained rate.
- ``SECURESCAN_RATE_LIMIT_BURST``   (default ``10``) -- burst capacity.
- ``SECURESCAN_RATE_LIMIT_ENABLED`` (default ``true``) -- on/off switch.

Bucket capacity is ``max(per_min, burst)`` so that the per-minute rate
is always honored as a floor and ``burst`` raises capacity for short
spikes when ``burst > per_min``.

Bounded memory: LRU eviction past 10K live buckets and a 1h idle TTL,
checked opportunistically on each request so the limiter never grows
unbounded under a key-rotation or DoS pattern.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import re
import time
from collections import OrderedDict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("securescan.ratelimit")

_SCANS_POST_PATH = re.compile(r"^/api(?:/v1)?/scans/?$")

_MAX_BUCKETS = 10_000
_IDLE_TTL_SECONDS = 3600.0


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        logger.warning("invalid int for %s=%r, using default %d", name, raw, default)
        return default
    return value if value > 0 else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in {"0", "false", "no", "off", ""}


class RateLimiter:
    """Token-bucket limiter shared across requests.

    Concurrency-safe via a single :class:`asyncio.Lock`; the critical
    section is O(1) so contention is negligible compared to the actual
    scan work that follows.
    """

    def __init__(self, per_min: int, burst: int) -> None:
        self.per_min = max(1, int(per_min))
        self.burst = max(1, int(burst))
        # Bucket capacity is the larger of the two so a fresh client can
        # always do at least ``per_min`` requests in the first minute,
        # even if ``burst`` was set lower.
        self.capacity = float(max(self.per_min, self.burst))
        self.refill_per_sec = self.per_min / 60.0
        # OrderedDict gives us O(1) LRU semantics: move_to_end on access,
        # popitem(last=False) to evict the oldest.
        self._buckets: OrderedDict[str, list[float]] = OrderedDict()
        self._lock = asyncio.Lock()

    @property
    def limit_per_min(self) -> int:
        return self.per_min

    async def acquire(self, key: str) -> tuple[bool, float, float, float]:
        """Try to consume one token for *key*.

        Returns ``(allowed, remaining, retry_after_sec, reset_at)``.

        ``reset_at`` is a unix timestamp at which a new token will be
        available (i.e., the bucket will hold at least 1 token). When
        the bucket already has tokens the caller still gets a meaningful
        reset value -- the time at which the bucket would refill back to
        full -- so dashboards that show "X-RateLimit-Reset" make sense.
        """
        async with self._lock:
            now = time.monotonic()
            self._evict_expired(now)

            tokens, last_refill = self._buckets.get(key, (self.capacity, now))
            elapsed = max(0.0, now - last_refill)
            tokens = min(self.capacity, tokens + elapsed * self.refill_per_sec)

            if tokens >= 1.0:
                tokens -= 1.0
                allowed = True
                retry_after = 0.0
            else:
                allowed = False
                deficit = 1.0 - tokens
                retry_after = (
                    deficit / self.refill_per_sec if self.refill_per_sec > 0 else float("inf")
                )

            self._buckets[key] = [tokens, now]
            self._buckets.move_to_end(key)

            while len(self._buckets) > _MAX_BUCKETS:
                self._buckets.popitem(last=False)

            now_wall = time.time()
            seconds_to_full_token = 0.0 if tokens >= 1.0 else (1.0 - tokens) / self.refill_per_sec
            reset_at = now_wall + seconds_to_full_token
            remaining = math.floor(tokens)

        return allowed, float(remaining), retry_after, reset_at

    def _evict_expired(self, now: float) -> None:
        """Drop buckets idle for >1h. O(N) only when oldest is stale; we
        stop as soon as we hit a fresh entry because OrderedDict
        preserves insertion-by-recency order."""
        ttl = _IDLE_TTL_SECONDS
        while self._buckets:
            oldest_key = next(iter(self._buckets))
            _tokens, last_seen = self._buckets[oldest_key]
            if (now - last_seen) <= ttl:
                break
            self._buckets.popitem(last=False)


def _build_limiter() -> RateLimiter | None:
    if not _env_bool("SECURESCAN_RATE_LIMIT_ENABLED", True):
        return None
    per_min = _env_int("SECURESCAN_RATE_LIMIT_PER_MIN", 60)
    burst = _env_int("SECURESCAN_RATE_LIMIT_BURST", 10)
    return RateLimiter(per_min=per_min, burst=burst)


def _identity(request: Request) -> str:
    api_key = request.headers.get("x-api-key")
    if api_key and api_key.strip():
        return f"key:{api_key.strip()}"
    if request.client and request.client.host:
        return f"ip:{request.client.host}"
    return "anonymous"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate-limit POST /api/scans (and /api/v1/scans).

    The limiter is rebuilt only when the relevant env vars actually
    change -- this lets tests use ``monkeypatch.setenv`` without paying
    the cost in production where env vars are stable.
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        self._limiter: RateLimiter | None = _build_limiter()
        self._snapshot = self._config_snapshot()

    @staticmethod
    def _config_snapshot() -> tuple[str, str, str]:
        return (
            os.environ.get("SECURESCAN_RATE_LIMIT_ENABLED", ""),
            os.environ.get("SECURESCAN_RATE_LIMIT_PER_MIN", ""),
            os.environ.get("SECURESCAN_RATE_LIMIT_BURST", ""),
        )

    def _current_limiter(self) -> RateLimiter | None:
        snapshot = self._config_snapshot()
        if snapshot != self._snapshot:
            self._limiter = _build_limiter()
            self._snapshot = snapshot
        return self._limiter

    @staticmethod
    def _is_rate_limited_route(request: Request) -> bool:
        if request.method != "POST":
            return False
        return bool(_SCANS_POST_PATH.match(request.url.path))

    async def dispatch(self, request: Request, call_next):
        limiter = self._current_limiter()

        if limiter is None or not self._is_rate_limited_route(request):
            return await call_next(request)

        key = _identity(request)
        allowed, remaining, retry_after, reset_at = await limiter.acquire(key)

        limit_header = str(limiter.limit_per_min)
        reset_header = str(int(reset_at))

        if not allowed:
            retry_seconds = max(1, int(math.ceil(retry_after)))
            logger.info(
                "rate_limit_block",
                extra={
                    "path": request.url.path,
                    "method": request.method,
                    "client": key,
                },
            )
            response: Response = JSONResponse(
                status_code=429,
                content={
                    "detail": "Rate limit exceeded",
                    "retry_after": retry_seconds,
                    "limit_per_min": limiter.limit_per_min,
                },
            )
            response.headers["Retry-After"] = str(retry_seconds)
            response.headers["X-RateLimit-Limit"] = limit_header
            response.headers["X-RateLimit-Remaining"] = "0"
            response.headers["X-RateLimit-Reset"] = reset_header
            return response

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = limit_header
        response.headers["X-RateLimit-Remaining"] = str(int(remaining))
        response.headers["X-RateLimit-Reset"] = reset_header
        return response


__all__ = ["RateLimiter", "RateLimitMiddleware"]
