"""SecureScan ASGI middlewares (rate limiting, etc.).

Each middleware is implemented as a small starlette ``BaseHTTPMiddleware``
subclass and mounted from :mod:`securescan.main`.
"""
