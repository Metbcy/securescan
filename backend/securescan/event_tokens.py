"""Short-lived signed tokens for SSE auth.

Why this exists: ``EventSource`` (the browser API behind our live
scan-progress dashboard) cannot send custom headers like
``X-API-Key``. Without these tokens the FE has to either fall back
to 2-second polling in authenticated deployments or punch a hole in
the auth dependency for ``/events`` routes — both unacceptable.

Tokens are bound to ``(scan_id, key_id)`` so a revoked DB key cannot
keep an SSE stream alive past revocation: the verifier only proves
the token was minted by us, the auth dependency then rehydrates the
principal from ``key_id`` at connect time and re-checks the row's
``revoked_at``.

Format (URL-safe base64 of):

    ``<scan_id>|<key_id>|<expires_at>|<sig_b64>``

where ``sig`` is HMAC-SHA256(secret, "<scan_id>|<key_id>|<expires_at>").
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Tuple

TOKEN_TTL_SECONDS = 300

# Resolved at first use; lazy so tests can monkeypatch the env var
# between runs without having to reimport the module.
_signing_secret: Optional[bytes] = None
_signing_secret_ephemeral: bool = False


def _resolve_secret() -> bytes:
    """Resolve the signing secret.

    In auth-required mode this MUST be set explicitly via
    ``SECURESCAN_EVENT_TOKEN_SECRET`` — startup will have already
    raised ``SystemExit`` if it isn't. In dev/unauth mode we
    auto-generate an ephemeral 32-byte secret and let the caller
    log the warning (we stay import-time pure here).
    """
    global _signing_secret, _signing_secret_ephemeral
    if _signing_secret is not None:
        return _signing_secret
    raw = os.environ.get("SECURESCAN_EVENT_TOKEN_SECRET", "").strip()
    if raw:
        _signing_secret = raw.encode("utf-8")
        _signing_secret_ephemeral = False
    else:
        _signing_secret = secrets.token_bytes(32)
        _signing_secret_ephemeral = True
    return _signing_secret


def reset_for_tests() -> None:
    """Forget any cached secret so the next call re-reads the env.

    Tests that set/unset ``SECURESCAN_EVENT_TOKEN_SECRET`` between
    runs use this to avoid carrying ephemeral secrets across tests.
    """
    global _signing_secret, _signing_secret_ephemeral
    _signing_secret = None
    _signing_secret_ephemeral = False


@dataclass(frozen=True)
class TokenPayload:
    scan_id: str
    key_id: str  # "env" or DB key id
    expires_at: int  # unix seconds


def mint(
    scan_id: str, key_id: str, ttl_seconds: int = TOKEN_TTL_SECONDS
) -> Tuple[str, int]:
    """Mint a signed token bound to ``scan_id`` and ``key_id``.

    Returns ``(token, expires_in_seconds)``.
    """
    expires_at = int(time.time()) + ttl_seconds
    body = f"{scan_id}|{key_id}|{expires_at}".encode("utf-8")
    sig = hmac.new(_resolve_secret(), body, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=")
    token_bytes = body + b"|" + sig_b64
    token = base64.urlsafe_b64encode(token_bytes).rstrip(b"=").decode("ascii")
    return token, ttl_seconds


def verify(token: str) -> Optional[TokenPayload]:
    """Verify HMAC + expiry. Returns the bound payload on success.

    Does NOT check key revocation; the auth dependency must rehydrate
    the principal from ``payload.key_id`` and re-check its row state
    at connect time.
    """
    if not isinstance(token, str) or not token:
        return None
    try:
        decoded = base64.urlsafe_b64decode(_pad(token).encode("ascii"))
        scan_id_b, key_id_b, expires_at_b, sig_b = decoded.split(b"|", 3)
        scan_id = scan_id_b.decode("utf-8")
        key_id = key_id_b.decode("utf-8")
        expires_at = int(expires_at_b)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    body = f"{scan_id}|{key_id}|{expires_at}".encode("utf-8")
    expected = hmac.new(_resolve_secret(), body, hashlib.sha256).digest()
    expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=")
    if not hmac.compare_digest(sig_b, expected_b64):
        return None
    if expires_at < int(time.time()):
        return None
    return TokenPayload(scan_id=scan_id, key_id=key_id, expires_at=expires_at)


def _pad(s: str) -> str:
    return s + "=" * (-len(s) % 4)
