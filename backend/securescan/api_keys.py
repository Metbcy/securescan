"""Hashed API key storage helpers (BE-AUTH-KEYS).

Plaintext keys live only at creation time on the response; the DB only
ever sees a salted SHA-256 hash. The stored hash is self-contained -
"<salt-hex>$<digest-hex>" - so we never need a separate salt column or
a runtime config knob to verify a key.

We rely on SHA-256 (not argon2/bcrypt) because the keys themselves are
192-bit random secrets - brute-forcing the hash is already infeasible
without a memory-hard KDF. Adding bcrypt here would buy nothing except
a hard dep and per-request CPU cost on the auth path.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import NamedTuple

KEY_PREFIX = "ssk_"
ID_LENGTH = 10  # base64url chars; ~60 bits
SECRET_LENGTH = 32  # base64url chars; ~192 bits

_HASH_SALT_BYTES = 16


class GeneratedKey(NamedTuple):
    """Output of :func:`generate_key`. ``full`` is the only value that
    must round-trip back to the caller; ``id`` and ``key_hash`` are what
    the DB persists, ``prefix`` is what the UI surfaces."""

    id: str  # 10-char base64url (no `-` or `_`)
    secret: str  # 32-char base64url
    full: str  # ssk_<id>_<secret>
    prefix: str  # full[:16] (id + 1 char of secret); safe to display
    key_hash: str  # "<salt-hex>$<sha256-hex>"


def generate_key() -> GeneratedKey:
    """Return a fresh random key.

    The id is 10 base64url chars (~60 bits); the secret is 32 base64url
    chars (~192 bits). Caller (CRUD layer) is responsible for catching
    the rare id collision via the DB's primary-key constraint and
    retrying generation.
    """
    # token_urlsafe(8) yields ~11 chars; trim to ID_LENGTH and substitute
    # `-` / `_` so the id can be parsed from the full key without the
    # separator (`_`) being ambiguous and without needing URL-escaping.
    id_ = secrets.token_urlsafe(8)[:ID_LENGTH].replace("-", "x").replace("_", "y")
    secret = secrets.token_urlsafe(24)[:SECRET_LENGTH]
    full = f"{KEY_PREFIX}{id_}_{secret}"
    return GeneratedKey(
        id=id_,
        secret=secret,
        full=full,
        prefix=full[:16],
        key_hash=_hash_key(full),
    )


def parse_key_id(provided: str) -> str | None:
    """Extract the id segment from ``ssk_<id>_<secret>``.

    Returns None on any malformed input (wrong prefix, missing
    separator, wrong id length). Used by the auth path so we can fetch
    the candidate row by id before doing a full hash compare.
    """
    if not isinstance(provided, str):
        return None
    if not provided.startswith(KEY_PREFIX):
        return None
    rest = provided[len(KEY_PREFIX) :]
    parts = rest.split("_", 1)
    if len(parts) != 2:
        return None
    if len(parts[0]) != ID_LENGTH:
        return None
    return parts[0]


def _hash_key(full: str) -> str:
    """Salted SHA-256. Salt is per-key, prepended to the digest output as
    ``<salt-hex>$<digest-hex>`` so the stored value is self-contained
    (no separate salt column required)."""
    salt = secrets.token_bytes(_HASH_SALT_BYTES)
    digest = hashlib.sha256(salt + full.encode("utf-8")).hexdigest()
    return f"{salt.hex()}${digest}"


def verify_key(full: str, stored: str) -> bool:
    """Constant-time compare. ``stored`` must be ``<salt-hex>$<digest-hex>``.

    Returns False (never raises) on malformed ``stored`` so a corrupt
    DB row reads as "wrong key" instead of crashing the auth path.
    """
    if not isinstance(full, str) or not isinstance(stored, str):
        return False
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except (ValueError, AttributeError):
        return False
    candidate = hashlib.sha256(salt + full.encode("utf-8")).hexdigest()
    # hmac.compare_digest gives constant-time equality on the fixed-
    # length hex digests (equivalent to comparing raw digest bytes).
    return hmac.compare_digest(candidate, digest_hex)
