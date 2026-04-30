"""Tests for the SSE event-token mint/verify path (BE-SSE-TOKEN).

EventSource cannot send X-API-Key, so authenticated deployments mint
a short-lived signed token (POST .../event-token), then attach it as
``?event_token=...`` on the SSE GET. These tests pin the helper-level
HMAC contract; the HTTP-level behaviour (rehydrate principal, reject
on revoked key, etc.) is exercised in ``test_sse.py``.
"""
from __future__ import annotations

import asyncio
import base64
import importlib
import time

import pytest

from securescan import auth, event_tokens


@pytest.fixture(autouse=True)
def _reset_signing_secret(monkeypatch):
    """Clear the cached secret so each test reads its own env var.

    The module-level ``_signing_secret`` is lazy and would otherwise
    carry an ephemeral secret (or a previous test's explicit one)
    across tests, masking real failures.
    """
    monkeypatch.setenv("SECURESCAN_EVENT_TOKEN_SECRET", "test-secret-A" * 4)
    event_tokens.reset_for_tests()
    yield
    event_tokens.reset_for_tests()


def test_mint_verify_round_trip():
    token, expires_in = event_tokens.mint("scan-1", "key-abc", ttl_seconds=60)
    assert expires_in == 60
    payload = event_tokens.verify(token)
    assert payload is not None
    assert payload.scan_id == "scan-1"
    assert payload.key_id == "key-abc"
    # Expiry stamped roughly now+ttl.
    assert abs(payload.expires_at - (int(time.time()) + 60)) <= 2


def test_verify_rejects_tampered_signature():
    token, _ = event_tokens.mint("scan-1", "key-abc")
    # Decode, flip a byte in the signature region, re-encode.
    raw = base64.urlsafe_b64decode(event_tokens._pad(token).encode())
    scan_id_b, key_id_b, expires_b, sig_b = raw.split(b"|", 3)
    flipped = bytearray(sig_b)
    flipped[0] = flipped[0] ^ 0x01
    forged_raw = b"|".join([scan_id_b, key_id_b, expires_b, bytes(flipped)])
    forged = base64.urlsafe_b64encode(forged_raw).rstrip(b"=").decode("ascii")

    assert event_tokens.verify(forged) is None


def test_verify_rejects_expired():
    # Negative TTL ⇒ already expired.
    token, _ = event_tokens.mint("scan-1", "key-abc", ttl_seconds=-1)
    assert event_tokens.verify(token) is None


def test_verify_rejects_garbage():
    assert event_tokens.verify("not_a_token") is None
    assert event_tokens.verify("") is None
    assert event_tokens.verify("???***") is None


def test_verify_rejects_tampered_payload():
    """Changing scan_id in the body without re-signing must fail.

    Pins the HMAC binding: a token can't be retargeted by an
    attacker who only sees the wire format.
    """
    token, _ = event_tokens.mint("scan-A", "key-abc")
    raw = base64.urlsafe_b64decode(event_tokens._pad(token).encode())
    _, key_id_b, expires_b, sig_b = raw.split(b"|", 3)
    forged_raw = b"|".join([b"scan-B", key_id_b, expires_b, sig_b])
    forged = base64.urlsafe_b64encode(forged_raw).rstrip(b"=").decode("ascii")

    assert event_tokens.verify(forged) is None


def test_signing_secret_required_when_auth_required(monkeypatch):
    """Startup helper must SystemExit when AUTH_REQUIRED=1 with no secret.

    Drives the helper directly (not the FastAPI startup hook) so the
    test stays a pure unit test.
    """
    monkeypatch.setenv(auth.AUTH_REQUIRED_ENV, "1")
    monkeypatch.delenv("SECURESCAN_EVENT_TOKEN_SECRET", raising=False)
    event_tokens.reset_for_tests()

    # Mirror the runtime check from main.startup.
    import os

    auth_required = auth._bool_env(auth.AUTH_REQUIRED_ENV)
    secret_set = bool(
        os.environ.get("SECURESCAN_EVENT_TOKEN_SECRET", "").strip()
    )
    assert auth_required is True
    assert secret_set is False

    # Reload main to trip its startup-time guard via direct call.
    main = importlib.import_module("securescan.main")
    importlib.reload(main)
    with pytest.raises(SystemExit) as exc:
        # Provide a valid env_key so the BE-AUTH-KEYS check passes
        # and the SECRET check is the one that fires.
        auth.assert_auth_credentials_configured(
            env_key="bootstrap", admin_db_count=0
        )
        # We have to run the real startup hook to hit the SECRET
        # check; do it via asyncio.run since it's an async function.
        asyncio.run(main.startup())
    assert exc.value.code == 2


def test_ephemeral_secret_warning_marker(monkeypatch):
    """When no secret is set, ``_resolve_secret`` flips the
    ``_signing_secret_ephemeral`` flag so the startup hook can WARN."""
    monkeypatch.delenv("SECURESCAN_EVENT_TOKEN_SECRET", raising=False)
    event_tokens.reset_for_tests()
    secret = event_tokens._resolve_secret()
    assert isinstance(secret, bytes) and len(secret) == 32
    assert event_tokens._signing_secret_ephemeral is True


def test_explicit_secret_marks_non_ephemeral(monkeypatch):
    monkeypatch.setenv("SECURESCAN_EVENT_TOKEN_SECRET", "operator-set-secret")
    event_tokens.reset_for_tests()
    event_tokens._resolve_secret()
    assert event_tokens._signing_secret_ephemeral is False


def test_reset_for_tests_clears_state(monkeypatch):
    monkeypatch.setenv("SECURESCAN_EVENT_TOKEN_SECRET", "first")
    event_tokens.reset_for_tests()
    s1 = event_tokens._resolve_secret()
    monkeypatch.setenv("SECURESCAN_EVENT_TOKEN_SECRET", "second")
    # Without reset, the cached value persists.
    assert event_tokens._resolve_secret() == s1
    event_tokens.reset_for_tests()
    s2 = event_tokens._resolve_secret()
    assert s2 == b"second"
