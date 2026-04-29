"""Hidden HTML markers for upserting per-finding inline review comments.

GitHub's PR Reviews API does not give us a way to attach SecureScan-
specific metadata to a comment. We work around this by embedding a
short hidden HTML comment in each review-comment body:

    <!-- securescan:fp:<12-hex-char-prefix> -->

On re-runs, the action's post-review.sh GETs all existing review
comments authored by github-actions[bot], extracts the marker prefixes,
and decides per-finding whether to PATCH (upsert), CREATE (new), or
reply with "Fixed in <sha>" (gone).

The 12-char prefix is enough collision resistance for per-PR scope
(~280T combinations); the full sha256 fingerprint is logically the
identity but not user-visible.
"""
from __future__ import annotations

import re

FINGERPRINT_PREFIX_LEN = 12

_MARKER_PREFIX = "<!-- securescan:fp:"
_MARKER_SUFFIX = " -->"
_MARKER_RE = re.compile(
    r"<!--\s*securescan:fp:\s*([0-9a-f]+)\s*-->",
    re.IGNORECASE,
)
_HEX_RE = re.compile(r"^[0-9a-f]+$")


def fingerprint_prefix(fingerprint: str) -> str:
    """Return the canonical 12-char prefix for the marker.

    Lowercased. Raises ValueError on too-short or non-hex input.
    """
    if not isinstance(fingerprint, str):
        raise ValueError(
            f"fingerprint must be a string, got {type(fingerprint).__name__}"
        )
    normalized = fingerprint.lower()
    if len(normalized) < FINGERPRINT_PREFIX_LEN:
        raise ValueError(
            f"fingerprint must be at least {FINGERPRINT_PREFIX_LEN} hex chars, "
            f"got {len(normalized)}"
        )
    if not _HEX_RE.match(normalized):
        raise ValueError(
            "fingerprint must be hexadecimal (0-9, a-f)"
        )
    return normalized[:FINGERPRINT_PREFIX_LEN]


def add_fingerprint_marker(body: str, fingerprint: str) -> str:
    """Append the marker to the body. Idempotent.

    If a marker for the same fingerprint is already present, returns the
    body unchanged. If the body already carries any marker (even for a
    different fingerprint), it is preserved and no second marker is
    appended; for v0.4 we never want two fingerprints in one body. A
    blank-line separator is inserted before the marker for readability
    when the body has prior content.
    """
    prefix = fingerprint_prefix(fingerprint)
    if extract_fingerprint(body) is not None:
        return body

    marker = f"{_MARKER_PREFIX}{prefix}{_MARKER_SUFFIX}"
    if body == "":
        return marker
    if body.endswith("\n\n"):
        separator = ""
    elif body.endswith("\n"):
        separator = "\n"
    else:
        separator = "\n\n"
    return f"{body}{separator}{marker}"


def extract_fingerprint(body: str) -> str | None:
    """Extract the FIRST fingerprint marker prefix, or None.

    Returns the prefix as lowercase hex (no ``<!--``/``-->`` wrapper).
    Callers should not have multiple markers in one body; if they do,
    only the first is returned.
    """
    if not body:
        return None
    match = _MARKER_RE.search(body)
    if match is None:
        return None
    return match.group(1).lower()


def has_fingerprint(body: str, fingerprint: str) -> bool:
    """True if the body carries a marker matching the given fingerprint.

    Compares the canonical 12-char prefix.
    """
    return extract_fingerprint(body) == fingerprint_prefix(fingerprint)


def strip_fingerprint_markers(body: str) -> str:
    """Remove ALL fingerprint markers from the body.

    Useful when posting a body that should not carry SecureScan
    identity (e.g., a user-facing review-summary body), or when
    computing the user-visible portion of a body for diffing across
    re-runs.
    """
    if not body:
        return body
    stripped = _MARKER_RE.sub("", body)
    stripped = re.sub(r"[ \t]+(\n|$)", r"\1", stripped)
    stripped = re.sub(r"\n{3,}", "\n\n", stripped)
    return stripped.rstrip("\n") + ("\n" if body.endswith("\n") else "")
