"""Time helpers for deterministic output rendering.

Production code paths use ``datetime.utcnow()``; tests and reproducible CI
runs can pin the wall clock by setting ``SECURESCAN_FAKE_NOW`` to an ISO
8601 timestamp (e.g. ``2026-01-01T00:00:00``). This is intentionally
opt-in so live scans still record real wall-clock times.
"""
from __future__ import annotations

import os
from datetime import datetime


def now_for_output() -> datetime:
    """Return the wall clock to embed in rendered output.

    Honors ``SECURESCAN_FAKE_NOW`` (ISO 8601, optional trailing ``Z``) when
    set; otherwise returns ``datetime.utcnow()``. Use this anywhere a
    timestamp would otherwise leak into a serialized artifact (SARIF,
    CycloneDX, SPDX, HTML report, etc.) where byte-identical re-renders
    matter.
    """
    fake = os.environ.get("SECURESCAN_FAKE_NOW")
    if fake:
        return datetime.fromisoformat(fake.rstrip("Z"))
    return datetime.utcnow()
