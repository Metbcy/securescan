"""Baseline suppression.

Loads a JSON snapshot of previously-acknowledged findings and suppresses
any current finding whose ``fingerprint`` matches a baseline entry. This
lets teams adopt SecureScan on existing codebases without drowning in
legacy noise on the first PR.

The file format is intentionally permissive:

* ``[{"fingerprint": "abc..."}, ...]``  - flat list of fingerprint dicts
* ``{"findings": [...]}``                 - wrapped output of
  ``securescan scan --output json`` once SS2 lands the ``fingerprint``
  field on ``Finding``
* ``[{"fingerprint": "abc...", ...full finding dict...}]`` - also fine

Anything we can't extract a fingerprint from is silently skipped, so a
half-formed baseline never fails an entire run.

The fingerprint field itself is being added by SS2 (parallel branch).
This module reads it via ``getattr(finding, "fingerprint", "")`` so it
can land before SS2 without breaking import.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _extract_fingerprints(data) -> set[str]:
    """Pull fingerprints out of whatever shape the JSON happens to be."""
    fingerprints: set[str] = set()

    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]

    if not isinstance(data, list):
        return fingerprints

    for entry in data:
        if not isinstance(entry, dict):
            continue
        fp = entry.get("fingerprint")
        if isinstance(fp, str) and fp:
            fingerprints.add(fp)

    return fingerprints


def filter_against_baseline(findings: list, baseline_path: Path) -> tuple[list, int]:
    """Suppress findings whose fingerprint appears in the baseline file.

    Returns ``(kept_findings, suppressed_count)``.

    Failure modes are non-fatal: a missing or malformed file emits a
    warning to stderr and returns the original list unchanged with a
    suppressed count of 0. CI runs should not blow up because somebody
    deleted ``security-baseline.json``.
    """
    path = Path(baseline_path)

    if not path.exists():
        print(
            f"warning: baseline file not found: {path} (no findings suppressed)",
            file=sys.stderr,
        )
        return findings, 0

    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"warning: could not parse baseline file {path}: {exc} (no findings suppressed)",
            file=sys.stderr,
        )
        return findings, 0

    baseline_fingerprints = _extract_fingerprints(data)
    if not baseline_fingerprints:
        return findings, 0

    kept: list = []
    suppressed = 0
    for f in findings:
        fp = getattr(f, "fingerprint", "") or ""
        if fp and fp in baseline_fingerprints:
            suppressed += 1
            continue
        kept.append(f)

    return kept, suppressed
