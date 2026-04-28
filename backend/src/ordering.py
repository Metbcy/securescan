"""Canonical ordering for findings.

Every renderer (SARIF, CSV, JUnit, JSON, HTML, terminal, PR comment) must
emit findings in the same order so that re-runs against the same logical
inputs produce byte-identical output. Byte-identical output is what makes:

* PR-comment upsert work without churn (the same comment body hashes the
  same and the bot doesn't post a new comment),
* SARIF re-uploads to GitHub's code-scanning Security tab not produce
  false "new alert" noise.

The canonical key is intentionally built from fields that already exist
on ``Finding`` today; SS2 is adding a stable ``fingerprint`` field in
parallel and may chain it on as a tiebreaker post-merge if useful.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .models import Severity

if TYPE_CHECKING:
    from .models import Finding


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def severity_rank(sev: Severity) -> int:
    """Return numeric severity rank (higher = more severe)."""
    return _SEVERITY_RANK.get(sev, -1)


def _canonical_key(f: "Finding") -> tuple:
    """Sort key: severity desc, then file, line, rule_id, title (all asc)."""
    return (
        -severity_rank(f.severity),
        f.file_path or "",
        f.line_start or 0,
        f.rule_id or "",
        f.title or "",
    )


def sort_findings_canonical(findings: list["Finding"]) -> list["Finding"]:
    """Return a new list of findings ordered by the canonical key.

    Order: severity desc (critical first), then file_path asc, then
    line_start asc, then rule_id asc, then title asc. Missing optional
    fields (``file_path``, ``line_start``, ``rule_id``) collate as the
    empty string / zero so the sort is total and stable for any input.

    Pure function: does not mutate the input list. Python's ``sorted``
    is guaranteed stable since 3.7, so equal-keyed findings retain
    their relative input order across calls.
    """
    return sorted(findings, key=_canonical_key)
