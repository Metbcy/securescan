"""Severity threshold helper.

Pure-functional helpers for "fail-on-severity" style thresholding.

Extracted into its own module so that SS6's diff subcommand can reuse it
to count NEW findings only (vs. the current global behaviour where the
threshold counts every finding in the report).
"""

from __future__ import annotations

from .models import Severity

# Higher value = more severe. Mirrors the table in cli.py; kept local so
# callers don't have to import from cli.py (which has heavyweight imports).
SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def count_at_or_above(findings: list, threshold: Severity) -> int:
    """Return the number of findings whose severity is >= ``threshold``.

    ``findings`` is intentionally typed as ``list`` (not ``list[Finding]``)
    so callers can pass any duck-typed object exposing a ``severity``
    attribute. SS6's diff subcommand will pass a pre-filtered list of NEW
    findings into the same helper.
    """
    threshold_rank = SEVERITY_RANK.get(threshold, 0)
    count = 0
    for finding in findings:
        sev = getattr(finding, "severity", None)
        if sev is None:
            continue
        if SEVERITY_RANK.get(sev, 0) >= threshold_rank:
            count += 1
    return count
