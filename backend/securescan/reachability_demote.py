"""Severity demotion for unreachable findings.

When ``[reachability] demote_unreachable = true``, a finding the analyzer
proved :attr:`~securescan.reachability_model.Reachability.UNREACHABLE` has its
severity lowered by one step before scoring and the fail-on gate. This is the
mechanism that lets reachability change the *ranking* of the NEW-findings PR
comment without ever hiding a finding: an unreachable critical becomes a high
(still shown, just not leading the list), while a reachable critical stays
critical and a finding we could not classify (UNKNOWN / unstamped) is never
touched.

The demotion is recorded in ``metadata`` (original severity + reason) so the
dashboard and audit trail can show "demoted critical -> high: unreachable",
mirroring how ``severity.py`` stamps its overrides.
"""

from __future__ import annotations

from .models import Finding, Severity
from .reachability_model import Reachability, get_reachability

# Ordered most-severe to least. Demotion moves one step toward the end; INFO is
# the floor (an unreachable INFO stays INFO).
_LADDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

# metadata keys for the audit stamp (namespaced to avoid colliding with the
# severity-override stamp written by severity.py).
_DEMOTED_FROM_KEY = "reachability_demoted_from"


def _one_step_down(sev: Severity) -> Severity:
    idx = _LADDER.index(sev)
    return _LADDER[min(idx + 1, len(_LADDER) - 1)]


def demote_unreachable_findings(findings: list[Finding]) -> int:
    """Lower the severity of every UNREACHABLE finding by one step, in place.

    Only findings explicitly stamped :attr:`Reachability.UNREACHABLE` are
    affected. REACHABLE, UNKNOWN, and unstamped findings (verdict ``None``) are
    left exactly as-is, honoring the never-hide-on-a-guess contract.

    Idempotent: a finding already carrying the ``reachability_demoted_from``
    stamp is skipped, so a second pipeline pass does not demote it twice.

    Returns:
        The number of findings whose severity was lowered on this call.
    """

    demoted = 0
    for finding in findings:
        if get_reachability(finding.metadata) is not Reachability.UNREACHABLE:
            continue
        if _DEMOTED_FROM_KEY in finding.metadata:
            continue  # already demoted on a prior pass; stay idempotent
        original = finding.severity
        lowered = _one_step_down(original)
        if lowered == original:
            # Already at the floor (INFO); record the stamp anyway so the audit
            # trail shows the demotion was considered, and stay idempotent.
            finding.metadata[_DEMOTED_FROM_KEY] = original.value
            continue
        finding.severity = lowered
        finding.metadata[_DEMOTED_FROM_KEY] = original.value
        demoted += 1
    return demoted
