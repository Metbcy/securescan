"""Reachability analyzers.

An *analyzer* takes a set of findings plus the project root and decides, for
each finding it understands, whether the vulnerable code or dependency is
reachable from a known entrypoint. Analyzers are language- / ecosystem-
specific and best-effort: anything they cannot decide stays
:attr:`~securescan.reachability_model.Reachability.UNKNOWN`, which never
hides a finding.

The public entrypoint is :func:`analyze`, which dispatches each finding to
the registered analyzer that claims it and stamps the verdict onto
``finding.metadata`` via :func:`securescan.reachability_model.set_reachability`.

## Design

* :class:`ReachabilityAnalyzer` is the ABC every analyzer implements.
* Analyzers register in :data:`_REGISTRY` (ordered; first ``claims()`` wins).
* :func:`analyze` is the single call site the pipeline uses. It is pure
  orchestration: build the shared :class:`AnalysisContext` once (so an
  analyzer that walks the import graph does it a single time, not per
  finding), then route findings.

The heavy lifting (import-closure walking, call-graph construction) lives in
the concrete analyzers under this package. They are intentionally separable
so a contributor can add a Go or JS analyzer without touching the dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..models import Finding
from ..reachability_model import Reachability, set_reachability
from .base import AnalysisContext, ReachabilityAnalyzer
from .python_imports import PythonImportClosureAnalyzer

# Ordered registry. The first analyzer whose ``claims(finding)`` returns True
# owns the finding. Keep most-specific analyzers first. New languages append
# here (and ship their module alongside).
_REGISTRY: list[ReachabilityAnalyzer] = [
    PythonImportClosureAnalyzer(),
]


@dataclass
class AnalysisResult:
    """Summary of an :func:`analyze` pass, for logging / dashboard surfacing.

    Attributes:
        analyzed: Findings an analyzer claimed and stamped a verdict on.
        reachable / unreachable / unknown: Per-verdict counts among the
            claimed findings.
        skipped: Findings no analyzer claimed (left untouched, no stamp).
    """

    analyzed: int = 0
    reachable: int = 0
    unreachable: int = 0
    unknown: int = 0
    skipped: int = 0


def analyze(
    findings: list[Finding],
    *,
    target_path: Path,
    enabled: bool = True,
) -> AnalysisResult:
    """Stamp a reachability verdict onto each finding an analyzer can claim.

    Mutates ``findings`` in place (stamping ``metadata['reachability']``).
    Findings no analyzer understands are left without a stamp, which a reader
    distinguishes from UNKNOWN via
    :func:`securescan.reachability_model.get_reachability` returning ``None``.

    Parameters:
        findings: Findings from the scan, already fingerprinted.
        target_path: Project root the analyzers root their graphs at.
        enabled: Master switch. When False this is a no-op returning an empty
            result -- the pipeline passes ``config.reachability.enabled``.

    Returns:
        An :class:`AnalysisResult` with per-verdict counts.

    Contract:
        * Never raises on a single analyzer failure. An analyzer that throws
          is caught, its findings fall through to the next claimant, and any
          still-unclaimed finding is simply left unstamped. Reachability is a
          best-effort signal; it must never fail a scan.
        * Idempotent: re-running on an already-stamped set recomputes and
          overwrites, producing the same verdicts for the same inputs.
    """

    result = AnalysisResult()
    if not enabled or not findings:
        result.skipped = len(findings)
        return result

    ctx = AnalysisContext(target_path=Path(target_path).resolve())

    for finding in findings:
        analyzer = _claimant(finding)
        if analyzer is None:
            result.skipped += 1
            continue
        try:
            verdict, reason = analyzer.classify(finding, ctx)
        except Exception:  # noqa: BLE001 - best-effort, never fail a scan
            # An analyzer blew up on this finding; treat as UNKNOWN so the
            # finding is never silently hidden, and keep going.
            verdict, reason = Reachability.UNKNOWN, "analyzer error"
        set_reachability(finding.metadata, verdict, reason)
        result.analyzed += 1
        _tally(result, verdict)

    return result


def _claimant(finding: Finding) -> ReachabilityAnalyzer | None:
    for analyzer in _REGISTRY:
        try:
            if analyzer.claims(finding):
                return analyzer
        except Exception:  # noqa: BLE001 - a broken claim() must not crash dispatch
            continue
    return None


def _tally(result: AnalysisResult, verdict: Reachability) -> None:
    if verdict is Reachability.REACHABLE:
        result.reachable += 1
    elif verdict is Reachability.UNREACHABLE:
        result.unreachable += 1
    else:
        result.unknown += 1


__all__ = [
    "AnalysisContext",
    "AnalysisResult",
    "ReachabilityAnalyzer",
    "analyze",
]
