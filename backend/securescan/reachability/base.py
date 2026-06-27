"""Reachability analyzer interface and shared analysis context.

Kept separate from ``__init__`` so concrete analyzers import only the ABC and
the context, never the registry (which would be a circular import).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding
from ..reachability_model import Reachability


@dataclass
class AnalysisContext:
    """Per-scan shared state handed to every analyzer.

    Built once per :func:`securescan.reachability.analyze` call so an analyzer
    that constructs an expensive artifact (import graph, call graph, entrypoint
    set) can cache it here across the many findings it classifies, rather than
    rebuilding per finding.

    Attributes:
        target_path: Resolved project root. All file paths an analyzer reasons
            about are relative to (or under) this.
        cache: Free-form per-analyzer scratch space. An analyzer keys its built
            graph under its own name, e.g.
            ``ctx.cache.setdefault("python_imports", build_graph(...))``.
    """

    target_path: Path
    cache: dict = field(default_factory=dict)


class ReachabilityAnalyzer(ABC):
    """Base class for a language- / ecosystem-specific reachability analyzer.

    Lifecycle per scan:
      1. The registry instance is reused across scans; keep instances stateless
         (all per-scan state belongs in :class:`AnalysisContext`).
      2. ``analyze`` calls :meth:`claims` to route each finding.
      3. For claimed findings it calls :meth:`classify`.
    """

    #: Human-readable analyzer name, also the suggested ``ctx.cache`` key.
    name: str = "base"

    @abstractmethod
    def claims(self, finding: Finding) -> bool:
        """Return True if this analyzer can reason about ``finding``.

        Should be cheap (look at ``finding.scanner`` / ``scan_type`` /
        ``file_path`` suffix). The first registry analyzer to claim a finding
        owns it, so be specific: a Python analyzer claims ``.py`` findings, not
        everything.
        """

    @abstractmethod
    def classify(
        self, finding: Finding, ctx: AnalysisContext
    ) -> tuple[Reachability, str | None]:
        """Decide reachability for a claimed ``finding``.

        Returns ``(verdict, reason)`` where ``reason`` is a short
        human-readable explanation ("imported by app/main.py", "no path from
        any entrypoint", "dynamic import, cannot decide") surfaced in the UI
        and PR comment. Return :attr:`Reachability.UNKNOWN` whenever the
        analysis is inconclusive -- never guess UNREACHABLE, because that hides
        a finding.

        Must not raise for expected "cannot analyze" cases (return UNKNOWN
        instead); the dispatcher catches unexpected exceptions but relying on
        that is a code smell.
        """
