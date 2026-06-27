"""Reachability classification for findings.

A finding's *reachability* answers the question a reviewer actually cares
about on a noisy scan: **is this vulnerable code (or dependency) actually
wired into something that runs?** A critical CVE in a transitive dependency
that nothing imports, or a Bandit hit in a file no entrypoint reaches, is
noise that drowns the findings that matter.

This module defines the vocabulary (the :class:`Reachability` verdict) and
the storage convention (a stamp inside ``Finding.metadata``). The actual
analysis lives in :mod:`securescan.reachability` -- this file is deliberately
dependency-free so the model layer can import it without pulling in any
analyzer machinery.

## Why ``metadata``, not a first-class ``Finding`` field

``Finding`` is ``model_dump``-ed by every exporter (SARIF, baseline JSON,
CLI, the dashboard API). ``models.py`` carries an explicit warning that
adding a field to bare ``Finding`` silently changes those JSON contracts.
Reachability is optional, best-effort, and not every scan computes it, so it
rides in the ``metadata`` escape hatch under a single reserved key. Exporters
that want it opt in by reading ``metadata['reachability']``; everyone else is
unchanged.
"""

from __future__ import annotations

from enum import Enum

# Reserved key under Finding.metadata where the verdict string is stamped.
REACHABILITY_KEY = "reachability"
# Reserved key under Finding.metadata holding the human-readable "why" string
# (e.g. "imported by securescan/main.py:12" or "no path from any entrypoint").
REACHABILITY_REASON_KEY = "reachability_reason"


class Reachability(str, Enum):
    """Verdict for whether a finding's code/dependency is reachable.

    String-valued so it serializes cleanly into ``metadata`` JSON and reads
    back without a custom decoder, matching the :class:`Severity` pattern.
    """

    # A path exists from a known entrypoint to the vulnerable symbol / the
    # dependency is in the import closure of something that runs.
    REACHABLE = "reachable"
    # Proven NOT wired in: dead code, an unimported dependency, a file no
    # entrypoint reaches. The high-value noise reduction case.
    UNREACHABLE = "unreachable"
    # Analysis ran but could not decide (dynamic import, reflection, a
    # language with no analyzer yet). Treated as REACHABLE for any gating
    # decision -- we never hide a finding on a guess.
    UNKNOWN = "unknown"


def get_reachability(metadata: dict) -> Reachability | None:
    """Read the reachability verdict stamped on a finding's ``metadata``.

    Returns ``None`` when no analyzer has run (the key is absent), which is
    distinct from :attr:`Reachability.UNKNOWN` (an analyzer ran and could not
    decide). Tolerates an unrecognized stored string by returning
    :attr:`Reachability.UNKNOWN` rather than raising, so a metadata blob
    written by a newer version never crashes an older reader.
    """

    raw = metadata.get(REACHABILITY_KEY)
    if raw is None:
        return None
    try:
        return Reachability(raw)
    except ValueError:
        return Reachability.UNKNOWN


def set_reachability(
    metadata: dict,
    verdict: Reachability,
    reason: str | None = None,
) -> None:
    """Stamp ``verdict`` (and optional ``reason``) onto ``metadata`` in place.

    Idempotent: re-stamping the same verdict is a no-op on the value. The
    reason is only written when provided so a bare verdict stamp does not
    clobber a previously-recorded explanation.
    """

    metadata[REACHABILITY_KEY] = verdict.value
    if reason is not None:
        metadata[REACHABILITY_REASON_KEY] = reason
