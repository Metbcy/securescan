"""End-to-end finding pipeline used by ``scan``, ``diff``, and ``compare``.

Each CLI subcommand calls :func:`apply_pipeline` after running scanners
and before rendering. This function:

  1. Loads the ``.securescan.yml`` (walks up from ``target_path``).
  2. Applies fingerprints (idempotent).
  3. Applies severity overrides from config.
  4. Builds :class:`SuppressionContext` from
     ``(config, baseline_path, no_suppress)``.
  5. Partitions findings into ``(kept, suppressed)`` -- both lists,
     with ``metadata['suppressed_by']`` stamped on the suppressed ones.
  6. Returns a :class:`PipelineResult` (kept, suppressed, config,
     ``found_config_path``, ``severity_overrides_applied``).

The renderers consume both ``kept`` and ``suppressed``; how they
display is their concern (TS6 already wired the ``show_suppressed``
flag through every renderer).

Why a single helper?
--------------------
Before TS10 every CLI subcommand wired its own ad-hoc subset of the
v0.3.0 pipeline (some called :func:`populate_fingerprints`, others
ran :func:`filter_against_baseline`, none had config or inline
suppression). That fragmentation is exactly what made each new
trust-and-signal-quality flag a multi-call-site change. The single
``apply_pipeline`` helper pins the integration order so a future
contributor can read one function to understand "what happens to a
finding between scan and render".

Backward compatibility invariant
--------------------------------
A project with **no** ``.securescan.yml``, **no** ``--baseline`` and
**no** inline ``# securescan: ignore`` directives produces exactly
the same ``kept`` set as the v0.2.0 pipeline produced before
suppression existed: defaults are empty, ``apply`` returns
``(findings, [])``, and fingerprints were already populated by every
v0.2.0 entrypoint. Switching ``filter_against_baseline`` to
``apply_pipeline(baseline_path=...)`` widens the audit trail
(suppressed findings now carry a ``suppressed_by`` stamp instead of
disappearing) but does not change what reaches a non-``--show-
suppressed`` renderer.

AI gate precedence (informational; lives in :mod:`cli`)
-------------------------------------------------------
The pipeline does not own the AI gate, but the three-tier precedence
that consumes ``config.ai`` deserves to be documented next to the
other v0.3.0 plumbing:

* CLI ``--ai`` / ``--no-ai``  (highest)  -> True / False
* config ``ai: true|false``   (middle)   -> True / False
* CI env auto-detect          (default)  -> False on CI, True off CI
  (or False unconditionally for diff/compare; see ``cli.py``).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config_file import SecureScanConfig, load_config
from .fingerprint import populate_fingerprints
from .models import Finding
from .severity import apply_severity_overrides
from .suppression import SuppressionContext


@dataclass(frozen=True)
class PipelineResult:
    """Bundle of every observable the pipeline produces.

    Attributes:
        kept: Findings that should be rendered as-is. Suppression has
            *not* removed them; renderers display them normally.
        suppressed: Findings that any of the suppression mechanisms
            (inline / config / baseline) removed from the
            user-visible default. Each carries
            ``metadata['suppressed_by']`` set to the precedence
            reason (``"inline"`` / ``"config"`` / ``"baseline"``).
            Renderers display them only when ``show_suppressed=True``.
        config: The fully-resolved :class:`SecureScanConfig` used by
            the run. ``semgrep_rules`` are absolute paths.
        found_config_path: Absolute path of the discovered
            ``.securescan.yml`` (or ``None`` when none was found / a
            caller-supplied config was used).
        severity_overrides_applied: Number of findings whose severity
            (or audit stamp) was written by the override pass during
            this call. Excludes idempotent re-applies (see
            :func:`securescan.severity.apply_severity_overrides`).
    """

    kept: list[Finding]
    suppressed: list[Finding]
    config: SecureScanConfig
    found_config_path: Path | None
    severity_overrides_applied: int


def apply_pipeline(
    findings: list[Finding],
    *,
    target_path: Path,
    baseline_path: Path | None = None,
    no_suppress: bool = False,
    config: SecureScanConfig | None = None,
    config_search_start: Path | None = None,
) -> PipelineResult:
    """Run the post-scan pipeline against ``findings``.

    Order of operations is fixed (see module docstring):
    ``load config -> fingerprints -> severity overrides -> suppression``.

    Parameters:
        findings: Findings produced by scanners. Mutated in place
            (fingerprints + severity overrides + suppression stamps).
        target_path: Project root used as the default config search
            start and as the path-resolution base for relative
            ``semgrep_rules`` when no config file is found.
        baseline_path: Optional path to a baseline JSON file. When
            present, findings whose fingerprint matches a baseline
            entry land in ``suppressed`` with
            ``suppressed_by == "baseline"``.
        no_suppress: When True, every finding lands in ``kept``
            regardless of inline / config / baseline matches and no
            ``suppressed_by`` metadata is stamped. Mirrors the CLI
            ``--no-suppress`` kill switch.
        config: Optional pre-loaded, **already path-resolved**
            :class:`SecureScanConfig`. When provided, the pipeline
            skips the disk load (used by both the CLI -- which loads
            once for the AI gate + scanner kwargs -- and tests).
            ``found_config_path`` on the result will be ``None``
            because the disk lookup was skipped.
        config_search_start: Test hook to override the directory
            ``load_config`` walks up from. Defaults to ``target_path``.

    Returns:
        A :class:`PipelineResult` -- never mutates the input list's
        identity (``kept + suppressed`` is a permutation of
        ``findings``).

    Idempotency:
        Safe to call repeatedly on the same finding set. Fingerprints,
        severity overrides, and suppression stamps each have their
        own idempotency contract; a second pass is a no-op.
    """

    if config is not None:
        resolved = config
        found: Path | None = None
    else:
        start = config_search_start if config_search_start is not None else target_path
        loaded, found = load_config(start_dir=Path(start))
        base = found.parent if found is not None else Path(target_path).resolve()
        resolved = loaded.resolve_paths(base)

    populate_fingerprints(findings)

    findings, n_overridden = apply_severity_overrides(findings, resolved)

    ctx = SuppressionContext.from_paths(
        config=resolved,
        baseline_path=baseline_path,
        no_suppress=no_suppress,
    )
    kept, suppressed = ctx.apply(findings)

    return PipelineResult(
        kept=kept,
        suppressed=suppressed,
        config=resolved,
        found_config_path=found,
        severity_overrides_applied=n_overridden,
    )
