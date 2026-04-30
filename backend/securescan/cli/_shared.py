"""Helpers shared by 2+ command modules in :mod:`securescan.cli`.

Split out of the original monolithic ``cli.py`` so each command module
only depends on the helpers it actually uses, and so monkey-patches in
the test suite have a single, stable target module
(``securescan.cli._shared``) for the call sites of the heavyweight
helpers (``_run_scan_for_diff``).

This module is imported by every command module via ``from . import
_shared``; helpers are then invoked as ``_shared.foo(...)`` so test
monkey-patches on ``_shared.foo`` are picked up at the call site.
"""

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console

from ..ai import AIEnricher
from ..config_file import SecureScanConfig, load_config
from ..dedup import deduplicate_findings
from ..diff import ChangeSet
from ..exporters import findings_to_sarif
from ..fingerprint import populate_fingerprints
from ..models import (
    Finding,
    Scan,
    ScanStatus,
    ScanType,
    Severity,
)
from ..scanners import get_scanners_for_types

console = Console()

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

SEVERITY_RANK = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


def should_run_ai(
    *,
    explicit_ai: bool,
    explicit_no_ai: bool,
    ci_env: str,
    config_ai: bool | None = None,
) -> bool:
    """Decide whether AI enrichment should run for a given invocation.

    Truth table (highest precedence first):

    * ``--ai``       wins                -> True
    * ``--no-ai``    wins                -> False
    * ``config_ai`` is not None          -> bool value (config wins)
    * ``CI`` env in {"true","1"}         -> False  (deterministic in CI)
    * otherwise                          -> True   (legacy default off-CI)

    ``ci_env`` is the raw string value of the ``CI`` environment
    variable (or empty string when unset). Pure-functional so tests
    don't need to mutate ``os.environ``.

    ``config_ai`` is the resolved ``ai`` field of ``.securescan.yml``
    (``None`` when the key is absent or no config file was found).
    Setting ``ai: false`` in the repo config force-disables AI even
    outside CI; setting ``ai: true`` force-enables it even on CI.
    Explicit CLI flags still win over both.
    """
    if explicit_ai:
        return True
    if explicit_no_ai:
        return False
    if config_ai is not None:
        return config_ai
    if (ci_env or "").lower() in ("true", "1"):
        return False
    return True


def diff_should_run_ai(
    *,
    explicit_ai: bool,
    explicit_no_ai: bool,
    config_ai: bool | None = None,
) -> bool:
    """AI gate for ``securescan diff`` / ``compare``. Differs from
    ``should_run_ai`` only in the default arm: AI is **off by default**
    in diff/compare mode even outside CI, because both are fundamentally
    CI/automation surfaces (PR comments must be byte-identical across
    re-runs to enable upsert). The user opts back in with ``--ai``.

    Truth table (highest precedence first):

    * ``--ai``                    -> True
    * ``--no-ai``                 -> False
    * ``config_ai`` is not None   -> bool value (config wins)
    * neither                     -> False  (the diff-mode default)

    Flag mutex (``--ai && --no-ai``) is rejected at the CLI layer
    before this helper is consulted.
    """
    if explicit_ai:
        return True
    if explicit_no_ai:
        return False
    if config_ai is not None:
        return config_ai
    return False


def _load_resolved_config(target_path: str) -> tuple[SecureScanConfig, Path | None]:
    """Load and path-resolve the ``.securescan.yml`` for ``target_path``.

    Used by every CLI subcommand that needs the config *before* the
    scanner pass (for the AI gate and for forwarding ``semgrep_rules``
    to the Semgrep scanner). The result is then re-used by
    :func:`apply_pipeline` via its ``config=`` parameter so we don't
    walk the filesystem twice per invocation.

    Returns ``(resolved_config, found_path)``. When no config file is
    present, ``found_path`` is ``None`` and the returned config is the
    default :class:`SecureScanConfig` resolved against
    ``target_path.resolve()`` (semgrep_rules will be empty in that
    case so the resolution base doesn't matter, but we use the
    target path for predictability).
    """
    target = Path(target_path)
    cfg, found = load_config(start_dir=target)
    base = found.parent if found is not None else target.resolve()
    return cfg.resolve_paths(base), found


async def _run_scan_for_diff(
    target_path: str,
    scan_types: list[ScanType],
    *,
    enable_ai: bool,
    scanner_kwargs: dict | None = None,
) -> list[Finding]:
    """Lightweight scan helper used by the ``diff`` subcommand.

    Differences vs. ``_run_scan_async``:

    * No DB I/O. We deliberately do not write a row to the ``scans`` /
      ``findings`` tables for either side of a diff -- a diff invocation
      is short-lived analysis, not a persisted scan, and CI runs would
      otherwise create two stray history rows per PR push.
    * No risk-score / summary computation -- the diff cares about
      finding *identity* (fingerprint), not aggregate scoring.
    * No compliance tagging -- compliance metadata isn't part of the
      fingerprint and doesn't change classification.

    Otherwise the scanner orchestration is identical: filter to the
    requested scan types, drop unavailable scanners, run the rest in
    parallel, dedupe the union, populate fingerprints. AI enrichment is
    opt-in via ``enable_ai`` (the diff CLI defaults this to False --
    see ``diff_should_run_ai``). ``scanner_kwargs`` is forwarded to
    every scanner's ``scan()`` call (used by TS10 to plumb
    ``semgrep_rules`` from ``.securescan.yml``); unknown keys are
    swallowed by each scanner's ``**kwargs`` accept-all signature.
    """
    scan_id = str(__import__("uuid").uuid4())
    scanners = get_scanners_for_types(scan_types)
    all_findings: list[Finding] = []

    available_scanners = []
    for scanner in scanners:
        try:
            if await scanner.is_available():
                available_scanners.append(scanner)
        except Exception:
            continue

    if available_scanners:
        kwargs = scanner_kwargs or {}

        async def _run_one(s):
            return await s.scan(target_path, scan_id, **kwargs)

        results = await asyncio.gather(
            *(_run_one(s) for s in available_scanners),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Exception):
                continue
            all_findings.extend(result)

    all_findings = deduplicate_findings(all_findings)

    if enable_ai:
        enricher = AIEnricher()
        if enricher.is_available:
            await enricher.enrich_findings(all_findings)

    populate_fingerprints(all_findings)
    return all_findings


_SEVERITY_THRESHOLD_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _render_diff_text(cs: ChangeSet, *, show_suppressed: bool = False) -> str:
    """Render a ``ChangeSet`` as plain-text suitable for a human terminal.

    Format is intentionally minimal so it fits on a single screen for
    typical PR-sized diffs:

        SecureScan diff: <N> new, <M> fixed, <K> unchanged

        New findings:
          [CRITICAL] <title> (<file>:<line>)
          ...

    No ANSI colour, no Markdown, no emojis. The PR-comment renderer
    handles the GitHub case; this is the local-development case.

    When ``show_suppressed`` is True, suppressed findings are included
    in the listing with a ``[SUPPRESSED:<reason>]`` prefix on the
    title; the leading-line counts ("N new, M fixed") reflect the
    pre-filter totals so the developer sees the full picture. When
    False (the CI / pipe default), suppressed findings are filtered
    out entirely and the counts reflect only what is shown.
    """
    new_findings = list(cs.new)
    fixed_findings = list(cs.fixed)
    if not show_suppressed:
        new_findings = [
            f
            for f in new_findings
            if not (
                isinstance(getattr(f, "metadata", None), dict) and f.metadata.get("suppressed_by")
            )
        ]
        fixed_findings = [
            f
            for f in fixed_findings
            if not (
                isinstance(getattr(f, "metadata", None), dict) and f.metadata.get("suppressed_by")
            )
        ]

    lines: list[str] = [
        f"SecureScan diff: {len(new_findings)} new, {len(fixed_findings)} fixed, "
        f"{len(cs.unchanged)} unchanged"
    ]
    if not new_findings and not fixed_findings:
        lines.append("")
        lines.append("No new or fixed findings.")
        return "\n".join(lines) + "\n"

    if new_findings:
        lines.append("")
        lines.append("New findings:")
        severity_order = (
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        )
        for sev in severity_order:
            for f in new_findings:
                if f.severity != sev:
                    continue
                loc = ""
                if f.file_path:
                    loc = f" ({f.file_path}"
                    if f.line_start:
                        loc += f":{f.line_start}"
                    loc += ")"
                prefix = ""
                if show_suppressed:
                    metadata = getattr(f, "metadata", None)
                    if isinstance(metadata, dict):
                        reason = metadata.get("suppressed_by")
                        if isinstance(reason, str) and reason:
                            prefix = f"[SUPPRESSED:{reason}] "
                lines.append(f"  [{sev.value.upper()}] {prefix}{f.title}{loc}")

    if fixed_findings:
        lines.append("")
        lines.append(f"Fixed findings: {len(fixed_findings)}")

    return "\n".join(lines) + "\n"


def _render_compare_text(cs: ChangeSet, *, show_suppressed: bool = False) -> str:
    """Render a ``ChangeSet`` as plain-text for ``securescan compare``.

    Counterpart of ``_render_diff_text`` with compare-mode wording:
    ``DISAPPEARED`` instead of ``fixed``, ``still present`` instead of
    ``unchanged``. Same minimal single-screen format, no Markdown, no
    ANSI, no emojis.

    ``show_suppressed`` semantics match :func:`_render_diff_text`:
    True includes suppressed findings prefixed with
    ``[SUPPRESSED:<reason>]``; False (default for non-TTY / CI)
    filters them out and the counts reflect only the visible subset.
    """
    new_findings = list(cs.new)
    fixed_findings = list(cs.fixed)
    if not show_suppressed:
        new_findings = [
            f
            for f in new_findings
            if not (
                isinstance(getattr(f, "metadata", None), dict) and f.metadata.get("suppressed_by")
            )
        ]
        fixed_findings = [
            f
            for f in fixed_findings
            if not (
                isinstance(getattr(f, "metadata", None), dict) and f.metadata.get("suppressed_by")
            )
        ]

    lines: list[str] = [
        f"SecureScan compare: {len(new_findings)} new since baseline, "
        f"{len(fixed_findings)} disappeared, {len(cs.unchanged)} still present"
    ]
    if not new_findings and not fixed_findings:
        lines.append("")
        lines.append("No drift since baseline.")
        return "\n".join(lines) + "\n"

    severity_order = (
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    )

    def _render_bucket(bucket: list[Finding]) -> None:
        for sev in severity_order:
            for f in bucket:
                if f.severity != sev:
                    continue
                loc = ""
                if f.file_path:
                    loc = f" ({f.file_path}"
                    if f.line_start:
                        loc += f":{f.line_start}"
                    loc += ")"
                prefix = ""
                if show_suppressed:
                    metadata = getattr(f, "metadata", None)
                    if isinstance(metadata, dict):
                        reason = metadata.get("suppressed_by")
                        if isinstance(reason, str) and reason:
                            prefix = f"[SUPPRESSED:{reason}] "
                lines.append(f"  [{sev.value.upper()}] {prefix}{f.title}{loc}")

    if new_findings:
        lines.append("")
        lines.append("New since baseline:")
        _render_bucket(new_findings)

    if fixed_findings:
        lines.append("")
        lines.append("Disappeared from baseline (drift?):")
        _render_bucket(fixed_findings)

    return "\n".join(lines) + "\n"


def _render_diff_sarif(
    cs: ChangeSet,
    *,
    target_path: str,
    scan_types: list[ScanType],
    base_ref: str | None,
    head_ref: str | None,
    show_suppressed: bool = False,
) -> dict:
    """Render the NEW findings of a changeset as a SARIF document.

    Decision: SARIF for diff mode is **NEW only**. Fixed findings are
    not security alerts; emitting them would generate spurious
    "resolved alert" noise on the GitHub Security tab. The
    ``invocations[].properties`` block records ``diffMode: true`` plus
    the base / head refs so a downstream consumer can tell this isn't a
    full scan upload.

    ``show_suppressed`` is forwarded to :func:`findings_to_sarif`:
    default False filters suppressed findings out of the SARIF, True
    includes them with a per-result ``properties.suppressed_by``
    field. SARIF's ``suppressions`` array is intentionally not used --
    inline properties travel with the result and don't require the
    consumer to cross-reference a separate top-level array.
    """
    diff_scan = Scan(
        target_path=target_path,
        scan_types=scan_types or [ScanType.CODE],
        status=ScanStatus.COMPLETED,
    )
    sarif = findings_to_sarif(cs.new, diff_scan, show_suppressed=show_suppressed)
    try:
        run = sarif["runs"][0]
        invocation = run["invocations"][0]
        props = invocation.setdefault("properties", {})
        props["diffMode"] = True
        if base_ref:
            props["baseRef"] = base_ref
        if head_ref:
            props["headRef"] = head_ref
    except (KeyError, IndexError):
        pass
    return sarif


_REVIEW_EVENTS: tuple[str, ...] = ("COMMENT", "REQUEST_CHANGES", "APPROVE")


def _validate_review_event(event: str, *, subcommand: str) -> str:
    """Validate ``--review-event`` against the GitHub Reviews API enum.

    Pure validator (no side effects). Returns the value verbatim on
    success; on failure echoes a helpful stderr line and raises
    :class:`typer.Exit`. Centralised so both ``diff`` and ``compare``
    surface the same error wording when a user typos the event name.
    """
    if event not in _REVIEW_EVENTS:
        typer.echo(
            f"{subcommand}: invalid --review-event {event!r}. Choose {' | '.join(_REVIEW_EVENTS)}.",
            err=True,
        )
        raise typer.Exit(code=2)
    return event


def _require_github_review_inputs(
    *,
    subcommand: str,
    repo: str | None,
    sha: str | None,
    base_sha: str | None,
) -> None:
    """Gate the ``--output github-review`` path on its required inputs.

    The Reviews API call needs ``repo``, ``sha`` (the head commit the
    review is anchored to), and ``base_sha`` (the commit the diff is
    computed against, so :mod:`securescan.diff_position` can resolve
    line numbers to diff positions). Each is independently required;
    we surface ALL missing ones in a single message rather than the
    user iterating one at a time.

    Env fallbacks (``GITHUB_REPOSITORY`` / ``GITHUB_SHA``) are wired
    via typer's ``envvar=`` on the option itself, so by the time we
    get here the value is either explicit-or-env or genuinely
    missing.
    """
    missing: list[str] = []
    if not repo:
        missing.append("--repo (or GITHUB_REPOSITORY)")
    if not sha:
        missing.append("--sha (or GITHUB_SHA)")
    if not base_sha:
        missing.append("--base-sha")
    if missing:
        typer.echo(
            f"{subcommand}: --output github-review requires " + ", ".join(missing) + ".",
            err=True,
        )
        raise typer.Exit(code=2)


def _resolve_default_output(explicit: str | None) -> str:
    """Choose the default ``--output`` value.

    When the user passed ``--output`` explicitly we take it verbatim.
    Otherwise: if stdout is a TTY (a human at a terminal), default to
    ``text``; otherwise default to ``github-pr-comment`` (the CI / pipe
    case, which is the wedge use case for the diff command).
    """
    if explicit:
        return explicit
    return "text" if sys.stdout.isatty() else "github-pr-comment"


def _default_show_suppressed(*, explicit: bool | None, output_format: str) -> bool:
    """Resolve the effective ``show_suppressed`` value for a renderer call.

    When ``explicit`` is non-``None``, the user passed
    ``--show-suppressed`` or ``--hide-suppressed`` and that value wins
    verbatim. Otherwise the default depends on the output format and
    whether stdout is a TTY:

    - Text output (``text`` / ``table``) on a TTY -> ``True``. The dev
      is at a terminal running ``securescan diff`` locally; they need
      to see what would be silenced in CI so they can audit it.
    - Everything else (``github-pr-comment``, ``sarif``, ``json``,
      ``csv``, ``junit``, or text on a non-TTY pipe) -> ``False``.
      CI / piped output stays clean by default; the explicit flag
      turns it back on for audits.

    Pure function. Same inputs (and same ``sys.stdout.isatty()``
    state) -> same output.
    """
    if explicit is not None:
        return explicit
    if output_format in {"text", "table"} and sys.stdout.isatty():
        return True
    return False
