"""``securescan diff`` command.

Diff two scan snapshots (either via two git refs or two pre-rendered
JSON snapshot files) and emit only NEW findings plus counts of the
fixed / unchanged buckets. The wedge use case is PR-comment rendering
in CI.

The command function below is registered on the root Typer app by
:mod:`securescan.cli.__init__`.
"""

import asyncio
import json
import os
from pathlib import Path

import typer

from ..diff import classify, load_findings_json
from ..git_ops import (
    GitOpError,
    is_git_repo,
)
from ..git_ops import (
    checkout as git_checkout,
)
from ..git_ops import (
    current_ref as git_current_ref,
)
from ..git_ops import (
    diff_text as git_diff_text,
)
from ..git_ops import (
    is_clean as git_is_clean,
)
from ..git_ops import (
    rev_parse as git_rev_parse,
)
from ..models import ScanType
from ..pipeline import apply_pipeline
from ..render_pr_comment import render_pr_comment
from ..render_review import render_review_json
from ..threshold import count_at_or_above
from . import _shared
from ._shared import diff_should_run_ai


def diff(
    target_path: str = typer.Argument(".", help="Path to the project to diff."),
    base_ref: str | None = typer.Option(
        None,
        "--base-ref",
        help=(
            "Git ref for the 'before' side (e.g. main, abc123). Required "
            "unless --base-snapshot/--head-snapshot are used."
        ),
    ),
    head_ref: str | None = typer.Option(
        None,
        "--head-ref",
        help="Git ref for the 'after' side. Defaults to HEAD.",
    ),
    base_snapshot: Path | None = typer.Option(
        None,
        "--base-snapshot",
        help=(
            "Path to a JSON file with the 'before' findings (skips the "
            "base scan, useful in CI where it's already done)."
        ),
    ),
    head_snapshot: Path | None = typer.Option(
        None,
        "--head-snapshot",
        help="Path to a JSON file with the 'after' findings.",
    ),
    scan_types: list[str] = typer.Option(
        ["code"],
        "--type",
        help="Scan types to run on each side (repeatable).",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        help=(
            "Output format: github-pr-comment | github-review | sarif "
            "| json | text. Default: github-pr-comment when stdout is "
            "piped, text on a TTY. ``github-review`` emits the GitHub "
            "Reviews API JSON the action's post-review.sh POSTs."
        ),
    ),
    output_file: Path | None = typer.Option(
        None,
        "--output-file",
        help="Write rendered output to a file instead of stdout.",
    ),
    fail_on_severity: str | None = typer.Option(
        None,
        "--fail-on-severity",
        help="Exit non-zero if NEW findings >= this severity.",
    ),
    repo: str | None = typer.Option(
        None,
        "--repo",
        envvar="GITHUB_REPOSITORY",
        help=(
            "owner/repo for github-pr-comment links AND the "
            "github-review payload. Falls back to $GITHUB_REPOSITORY."
        ),
    ),
    sha: str | None = typer.Option(
        None,
        "--sha",
        envvar="GITHUB_SHA",
        help=(
            "Commit sha for github-pr-comment links AND the "
            "github-review ``commit_id`` (the head sha the review is "
            "anchored to). Falls back to $GITHUB_SHA."
        ),
    ),
    base_sha: str | None = typer.Option(
        None,
        "--base-sha",
        help=(
            "Base commit sha for github-review's `git diff` "
            "resolution. In ref-mode auto-resolved from --base-ref "
            "via `git rev-parse`; in snapshot-mode required (or "
            "set $GITHUB_BASE_REF, which we resolve via git)."
        ),
    ),
    review_event: str = typer.Option(
        "COMMENT",
        "--review-event",
        help=(
            "GitHub Reviews API event for --output github-review: "
            "COMMENT | REQUEST_CHANGES | APPROVE. Default COMMENT."
        ),
    ),
    no_suggestions: bool = typer.Option(
        False,
        "--no-suggestions",
        help=(
            "Drop GitHub `suggestion` fences from inline review "
            "comments (compact output). Default: suggestions on."
        ),
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        help=("Suppress findings present in this baseline JSON file (applied to BOTH sides)."),
    ),
    no_ai: bool = typer.Option(False, "--no-ai"),
    ai: bool = typer.Option(False, "--ai"),
    show_suppressed: bool | None = typer.Option(
        None,
        "--show-suppressed/--hide-suppressed",
        help=(
            "Include suppressed findings in output, marked with "
            "[SUPPRESSED:<reason>] prefix where supported. Default: "
            "auto -- shown on a TTY (text format) so devs see what CI "
            "would hide; hidden when piped or in non-text formats "
            "(github-pr-comment / sarif / json). Use --hide-suppressed "
            "to force hiding even on a TTY."
        ),
    ),
    no_suppress: bool = typer.Option(
        False,
        "--no-suppress",
        help=(
            "Disable all suppression mechanisms (config, inline "
            "comments, baseline). Use to debug what would otherwise "
            "be hidden. Wired through to SuppressionContext; the "
            "diff-time application is owned by TS10."
        ),
    ),
    baseline_host_probes: bool = typer.Option(
        False,
        "--baseline-host-probes",
        help=(
            "Force the baseline scanner to run host-wide probes on "
            "BOTH sides of the diff regardless of target_path. "
            "Default: off (baseline honors target_path)."
        ),
    ),
):
    """Diff two scan snapshots; emit only NEW findings (and counts of fixed/unchanged).

    Two modes:

    - ``--base-ref`` / ``--head-ref``: securescan handles the git
      checkouts and runs scanners on each side. Working tree must be
      clean. Original ref is always restored on exit (even on error).
    - ``--base-snapshot`` / ``--head-snapshot``: provide pre-scanned
      JSON outputs (CI fast path; no git needed). The GitHub Action
      uses this mode after pre-scanning base and head separately.

    AI enrichment is **off by default in diff mode** -- the diff is the
    canonical CI/automation surface and PR-comment bodies must be
    byte-identical across re-runs to enable comment upsert. Pass
    ``--ai`` to opt back in.

    Default ``--output`` is ``github-pr-comment`` when stdout is piped
    (the CI case) and ``text`` when stdout is a TTY (the local case).
    """
    if no_ai and ai:
        typer.echo("diff: --ai and --no-ai are mutually exclusive", err=True)
        raise typer.Exit(code=2)

    have_ref_inputs = base_ref is not None or head_ref is not None
    have_snap_inputs = base_snapshot is not None or head_snapshot is not None

    if have_ref_inputs and have_snap_inputs:
        typer.echo(
            "diff: choose either --base-ref/--head-ref OR "
            "--base-snapshot/--head-snapshot, not both",
            err=True,
        )
        raise typer.Exit(code=2)

    if not have_ref_inputs and not have_snap_inputs:
        typer.echo(
            "diff: must provide either --base-ref (with optional --head-ref) "
            "or --base-snapshot AND --head-snapshot",
            err=True,
        )
        raise typer.Exit(code=2)

    if have_snap_inputs and (base_snapshot is None or head_snapshot is None):
        typer.echo(
            "diff: snapshot mode requires BOTH --base-snapshot AND --head-snapshot",
            err=True,
        )
        raise typer.Exit(code=2)

    if have_ref_inputs and base_ref is None:
        typer.echo(
            "diff: ref mode requires --base-ref (--head-ref defaults to HEAD)",
            err=True,
        )
        raise typer.Exit(code=2)

    output_format = _shared._resolve_default_output(output)
    if output_format not in {"github-pr-comment", "github-review", "sarif", "json", "text"}:
        typer.echo(
            f"diff: unknown --output {output_format!r}. "
            "Choose github-pr-comment | github-review | sarif | json | text.",
            err=True,
        )
        raise typer.Exit(code=2)

    # Validate --review-event up-front (before any git work / scan)
    # so a typo on the new --output github-review path fails fast.
    if output_format == "github-review":
        _shared._validate_review_event(review_event, subcommand="diff")

    parsed_types: list[ScanType] = []
    for raw_type in scan_types:
        try:
            parsed_types.append(ScanType(raw_type))
        except ValueError:
            typer.echo(
                f"diff: unknown --type {raw_type!r}. Valid: {', '.join(t.value for t in ScanType)}",
                err=True,
            )
            raise typer.Exit(code=2) from None

    # TS10: load + path-resolve .securescan.yml ONCE up front, before
    # the scanner pass. Same instance feeds (a) the AI gate via
    # ``config_ai``, (b) the Semgrep custom-rule plumbing via
    # ``scanner_kwargs``, and (c) the post-scan ``apply_pipeline``
    # invocations on each side of the diff.
    resolved_config, found_config_path = _shared._load_resolved_config(target_path)
    if found_config_path is not None:
        typer.echo(f"diff: loaded config from {found_config_path}", err=True)

    enable_ai = diff_should_run_ai(
        explicit_ai=ai,
        explicit_no_ai=no_ai,
        config_ai=resolved_config.ai,
    )

    scanner_kwargs: dict = {}
    if resolved_config.semgrep_rules:
        scanner_kwargs["semgrep_rules"] = resolved_config.semgrep_rules
    if baseline_host_probes:
        # Forced HOST-mode baseline scope on both sides of the diff.
        # Only BaselineScanner reads this key; other scanners swallow
        # the kwarg via their accept-all signatures.
        scanner_kwargs["baseline_host_probes"] = True

    resolved_head_sha: str | None = None
    resolved_base_sha: str | None = None

    if have_snap_inputs:
        try:
            base_findings = load_findings_json(base_snapshot)
            head_findings = load_findings_json(head_snapshot)
        except (OSError, json.JSONDecodeError) as exc:
            typer.echo(f"diff: failed to load snapshot: {exc}", err=True)
            raise typer.Exit(code=2) from None
    else:
        target = Path(target_path).resolve()
        if not is_git_repo(target):
            typer.echo(
                f"diff: {target} is not inside a git working tree",
                err=True,
            )
            raise typer.Exit(code=2)

        try:
            if not git_is_clean(target):
                typer.echo(
                    "diff: working tree has uncommitted changes; "
                    "commit, stash, or clean before running diff in ref mode",
                    err=True,
                )
                raise typer.Exit(code=2)
            original_ref = git_current_ref(target)
        except GitOpError as exc:
            typer.echo(f"diff: {exc}", err=True)
            raise typer.Exit(code=2) from None

        h_ref = head_ref or "HEAD"
        try:
            resolved_head_sha = git_rev_parse(target, h_ref)
            base_resolved_sha = git_rev_parse(target, base_ref)
            resolved_base_sha = base_resolved_sha
        except GitOpError as exc:
            typer.echo(f"diff: {exc}", err=True)
            raise typer.Exit(code=2) from None

        try:
            try:
                git_checkout(target, base_resolved_sha)
                base_findings = asyncio.run(
                    _shared._run_scan_for_diff(
                        str(target),
                        parsed_types,
                        enable_ai=enable_ai,
                        scanner_kwargs=scanner_kwargs,
                    )
                )
                git_checkout(target, resolved_head_sha)
                head_findings = asyncio.run(
                    _shared._run_scan_for_diff(
                        str(target),
                        parsed_types,
                        enable_ai=enable_ai,
                        scanner_kwargs=scanner_kwargs,
                    )
                )
            except GitOpError as exc:
                typer.echo(f"diff: {exc}", err=True)
                raise typer.Exit(code=1) from None
        finally:
            try:
                git_checkout(target, original_ref)
            except GitOpError as exc:
                typer.echo(
                    f"diff: warning: could not restore original ref {original_ref}: {exc}",
                    err=True,
                )

    if sha is None and resolved_head_sha:
        sha = resolved_head_sha
    if base_sha is None and resolved_base_sha:
        base_sha = resolved_base_sha
    # Snapshot-mode fallback: GITHUB_BASE_REF (the action ships it as
    # the PR's base ref name, e.g. ``main``); resolve it via git when
    # the target is a real repo. We don't apply this in ref-mode
    # because ref-mode already pinned ``--base-ref``.
    if base_sha is None and have_snap_inputs:
        env_base_ref = os.environ.get("GITHUB_BASE_REF") or ""
        if env_base_ref:
            target = Path(target_path).resolve()
            if is_git_repo(target):
                try:
                    base_sha = git_rev_parse(target, env_base_ref)
                except GitOpError:
                    pass

    # TS10: apply the pipeline to BOTH sides of the diff. Config and
    # baseline rules apply uniformly across both; running them
    # symmetrically is what lets the fingerprint-based classifier
    # ("new" / "fixed" / "unchanged") downstream stay agnostic of
    # suppression. In snapshot mode the inputs may already carry
    # ``suppressed_by`` stamps from a previous run -- the pipeline is
    # idempotent (TS3 contract) so we re-apply anyway, which lets a
    # config change since the snapshot was generated take effect.
    base_pipeline = apply_pipeline(
        base_findings,
        target_path=Path(target_path),
        baseline_path=baseline,
        no_suppress=no_suppress,
        config=resolved_config,
    )
    head_pipeline = apply_pipeline(
        head_findings,
        target_path=Path(target_path),
        baseline_path=baseline,
        no_suppress=no_suppress,
        config=resolved_config,
    )
    if base_pipeline.suppressed or head_pipeline.suppressed:
        typer.echo(
            f"diff: suppressed "
            f"{len(base_pipeline.suppressed)} base / "
            f"{len(head_pipeline.suppressed)} head finding(s) "
            "(inline + config + baseline)",
            err=True,
        )

    # Feed kept + suppressed to the classifier so the suppression
    # stamps survive into the ChangeSet; the renderers then filter on
    # ``show_suppressed``. Failure-gate counts only the kept side
    # below.
    base_findings = base_pipeline.kept + base_pipeline.suppressed
    head_findings = head_pipeline.kept + head_pipeline.suppressed

    cs = classify(base_findings, head_findings)

    # TS10: the show_suppressed flag is now backed by real
    # ``metadata['suppressed_by']`` stamps from the pipeline above, so
    # the renderer's filter / label paths actually have something to
    # filter / label.
    effective_show_suppressed = _shared._default_show_suppressed(
        explicit=show_suppressed, output_format=output_format
    )

    if output_format == "github-pr-comment":
        body = render_pr_comment(
            cs,
            repo=repo,
            sha=sha,
            show_suppressed=effective_show_suppressed,
        )
    elif output_format == "github-review":
        # The Reviews API needs ``commit_id`` (head sha) and a
        # base..head unified diff for position resolution. We
        # require all three of repo + sha + base-sha up front;
        # without them the payload is either invalid or anchors
        # every finding in the body fallback (silent degradation).
        _shared._require_github_review_inputs(
            subcommand="diff",
            repo=repo,
            sha=sha,
            base_sha=base_sha,
        )
        target = Path(target_path).resolve()
        if not is_git_repo(target):
            typer.echo(
                f"diff: --output github-review requires a git "
                f"working tree at {target}; got a non-git path. "
                f"Either run against a real repo or switch "
                f"--output to github-pr-comment / sarif / json / text.",
                err=True,
            )
            raise typer.Exit(code=2)
        try:
            diff_unified = git_diff_text(target, base_sha, sha)
        except GitOpError as exc:
            typer.echo(f"diff: {exc}", err=True)
            raise typer.Exit(code=2) from None
        body = render_review_json(
            changeset=cs,
            commit_id=sha,
            diff_text=diff_unified,
            mode="diff",
            event=review_event,
            repo=repo,
            include_suggestions=not no_suggestions,
        )
    elif output_format == "sarif":
        body = json.dumps(
            _shared._render_diff_sarif(
                cs,
                target_path=target_path,
                scan_types=parsed_types,
                base_ref=base_ref,
                head_ref=head_ref or resolved_head_sha,
                show_suppressed=effective_show_suppressed,
            ),
            indent=2,
            default=str,
        )
    elif output_format == "json":
        if effective_show_suppressed:
            new_list = list(cs.new)
            fixed_list = list(cs.fixed)
            unchanged_count = len(cs.unchanged)
        else:
            new_list = [
                f
                for f in cs.new
                if not (
                    isinstance(getattr(f, "metadata", None), dict)
                    and f.metadata.get("suppressed_by")
                )
            ]
            fixed_list = [
                f
                for f in cs.fixed
                if not (
                    isinstance(getattr(f, "metadata", None), dict)
                    and f.metadata.get("suppressed_by")
                )
            ]
            # TS10: ``classify`` now operates on kept+suppressed (so the
            # ``suppressed_by`` audit stamps survive into the ChangeSet).
            # Keep the JSON output consumer-facing-consistent: when
            # show_suppressed=False, ``unchanged_count`` reflects only
            # the user-visible unchanged findings, mirroring the
            # filtered ``new`` / ``fixed`` lists.
            unchanged_count = sum(
                1
                for f in cs.unchanged
                if not (
                    isinstance(getattr(f, "metadata", None), dict)
                    and f.metadata.get("suppressed_by")
                )
            )
        body = json.dumps(
            {
                "new": [f.model_dump(mode="json") for f in new_list],
                "fixed": [f.model_dump(mode="json") for f in fixed_list],
                "unchanged_count": unchanged_count,
            },
            indent=2,
            default=str,
        )
    else:
        body = _shared._render_diff_text(cs, show_suppressed=effective_show_suppressed)

    if output_file is not None:
        Path(output_file).write_text(body)
    else:
        typer.echo(body, nl=False)

    if fail_on_severity:
        threshold_sev = _shared._SEVERITY_THRESHOLD_MAP.get(fail_on_severity.lower())
        if threshold_sev is None:
            typer.echo(
                f"diff: invalid --fail-on-severity {fail_on_severity!r}. "
                "Use critical, high, medium, low, or info.",
                err=True,
            )
            raise typer.Exit(code=2)
        # TS10: gate counts only non-suppressed new findings. A finding
        # the user has explicitly silenced via .securescan.yml / inline /
        # baseline is not allowed to fail CI.
        gate_new = [
            f
            for f in cs.new
            if not (
                isinstance(getattr(f, "metadata", None), dict) and f.metadata.get("suppressed_by")
            )
        ]
        offending = count_at_or_above(gate_new, threshold_sev)
        if offending > 0:
            raise typer.Exit(code=1)

    raise typer.Exit(code=0)
