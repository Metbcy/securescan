"""``securescan compare`` command.

Compare a fresh scan against a saved baseline JSON; report what's NEW
and what DISAPPEARED (drift). Sibling to ``diff`` but consumes a
frozen baseline artifact instead of two git refs.

The command function below is registered on the root Typer app by
:mod:`securescan.cli.__init__`.
"""

import asyncio
import json
from pathlib import Path

import typer

from ..diff import classify, load_findings_json
from ..fingerprint import populate_fingerprints
from ..git_ops import (
    GitOpError,
    is_git_repo,
)
from ..git_ops import (
    diff_text as git_diff_text,
)
from ..models import ScanType
from ..pipeline import apply_pipeline
from ..render_pr_comment import render_pr_comment
from ..render_review import render_review_json
from . import _shared
from ._shared import diff_should_run_ai


def compare(
    target_path: str = typer.Argument(".", help="Path to scan."),
    baseline_path: Path = typer.Argument(
        ...,
        help=(
            "Path to a baseline findings JSON (from `securescan baseline` "
            "or `securescan scan --output json`)."
        ),
    ),
    scan_types: list[str] = typer.Option(
        ["code"],
        "--type",
        help="Scan types to run (repeatable).",
    ),
    output: str | None = typer.Option(
        None,
        "--output",
        help=(
            "Output format: github-pr-comment | github-review | sarif "
            "| json | text. Defaults to text on TTY, github-pr-comment "
            "when piped. ``github-review`` emits the GitHub Reviews "
            "API JSON the action's post-review.sh POSTs."
        ),
    ),
    output_file: Path | None = typer.Option(
        None,
        "--output-file",
        help="Write rendered output to a file instead of stdout.",
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
            "resolution. REQUIRED for compare's github-review path: "
            "we don't track which commit the baseline was scanned "
            "at (a v0.5 enhancement), so the user must assert it."
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
            "compare-time application is owned by TS10."
        ),
    ),
    baseline_host_probes: bool = typer.Option(
        False,
        "--baseline-host-probes",
        help=(
            "Force the baseline scanner to run host-wide probes on "
            "the FRESH scan regardless of target_path. The baseline "
            "JSON is consumed as-is and not re-scanned. Default: "
            "off (baseline honors target_path)."
        ),
    ),
):
    """Compare current scan against a baseline; report what's NEW and what
    DISAPPEARED (drift).

    Like ``diff``, but instead of two refs you provide a saved baseline
    JSON file. New findings = present now, absent from baseline.
    Disappeared findings = present in baseline, absent now (probably
    fixed; could be silently suppressed via .securescan.yml or inline
    ignores). Both are worth flagging.

    PR-comment output uses the ``<!-- securescan:compare -->`` marker
    so it lives in its own upsert lane and doesn't collide with the
    ``securescan diff`` comment on the same PR.

    SARIF output emits NEW findings only. SARIF describes findings IN
    a scan, not their absence, so DISAPPEARED findings don't have a
    natural SARIF representation. Use json or github-pr-comment output
    if you need to surface drift.

    AI enrichment is off by default in compare mode (same rationale as
    ``diff``: PR-comment bodies must be byte-identical across re-runs
    to enable upsert). Pass ``--ai`` to opt back in.

    Pipeline scope: ``compare`` applies the current ``.securescan.yml``
    (severity overrides, ``ignored_rules``, inline ``# securescan:
    ignore`` directives) to the FRESH scan only. The baseline JSON is
    NOT re-filtered -- a baseline is what it is at write time, and
    re-running today's config against yesterday's baseline would
    silently rewrite history. If you want the baseline normalized to
    today's config, regenerate it with ``securescan baseline``.
    """
    if no_ai and ai:
        typer.echo("compare: --ai and --no-ai are mutually exclusive", err=True)
        raise typer.Exit(code=2)

    if not Path(baseline_path).exists():
        typer.echo(
            f"compare: baseline file not found: {baseline_path}\n"
            "compare: hint: generate one with `securescan baseline` or "
            "`securescan scan --output json --output-file baseline.json`",
            err=True,
        )
        raise typer.Exit(code=2)

    output_format = _shared._resolve_default_output(output)
    if output_format not in {"github-pr-comment", "github-review", "sarif", "json", "text"}:
        typer.echo(
            f"compare: unknown --output {output_format!r}. "
            "Choose github-pr-comment | github-review | sarif | json | text.",
            err=True,
        )
        raise typer.Exit(code=2)

    if output_format == "github-review":
        _shared._validate_review_event(review_event, subcommand="compare")

    parsed_types: list[ScanType] = []
    for raw_type in scan_types:
        try:
            parsed_types.append(ScanType(raw_type))
        except ValueError:
            typer.echo(
                f"compare: unknown --type {raw_type!r}. "
                f"Valid: {', '.join(t.value for t in ScanType)}",
                err=True,
            )
            raise typer.Exit(code=2) from None

    # TS10: load + path-resolve .securescan.yml ONCE up front. Same
    # instance feeds (a) the AI gate, (b) the Semgrep custom-rule
    # plumbing for the fresh scan, and (c) the post-scan
    # ``apply_pipeline`` on the FRESH side only.
    #
    # Compare deliberately does NOT re-filter the baseline JSON: the
    # baseline is a frozen artifact (it is what it is at write time --
    # see the ``securescan baseline`` command's docstring for the
    # determinism contract). Re-running today's config against
    # yesterday's baseline would silently rewrite history.
    resolved_config, found_config_path = _shared._load_resolved_config(target_path)
    if found_config_path is not None:
        typer.echo(f"compare: loaded config from {found_config_path}", err=True)

    enable_ai = diff_should_run_ai(
        explicit_ai=ai,
        explicit_no_ai=no_ai,
        config_ai=resolved_config.ai,
    )

    scanner_kwargs: dict = {}
    if resolved_config.semgrep_rules:
        scanner_kwargs["semgrep_rules"] = resolved_config.semgrep_rules
    if baseline_host_probes:
        # Forced HOST-mode baseline scope on the fresh scan. The
        # baseline JSON itself is frozen and not re-scanned, so this
        # only affects today's findings.
        scanner_kwargs["baseline_host_probes"] = True

    try:
        baseline_findings = load_findings_json(baseline_path)
    except (OSError, json.JSONDecodeError) as exc:
        typer.echo(f"compare: failed to load baseline: {exc}", err=True)
        raise typer.Exit(code=2) from None

    fresh_findings = asyncio.run(
        _shared._run_scan_for_diff(
            target_path,
            parsed_types,
            enable_ai=enable_ai,
            scanner_kwargs=scanner_kwargs,
        )
    )

    populate_fingerprints(baseline_findings)

    # TS10: apply pipeline to FRESH side only (see comment above for the
    # baseline-is-frozen rationale).
    fresh_pipeline = apply_pipeline(
        fresh_findings,
        target_path=Path(target_path),
        baseline_path=None,  # baseline_path arg is for fingerprint-suppression; here the baseline is already the comparison axis
        no_suppress=no_suppress,
        config=resolved_config,
    )
    if fresh_pipeline.suppressed:
        typer.echo(
            f"compare: suppressed {len(fresh_pipeline.suppressed)} "
            "fresh finding(s) (inline + config)",
            err=True,
        )
    fresh_findings = fresh_pipeline.kept + fresh_pipeline.suppressed

    cs = classify(baseline_findings, fresh_findings)

    # TS10: show_suppressed is now backed by real
    # ``metadata['suppressed_by']`` stamps from the fresh-side pipeline
    # above; renderers can both filter (CI default) and label (TTY
    # default) accordingly.
    effective_show_suppressed = _shared._default_show_suppressed(
        explicit=show_suppressed, output_format=output_format
    )

    if output_format == "github-pr-comment":
        body = render_pr_comment(
            cs,
            repo=repo,
            sha=sha,
            mode="compare",
            show_suppressed=effective_show_suppressed,
        )
    elif output_format == "github-review":
        # ``compare`` doesn't track the baseline's commit-id (the
        # baseline JSON is a frozen artifact; recording the sha it
        # was scanned at is a v0.5 enhancement). So --base-sha is
        # not auto-resolvable here -- we trust the user's assertion
        # of "what commit the baseline corresponds to".
        _shared._require_github_review_inputs(
            subcommand="compare",
            repo=repo,
            sha=sha,
            base_sha=base_sha,
        )
        target = Path(target_path).resolve()
        if not is_git_repo(target):
            typer.echo(
                f"compare: --output github-review requires a git "
                f"working tree at {target}; got a non-git path. "
                f"Either run against a real repo or switch "
                f"--output to github-pr-comment / sarif / json / text.",
                err=True,
            )
            raise typer.Exit(code=2)
        try:
            diff_unified = git_diff_text(target, base_sha, sha)
        except GitOpError as exc:
            typer.echo(f"compare: {exc}", err=True)
            raise typer.Exit(code=2) from None
        body = render_review_json(
            changeset=cs,
            commit_id=sha,
            diff_text=diff_unified,
            mode="compare",
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
                base_ref=None,
                head_ref=None,
                show_suppressed=effective_show_suppressed,
            ),
            indent=2,
            default=str,
        )
    elif output_format == "json":
        if effective_show_suppressed:
            new_list = list(cs.new)
            disappeared_list = list(cs.fixed)
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
            disappeared_list = [
                f
                for f in cs.fixed
                if not (
                    isinstance(getattr(f, "metadata", None), dict)
                    and f.metadata.get("suppressed_by")
                )
            ]
            # TS10: see the matching note in ``diff`` -- when the fresh
            # side carries ``suppressed_by`` stamps, keep the JSON
            # ``unchanged_count`` aligned with the (filtered) ``new`` /
            # ``disappeared`` lists so consumers don't have to re-do
            # the filter themselves.
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
                "disappeared": [f.model_dump(mode="json") for f in disappeared_list],
                "unchanged_count": unchanged_count,
            },
            indent=2,
            default=str,
        )
    else:
        body = _shared._render_compare_text(cs, show_suppressed=effective_show_suppressed)

    if output_file is not None:
        Path(output_file).write_text(body)
    else:
        typer.echo(body, nl=False)

    raise typer.Exit(code=0)
