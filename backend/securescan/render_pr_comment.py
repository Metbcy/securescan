"""GitHub PR-comment Markdown renderer.

The wedge for SecureScan v0.2.0: posting a single, diff-aware PR comment
that *upserts* in place — instead of appending a fresh comment on every
push — is what makes a security tool tolerable to leave on across an
org. The same lesson bomdrift learned in v0.1.0.

The upsert mechanism is purely conventional: the GitHub Action (SS9)
greps PR comments for the marker line ``<!-- securescan:diff -->`` and
edits the matching one if it exists, otherwise creates a new one. For
that grep to be reliable the marker MUST be the first line of the
output, every time, with no exceptions — even on the empty-changeset
path. That invariant is enforced by ``render_pr_comment`` and pinned by
``test_marker_is_first_line``.

Two render modes share the renderer: ``"diff"`` (default, backward
compat) for ``securescan diff`` PR comments, and ``"compare"`` for
``securescan compare`` baseline-drift comments. Compare uses a
separate marker (``MARKER_COMPARE = "<!-- securescan:compare -->"``)
so the two upsert lanes don't collide on the same PR.

Suppressed findings (TS6)
-------------------------
The renderer accepts a ``show_suppressed: bool = False`` keyword arg.
Default behavior filters out findings stamped with
``metadata['suppressed_by']`` before counting and rendering, so the
PR comment stays clean (the wedge use case: low-noise, audited
auto-mute). When ``show_suppressed=True`` every finding is included,
each suppressed row's title is prefixed with ``[SUPPRESSED:<reason>]``
to make the audit trail obvious to a reviewer skimming the comment,
and a ``Suppressed`` row is added to the summary table broken down
by reason (``inline=I, config=C, baseline=B``). Default-mode bytes
are unchanged from pre-TS6 output (the new row only appears when the
flag is on); same input + flag → byte-identical output.

The renderer is intentionally I/O-free and depends only on the
``ChangeSet`` dataclass from ``diff.py``: no datetime, no logging, no
filesystem, no env vars. The exporters.py wrapper
``findings_to_pr_comment`` exists for the common CLI path where the
caller has a flat list of findings and wants to treat them all as
"new"; the ``securescan diff`` subcommand (SS6) constructs a real
``ChangeSet`` and calls ``render_pr_comment`` directly.

Output format is GitHub-flavored Markdown only. No ANSI escapes (the
Action posts the body verbatim into a comment) and no emojis (pinned
v0.2.0 decision — see plan.md).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Literal

from .models import Severity
from .ordering import sort_findings_canonical

if TYPE_CHECKING:
    from .diff import ChangeSet
    from .models import Finding


MARKER = "<!-- securescan:diff -->"
MARKER_COMPARE = "<!-- securescan:compare -->"

RenderMode = Literal["diff", "compare"]

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}

_SUPPRESSION_REASON_ORDER: tuple[str, ...] = ("inline", "config", "baseline")

_DESCRIPTION_MAX_CHARS = 120

_SENTENCE_END = re.compile(r"(?<=[.!?])\s")


def _suppressed_reason(finding: Finding) -> str | None:
    """Return the suppression reason stamped on ``finding`` or ``None``.

    Mirrors the helper in :mod:`securescan.exporters`. Reads
    ``metadata['suppressed_by']`` defensively so duck-typed test
    doubles don't crash the renderer. The reason string itself
    (``"inline"`` / ``"config"`` / ``"baseline"``) is the same value
    the suppression precedence resolver in
    :class:`securescan.suppression.SuppressionContext` writes.
    """
    metadata = getattr(finding, "metadata", None)
    if not isinstance(metadata, dict):
        return None
    reason = metadata.get("suppressed_by")
    if isinstance(reason, str) and reason:
        return reason
    return None


def _suppression_breakdown(findings: list[Finding]) -> dict[str, int]:
    """Tally suppressed-by reasons across ``findings``.

    Returns a dict mapping reason -> count for every reason in
    :data:`_SUPPRESSION_REASON_ORDER`, with zero entries included so
    the caller can render a stable ``inline=I, config=C, baseline=B``
    summary regardless of whether any given reason is present.
    """
    breakdown: dict[str, int] = {r: 0 for r in _SUPPRESSION_REASON_ORDER}
    for f in findings:
        reason = _suppressed_reason(f)
        if reason in breakdown:
            breakdown[reason] += 1
        elif reason is not None:
            breakdown[reason] = breakdown.get(reason, 0) + 1
    return breakdown


def _filter_suppressed(findings: list[Finding], *, show_suppressed: bool) -> list[Finding]:
    """Drop findings stamped with ``metadata['suppressed_by']`` unless
    ``show_suppressed`` is True. Stable: order is preserved.
    """
    if show_suppressed:
        return list(findings)
    return [f for f in findings if _suppressed_reason(f) is None]


def _first_sentence_or_truncate(text: str, limit: int = _DESCRIPTION_MAX_CHARS) -> str:
    """Return the first sentence of ``text``, capped at ``limit`` chars.

    Decision: prefer the first sentence (split on ``.!?`` followed by
    whitespace) when it fits within ``limit``; otherwise hard-truncate
    at ``limit`` and append an ellipsis. This keeps the PR comment
    skim-readable on noisy scanners (semgrep in particular emits
    paragraph-long descriptions) without dropping the leading verb that
    tells the reviewer what's wrong.
    """
    text = (text or "").strip()
    if not text:
        return ""
    text = re.sub(r"\s+", " ", text)
    match = _SENTENCE_END.search(text)
    if match:
        first = text[: match.start() + 1].rstrip()
        if len(first) <= limit:
            return first
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "\u2026"


def _file_reference(
    finding: Finding,
    *,
    repo: str | None,
    sha: str | None,
) -> str:
    """Render the ``file:line`` reference for a finding.

    Returns Markdown-link form ``[src/x.py:42](https://github.com/...#L42)``
    when both ``repo`` and ``sha`` are provided and the finding has a
    file path; otherwise the plain backtick-wrapped ``src/x.py:42``
    form. When ``line_end`` is also present and differs from
    ``line_start``, the link fragment becomes ``#L<start>-L<end>``
    (matching real GitHub blob-URL syntax).
    """
    if not finding.file_path:
        return ""

    line = finding.line_start
    line_end = finding.line_end

    if line:
        if line_end and line_end != line:
            display = f"{finding.file_path}:{line}-{line_end}"
        else:
            display = f"{finding.file_path}:{line}"
    else:
        display = finding.file_path

    if repo and sha:
        url = f"https://github.com/{repo}/blob/{sha}/{finding.file_path}"
        if line:
            if line_end and line_end != line:
                url += f"#L{line}-L{line_end}"
            else:
                url += f"#L{line}"
        return f"[`{display}`]({url})"

    return f"`{display}`"


def _bucket_by_severity(
    findings: list[Finding],
) -> dict[Severity, list[Finding]]:
    """Group ``findings`` into per-severity buckets.

    Each bucket is sorted via ``sort_findings_canonical`` (the same key
    used by every other v0.2.0 renderer) so PR-comment output is
    byte-identical for the same logical input — the determinism
    invariant from SS3 / ordering.py.
    """
    buckets: dict[Severity, list[Finding]] = {sev: [] for sev in _SEVERITY_ORDER}
    for f in findings:
        if f.severity in buckets:
            buckets[f.severity].append(f)
    for sev in buckets:
        buckets[sev] = sort_findings_canonical(buckets[sev])
    return buckets


def _render_finding_bullet(
    finding: Finding,
    *,
    repo: str | None,
    sha: str | None,
    include_remediation: bool,
    show_suppressed: bool,
) -> list[str]:
    """Render one finding as Markdown list-item lines.

    The bullet is intentionally compact (one bold title line + an
    indented description, optionally an indented remediation) so a
    100-finding PR comment doesn't blow past GitHub's 65k-char comment
    body limit on large refactors.

    When ``show_suppressed`` is True and the finding carries a
    ``metadata['suppressed_by']`` stamp, the title is prefixed with
    ``[SUPPRESSED:<reason>]`` so a reviewer skimming the comment
    immediately sees which findings were silenced and why. The prefix
    appears OUTSIDE the bold span so the marker reads as metadata, not
    title text.
    """
    ref = _file_reference(finding, repo=repo, sha=sha)
    head_parts: list[str] = []
    reason = _suppressed_reason(finding) if show_suppressed else None
    if reason is not None:
        head_parts.append(f"- `[SUPPRESSED:{reason}]` **{finding.title}**")
    else:
        head_parts.append(f"- **{finding.title}**")
    if ref:
        head_parts.append(f"\u2014 {ref}")
    if finding.scanner:
        head_parts.append(f"([{finding.scanner}])")
    head_line = " ".join(head_parts)

    lines: list[str] = [head_line]
    desc = _first_sentence_or_truncate(finding.description)
    if desc:
        lines.append(f"  {desc}")
    if include_remediation and finding.remediation:
        rem = _first_sentence_or_truncate(finding.remediation)
        if rem:
            lines.append(f"  _Remediation:_ {rem}")
    return lines


def _render_section(
    title: str,
    findings: list[Finding],
    *,
    repo: str | None,
    sha: str | None,
    include_remediation: bool,
    show_suppressed: bool,
) -> list[str]:
    """Render a top-level section (### New / ### Fixed) with per-severity subsections.

    Severity subsections are emitted strictly in critical → info order,
    and a subsection is omitted entirely when it has zero findings
    (matches the bomdrift / SS3 Markdown convention — empty headings are
    just noise in a PR comment).
    """
    buckets = _bucket_by_severity(findings)
    lines: list[str] = [f"### {title} ({len(findings)})", ""]

    if not findings:
        lines.append("_None._")
        lines.append("")
        return lines

    for sev in _SEVERITY_ORDER:
        bucket = buckets[sev]
        if not bucket:
            continue
        lines.append(f"#### {_SEVERITY_LABEL[sev]} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            lines.extend(
                _render_finding_bullet(
                    f,
                    repo=repo,
                    sha=sha,
                    include_remediation=include_remediation,
                    show_suppressed=show_suppressed,
                ),
            )
        lines.append("")

    return lines


def render_pr_comment(
    changeset: ChangeSet,
    *,
    repo: str | None = None,
    sha: str | None = None,
    mode: RenderMode = "diff",
    show_suppressed: bool = False,
) -> str:
    """Render a ``ChangeSet`` as a Markdown PR comment body.

    ``repo`` and ``sha`` are both optional. When both are provided,
    file:line references become Markdown links to
    ``https://github.com/{repo}/blob/{sha}/{path}#L{line}``; otherwise
    they render as plain backtick-wrapped ``path:line`` text. Passing
    only one of the two also falls back to plain text — there's no
    sensible link without both.

    ``mode`` selects diff vs compare semantics. ``"diff"`` (default,
    backward compatible) labels the sections "New findings" / "Fixed
    findings" and uses ``MARKER`` (``<!-- securescan:diff -->``).
    ``"compare"`` labels them "New since baseline" / "Disappeared from
    baseline (drift?)" and uses ``MARKER_COMPARE``
    (``<!-- securescan:compare -->``) so PR-comment upserts don't
    collide with the diff lane. The parameter is purely additive:
    pre-existing callers pass nothing and get diff behavior.

    ``show_suppressed`` controls how findings with a
    ``metadata['suppressed_by']`` stamp are handled. Default is False:
    suppressed findings are filtered out of both ``new`` and ``fixed``
    before any counts or sections render, so the PR comment stays low
    noise. With True, suppressed findings are included, the row title
    is prefixed with ``[SUPPRESSED:<reason>]``, and the summary table
    gains a "Suppressed" row broken down by reason
    (``inline=I, config=C, baseline=B``). Output is byte-identical
    pre-TS6 when no suppressions are present (or the flag is False),
    so existing upsert / determinism tests stay green.

    Empty-changeset short-circuit: when ``changeset`` (after
    suppression filtering) has no new and no fixed findings the body is
    just the marker plus a single line (``_No new or fixed findings._``
    for diff, ``_No drift since baseline._`` for compare). The marker
    is ALWAYS the first line so the GitHub Action's upsert grep can
    find it unconditionally.

    Pure function. Same ``ChangeSet`` plus same
    ``repo``/``sha``/``mode``/``show_suppressed`` → byte-identical
    output, every time.
    """
    raw_new = list(changeset.new)
    raw_fixed = list(changeset.fixed)
    new_findings = _filter_suppressed(raw_new, show_suppressed=show_suppressed)
    fixed_findings = _filter_suppressed(raw_fixed, show_suppressed=show_suppressed)
    unchanged_count = len(changeset.unchanged)

    if mode == "compare":
        marker = MARKER_COMPARE
        heading = "## SecureScan: baseline drift"
        new_label = "New since baseline"
        fixed_label = "Disappeared from baseline (drift?)"
        empty_message = "_No drift since baseline._"
        new_section_title = "New since baseline"
        fixed_section_title = "Disappeared from baseline (drift?)"
        unchanged_label = "Still present"
    else:
        marker = MARKER
        heading = "## SecureScan: dependency & code change review"
        new_label = "New findings"
        fixed_label = "Fixed findings"
        empty_message = "_No new or fixed findings._"
        new_section_title = "New findings"
        fixed_section_title = "Fixed findings"
        unchanged_label = "Unchanged findings"

    if not new_findings and not fixed_findings:
        return f"{marker}\n{empty_message}\n"

    lines: list[str] = [
        marker,
        heading,
        "",
        "| Change | Count |",
        "|---|---:|",
        f"| {new_label} | {len(new_findings)} |",
        f"| {fixed_label} | {len(fixed_findings)} |",
        f"| {unchanged_label} | {unchanged_count} |",
    ]

    if show_suppressed:
        suppressed_in_new = [f for f in raw_new if _suppressed_reason(f) is not None]
        suppressed_in_fixed = [f for f in raw_fixed if _suppressed_reason(f) is not None]
        suppressed_total = len(suppressed_in_new) + len(suppressed_in_fixed)
        if suppressed_total > 0:
            breakdown = _suppression_breakdown(suppressed_in_new + suppressed_in_fixed)
            ordered_keys = list(_SUPPRESSION_REASON_ORDER) + sorted(
                k for k in breakdown if k not in _SUPPRESSION_REASON_ORDER
            )
            breakdown_text = ", ".join(f"{k}={breakdown[k]}" for k in ordered_keys)
            lines.append(f"| Suppressed | {suppressed_total} ({breakdown_text}) |")

    lines.append("")

    lines.extend(
        _render_section(
            new_section_title,
            new_findings,
            repo=repo,
            sha=sha,
            include_remediation=True,
            show_suppressed=show_suppressed,
        ),
    )
    lines.extend(
        _render_section(
            fixed_section_title,
            fixed_findings,
            repo=repo,
            sha=sha,
            include_remediation=False,
            show_suppressed=show_suppressed,
        ),
    )

    while lines and lines[-1] == "":
        lines.pop()
    lines.append("")
    return "\n".join(lines)
