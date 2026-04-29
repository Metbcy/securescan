"""Serialise findings into a GitHub Reviews API payload.

The v0.4.0 wedge: a single deterministic JSON document the
GitHub Action's ``post-review.sh`` POSTs to GitHub at
``POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews`` to land
per-file/per-line review comments on a PR. Ties together:

- IR1 :mod:`securescan.diff_position` -- (file, line) -> diff
  position resolution off the unified diff;
- IR2 :mod:`securescan.review_marker` -- the
  ``<!-- securescan:fp:<prefix> -->`` upsert marker that survives
  re-runs;
- IR3 :mod:`securescan.suggestions` -- one-click ``suggestion``
  fences for inline-ignore + a copy-paste YAML fence for
  severity-pinning.

Position resolution
-------------------
For each finding produced by the scan, the renderer looks up
``diff_map.lookup(file, line_start)``. When that returns an
integer, the finding becomes an inline ``ReviewComment``. When it
returns ``None`` (file not in the diff, or line outside any hunk),
the finding lands in the review's overall ``body`` -- the
"body fallback" bucket -- so it doesn't disappear silently.

Anchor-shift contract for inline-ignore suggestions
---------------------------------------------------
Per IR3, ``build_inline_ignore_suggestion`` emits a ``suggestion``
fence intended to REPLACE the line ABOVE the finding (the line
at ``finding.line_start - 1``). When the renderer attaches such
a suggestion to a comment, it MUST therefore anchor the comment
at the line-above's position. If the line above isn't in the
diff (no position), the renderer drops the inline-ignore
suggestion (keeping the severity-pin) and anchors at the
finding's natural line position. Misanchoring a ``suggestion``
fence would silently delete code on one click; dropping the
optional helper is the safer trade-off.

Determinism
-----------
Same inputs -> byte-identical ``to_api_dict()`` and
``render_review_json(...)`` output. Comments are sorted by
``(path, position, fingerprint_prefix)``; body iteration uses
``sort_findings_canonical``. No wall-clock timestamps. Mirrors
SS3's invariant for SARIF + render_pr_comment for the diff PR
comment.

Two markers for two upsert lanes
--------------------------------
``MARKER_REVIEW`` (``<!-- securescan:diff-review -->``) and
``MARKER_REVIEW_COMPARE`` (``<!-- securescan:compare-review -->``)
are deliberately distinct from TS7's ``MARKER`` /
``MARKER_COMPARE`` so the action's grep can keep the diff-mode
single PR comment lane and the diff-mode review lane separate.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Literal

from .diff import ChangeSet
from .diff_position import DiffPositionMap, parse_unified_diff
from .fingerprint import populate_fingerprints
from .models import Finding, Severity
from .ordering import sort_findings_canonical
from .render_pr_comment import RenderMode
from .review_marker import (
    FINGERPRINT_PREFIX_LEN,
    add_fingerprint_marker,
    extract_fingerprint,
)
from .suggestions import (
    build_inline_ignore_suggestion,
    build_severity_pin_suggestion,
)


MARKER_REVIEW = "<!-- securescan:diff-review -->"
MARKER_REVIEW_COMPARE = "<!-- securescan:compare-review -->"

ReviewEvent = Literal["COMMENT", "REQUEST_CHANGES", "APPROVE"]

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

# Duplicated from render_pr_comment.py rather than imported, per the
# IR4 brief: the "no shared private helper" rule keeps the existing
# module untouched. v0.5 may consolidate.
_SEVERITY_LABEL: dict[Severity, str] = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}

_DESCRIPTION_MAX_CHARS = 200

_SENTENCE_END = re.compile(r"(?<=[.!?])\s")

_CWE_RE = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)


@dataclass(frozen=True)
class ReviewComment:
    """One inline review comment in the Reviews API payload.

    ``position`` is the integer offset INTO the PR's unified diff
    (per :mod:`securescan.diff_position`), not a source-file line.
    ``body`` always carries an IR2 fingerprint marker so re-runs
    can locate-and-edit the existing comment.
    """

    path: str
    position: int
    body: str

    def to_api_dict(self) -> dict:
        return {"path": self.path, "position": self.position, "body": self.body}


@dataclass(frozen=True)
class ReviewPayload:
    """The full ``POST /pulls/{n}/reviews`` request body.

    Frozen + ``comments`` as a tuple so the payload is hashable
    and obviously immutable. ``commit_id`` is pinned at render
    time so re-runs target the same head SHA even if the action's
    later steps see a newer push.
    """

    commit_id: str
    event: ReviewEvent
    body: str
    comments: tuple[ReviewComment, ...]

    def to_api_dict(self) -> dict:
        return {
            "commit_id": self.commit_id,
            "event": self.event,
            "body": self.body,
            "comments": [c.to_api_dict() for c in self.comments],
        }


def _first_sentence_or_truncate(
    text: str, limit: int = _DESCRIPTION_MAX_CHARS
) -> str:
    """Return the first sentence of ``text``, capped at ``limit`` chars.

    Same shape as the helper in render_pr_comment.py but with a
    larger limit (200 vs 120) -- inline review comments have more
    vertical room than a single PR-comment bullet, and reviewers
    benefit from a fuller description here.
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


def _cwe_url(cwe: str | None) -> str | None:
    """Return the canonical CWE definition URL, or None.

    Accepts ``"CWE-89"`` / ``"cwe-89"``; returns
    ``https://cwe.mitre.org/data/definitions/89.html``.
    """
    if not cwe:
        return None
    m = _CWE_RE.match(cwe.strip())
    if not m:
        return None
    return f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html"


def _linkify_title(finding: Finding, *, repo: str | None) -> str:
    """Return the finding title, optionally as a Markdown link.

    When ``repo`` is provided AND the finding carries a CWE id, the
    title becomes a Markdown link to the CWE definition page.
    Without ``repo`` we render plain text -- consistent with the
    "GitHub-context-only" semantic of ``repo`` in render_pr_comment.
    """
    title = finding.title or ""
    if not repo:
        return title
    url = _cwe_url(finding.cwe)
    if url is None:
        return title
    return f"[{title}]({url})"


def render_inline_comment_body(
    finding: Finding,
    *,
    repo: str | None = None,
    include_suggestions: bool = True,
    include_inline_ignore: bool = True,
) -> str:
    """Render the Markdown body for a single inline review comment.

    Structure (blank lines between blocks):

        **{SEVERITY}: {scanner}** -- {title}

        {description first-sentence-or-truncated to 200 chars}

        {remediation, when present}

        {inline-ignore suggestion, when buildable + flags allow}

        {severity-pin suggestion, when buildable + flag allows}

        <!-- securescan:fp:<12-char-prefix> -->

    ``include_suggestions=False`` drops both suggestion blocks.
    ``include_inline_ignore=False`` drops only the inline-ignore
    block (used by the renderer when the line ABOVE the finding
    isn't in the diff -- see the anchor-shift contract in this
    module's docstring).

    The fingerprint marker is always appended via
    :func:`securescan.review_marker.add_fingerprint_marker` so the
    upsert path in ``post-review.sh`` can match the comment on a
    re-run regardless of which suggestion blocks rendered this
    time around.
    """
    severity_value = getattr(finding.severity, "value", finding.severity)
    severity_str = str(severity_value).upper()
    scanner = finding.scanner or "scanner"
    title = _linkify_title(finding, repo=repo)

    blocks: list[str] = [f"**{severity_str}: {scanner}** \u2014 {title}"]

    desc = _first_sentence_or_truncate(finding.description or "")
    if desc:
        blocks.append(desc)

    remediation = (finding.remediation or "").strip()
    if remediation:
        remediation = re.sub(r"\s+", " ", remediation)
        blocks.append(f"_Remediation:_ {remediation}")

    if include_suggestions:
        if include_inline_ignore:
            ignore = build_inline_ignore_suggestion(finding)
            if ignore is not None:
                blocks.append(ignore.rstrip("\n"))
        pin = build_severity_pin_suggestion(finding)
        if pin is not None:
            blocks.append(pin.rstrip("\n"))

    body = "\n\n".join(blocks)
    fp = getattr(finding, "fingerprint", "") or ""
    if len(fp) >= FINGERPRINT_PREFIX_LEN:
        body = add_fingerprint_marker(body, fp)
    return body


def _resolve_anchor(
    finding: Finding,
    diff_map: DiffPositionMap,
    *,
    include_suggestions: bool,
) -> tuple[int | None, bool]:
    """Resolve the (position, include_inline_ignore) tuple for a finding.

    The anchor-shift logic lives here. Returns:

    - ``(position_above, True)`` when an inline-ignore is buildable
      AND both ``line_start`` and ``line_start - 1`` resolve to
      diff positions. The comment anchors at the line ABOVE so
      GitHub's ``suggestion`` fence rewrites the right line.
    - ``(position_natural, False)`` when the line above is missing
      from the diff: drop the inline-ignore suggestion, anchor
      naturally so the severity-pin reference still surfaces.
    - ``(position_natural, False)`` when no inline-ignore is
      buildable in the first place (no rule_id, no file, line<=1).
    - ``(None, False)`` when the finding's own line isn't in the
      diff -- caller routes to the body fallback bucket.
    """
    file_path = finding.file_path
    line_start = finding.line_start
    if not file_path or line_start is None:
        return None, False

    natural = diff_map.lookup(file_path, line_start)
    if natural is None:
        return None, False

    if not include_suggestions:
        return natural, False

    ignore = build_inline_ignore_suggestion(finding)
    if ignore is None:
        return natural, False

    position_above = diff_map.lookup(file_path, line_start - 1)
    if position_above is None:
        return natural, False
    return position_above, True


def _summary_table_lines(
    *,
    new_label: str,
    fixed_label: str,
    new_count: int,
    fixed_count: int,
    inline_count: int,
    body_fallback_count: int,
) -> list[str]:
    return [
        "| Change | Count |",
        "|---|---:|",
        f"| {new_label} | {new_count} |",
        f"| {fixed_label} | {fixed_count} |",
        f"| Inline comments | {inline_count} |",
        f"| Body fallback | {body_fallback_count} |",
    ]


def _render_body_fallback_section(
    title: str,
    findings: list[Finding],
    *,
    repo: str | None,
) -> list[str]:
    """Render a ``### {title}`` section with per-severity sub-sections."""
    lines: list[str] = [f"### {title} ({len(findings)})", ""]
    if not findings:
        lines.append("_None._")
        lines.append("")
        return lines

    buckets: dict[Severity, list[Finding]] = {sev: [] for sev in _SEVERITY_ORDER}
    for f in findings:
        if f.severity in buckets:
            buckets[f.severity].append(f)
    for sev in buckets:
        buckets[sev] = sort_findings_canonical(buckets[sev])

    for sev in _SEVERITY_ORDER:
        bucket = buckets[sev]
        if not bucket:
            continue
        lines.append(f"#### {_SEVERITY_LABEL[sev]} ({len(bucket)})")
        lines.append("")
        for f in bucket:
            scanner = f.scanner or "scanner"
            title_md = _linkify_title(f, repo=repo)
            ref = ""
            if f.file_path:
                if f.line_start:
                    ref = f" `{f.file_path}:{f.line_start}`"
                else:
                    ref = f" `{f.file_path}`"
            lines.append(f"- **{title_md}** ({scanner}){ref}")
            desc = _first_sentence_or_truncate(f.description or "")
            if desc:
                lines.append(f"  {desc}")
        lines.append("")
    return lines


def _render_fixed_section(
    title: str,
    findings: list[Finding],
    *,
    repo: str | None,
    commit_short: str,
) -> list[str]:
    """Render the fixed/disappeared section with a ``Fixed in <sha>`` trailer."""
    lines: list[str] = [f"### {title} ({len(findings)})", ""]
    if not findings:
        lines.append("_None._")
        lines.append("")
        return lines

    for f in sort_findings_canonical(findings):
        scanner = f.scanner or "scanner"
        title_md = _linkify_title(f, repo=repo)
        ref = ""
        if f.file_path:
            if f.line_start:
                ref = f" `{f.file_path}:{f.line_start}`"
            else:
                ref = f" `{f.file_path}`"
        lines.append(f"- **{title_md}** ({scanner}){ref} -- Fixed in `{commit_short}`")
    lines.append("")
    return lines


def _build_review_body(
    *,
    mode: RenderMode,
    new_findings: list[Finding],
    fixed_findings: list[Finding],
    body_fallback_findings: list[Finding],
    inline_count: int,
    commit_id: str,
    repo: str | None,
) -> str:
    """Compose the overall review-body Markdown.

    Structure: marker line, heading, summary table, then a
    per-severity body-fallback section (only when there are any
    findings without an inline anchor) and a fixed-section (only
    when ``fixed_findings`` is non-empty). The marker is ALWAYS
    the first line so the action's upsert grep can find it
    unconditionally -- same invariant as TS7's PR-comment marker.
    """
    if mode == "compare":
        marker = MARKER_REVIEW_COMPARE
        heading = "## SecureScan baseline-drift review"
        new_label = "New since baseline"
        fixed_label = "Disappeared since baseline"
        body_fallback_title = "Findings without inline anchor"
        fixed_section_title = "Disappeared since baseline"
    else:
        marker = MARKER_REVIEW
        heading = "## SecureScan review"
        new_label = "New findings"
        fixed_label = "Fixed findings"
        body_fallback_title = "Findings without inline anchor"
        fixed_section_title = "Fixed findings"

    commit_short = (commit_id or "")[:7]
    body_fallback_count = len(body_fallback_findings)

    lines: list[str] = [marker, heading, ""]
    lines.extend(
        _summary_table_lines(
            new_label=new_label,
            fixed_label=fixed_label,
            new_count=len(new_findings),
            fixed_count=len(fixed_findings),
            inline_count=inline_count,
            body_fallback_count=body_fallback_count,
        )
    )
    lines.append("")

    if body_fallback_findings:
        lines.extend(
            _render_body_fallback_section(
                body_fallback_title,
                body_fallback_findings,
                repo=repo,
            )
        )

    if fixed_findings:
        lines.extend(
            _render_fixed_section(
                fixed_section_title,
                fixed_findings,
                repo=repo,
                commit_short=commit_short,
            )
        )

    while lines and lines[-1] == "":
        lines.pop()
    lines.append("")
    return "\n".join(lines)


def render_review(
    changeset: ChangeSet | None = None,
    findings: list[Finding] | None = None,
    *,
    commit_id: str,
    diff_text: str,
    mode: RenderMode = "diff",
    event: ReviewEvent = "COMMENT",
    repo: str | None = None,
    include_suggestions: bool = True,
) -> ReviewPayload:
    """Build a :class:`ReviewPayload` from a ChangeSet or a flat list.

    Two input shapes:

    - ``changeset`` (preferred for ``securescan diff`` /
      ``securescan compare``): use ``changeset.new`` as the
      inline-comment source and ``changeset.fixed`` for the
      "Fixed in <sha>" trailer in the body.
    - ``findings`` (the ``securescan scan`` path): treat the
      flat list as the new findings; no fixed bucket.

    For each new finding the renderer:

    1. Resolves ``(file_path, line_start)`` to a diff position
       via :func:`parse_unified_diff(diff_text)`.
    2. If a position is found AND inline-ignore is buildable,
       attempts to shift the anchor up one line so the
       ``suggestion`` fence rewrites the right source line. If
       the line above isn't in the diff, drops the inline-ignore
       suggestion (keeps the severity-pin) and anchors naturally.
    3. If no position is found, routes the finding to the body
       fallback bucket so it shows up in the review's overall
       body Markdown.

    Comments are sorted by ``(path, position,
    fingerprint_prefix)`` for byte-identical re-render output.
    The fingerprint prefix tiebreaker matters when two findings
    legitimately share a (path, position) -- e.g., two scanners
    flagging the same line.

    No wall-clock timestamps anywhere; same inputs ->
    byte-identical ``to_api_dict()`` and JSON serialisation.
    """
    if changeset is not None:
        new_findings: list[Finding] = list(changeset.new)
        fixed_findings: list[Finding] = list(changeset.fixed)
    else:
        new_findings = list(findings or [])
        fixed_findings = []

    populate_fingerprints(new_findings)
    populate_fingerprints(fixed_findings)

    diff_map = parse_unified_diff(diff_text or "")

    inline_comments: list[ReviewComment] = []
    body_fallback: list[Finding] = []

    for finding in new_findings:
        position, include_inline_ignore = _resolve_anchor(
            finding,
            diff_map,
            include_suggestions=include_suggestions,
        )
        if position is None or not finding.file_path:
            body_fallback.append(finding)
            continue
        body = render_inline_comment_body(
            finding,
            repo=repo,
            include_suggestions=include_suggestions,
            include_inline_ignore=include_inline_ignore,
        )
        inline_comments.append(
            ReviewComment(path=finding.file_path, position=position, body=body)
        )

    inline_comments.sort(
        key=lambda c: (
            c.path,
            c.position,
            extract_fingerprint(c.body) or "",
        )
    )

    review_body = _build_review_body(
        mode=mode,
        new_findings=new_findings,
        fixed_findings=fixed_findings,
        body_fallback_findings=sort_findings_canonical(body_fallback),
        inline_count=len(inline_comments),
        commit_id=commit_id,
        repo=repo,
    )

    return ReviewPayload(
        commit_id=commit_id,
        event=event,
        body=review_body,
        comments=tuple(inline_comments),
    )


def render_review_json(
    changeset: ChangeSet | None = None,
    findings: list[Finding] | None = None,
    *,
    commit_id: str,
    diff_text: str,
    mode: RenderMode = "diff",
    event: ReviewEvent = "COMMENT",
    repo: str | None = None,
    include_suggestions: bool = True,
) -> str:
    """Convenience: ``render_review`` then JSON-serialise.

    Used by the CLI's ``--output github-review`` path. The
    serialiser is fixed at ``indent=2, sort_keys=True,
    ensure_ascii=False`` so the same inputs produce
    byte-identical JSON across platforms (no hash randomisation
    bleed-through, no platform-default encoding surprises).
    """
    payload = render_review(
        changeset=changeset,
        findings=findings,
        commit_id=commit_id,
        diff_text=diff_text,
        mode=mode,
        event=event,
        repo=repo,
        include_suggestions=include_suggestions,
    )
    return json.dumps(
        payload.to_api_dict(),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
