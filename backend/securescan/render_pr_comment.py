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
from typing import TYPE_CHECKING

from .models import Severity
from .ordering import sort_findings_canonical

if TYPE_CHECKING:
    from .diff import ChangeSet
    from .models import Finding


MARKER = "<!-- securescan:diff -->"

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

_DESCRIPTION_MAX_CHARS = 120

_SENTENCE_END = re.compile(r"(?<=[.!?])\s")


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
    finding: "Finding",
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
    findings: list["Finding"],
) -> dict[Severity, list["Finding"]]:
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
    finding: "Finding",
    *,
    repo: str | None,
    sha: str | None,
    include_remediation: bool,
) -> list[str]:
    """Render one finding as Markdown list-item lines.

    The bullet is intentionally compact (one bold title line + an
    indented description, optionally an indented remediation) so a
    100-finding PR comment doesn't blow past GitHub's 65k-char comment
    body limit on large refactors.
    """
    ref = _file_reference(finding, repo=repo, sha=sha)
    head_parts: list[str] = [f"- **{finding.title}**"]
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
    findings: list["Finding"],
    *,
    repo: str | None,
    sha: str | None,
    include_remediation: bool,
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
                ),
            )
        lines.append("")

    return lines


def render_pr_comment(
    changeset: "ChangeSet",
    *,
    repo: str | None = None,
    sha: str | None = None,
) -> str:
    """Render a ``ChangeSet`` as a Markdown PR comment body.

    ``repo`` and ``sha`` are both optional. When both are provided,
    file:line references become Markdown links to
    ``https://github.com/{repo}/blob/{sha}/{path}#L{line}``; otherwise
    they render as plain backtick-wrapped ``path:line`` text. Passing
    only one of the two also falls back to plain text — there's no
    sensible link without both.

    Empty-changeset short-circuit: when ``changeset`` has no new and no
    fixed findings the body is just the marker plus a single line
    ``_No new or fixed findings._``. The marker is ALWAYS the first
    line so the GitHub Action's upsert grep can find it
    unconditionally.

    Pure function. Same ``ChangeSet`` plus same ``repo``/``sha`` →
    byte-identical output, every time.
    """
    new_findings = list(changeset.new)
    fixed_findings = list(changeset.fixed)
    unchanged_count = len(changeset.unchanged)

    if not new_findings and not fixed_findings:
        return f"{MARKER}\n_No new or fixed findings._\n"

    lines: list[str] = [
        MARKER,
        "## SecureScan: dependency & code change review",
        "",
        "| Change | Count |",
        "|---|---:|",
        f"| New findings | {len(new_findings)} |",
        f"| Fixed findings | {len(fixed_findings)} |",
        f"| Unchanged findings | {unchanged_count} |",
        "",
    ]

    lines.extend(
        _render_section(
            "New findings",
            new_findings,
            repo=repo,
            sha=sha,
            include_remediation=True,
        ),
    )
    lines.extend(
        _render_section(
            "Fixed findings",
            fixed_findings,
            repo=repo,
            sha=sha,
            include_remediation=False,
        ),
    )

    while lines and lines[-1] == "":
        lines.pop()
    lines.append("")
    return "\n".join(lines)
