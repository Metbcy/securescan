"""Suppression mechanisms: inline ignore comments, config-driven ignored
rules, and baseline fingerprint matches.

This module ships the inline-comment parser today (TS2). A subsequent
commit (TS3) extends it with SuppressionContext and the precedence
resolver across all three mechanisms.

Inline directive grammar
------------------------
A "marker" is the literal token ``securescan:`` inside a source comment.
Three directives are recognised:

* ``ignore`` / ``ignore-this-line`` — suppress findings on the same line
  the comment is on. The two are exact synonyms; we accept both because
  reviewers tend to type whichever feels more natural.
* ``ignore-next-line`` — suppress findings on ``line + 1`` (the literal
  next line, NOT next-non-blank-line; semantics stay dead-obvious so
  users can put the comment immediately above the finding line).

Examples (all valid)::

    # securescan: ignore RULE-A
    // securescan: ignore RULE-A, RULE-B
    -- securescan: ignore-next-line *
    # Securescan: IGNORE rule-x   (case-insensitive)

The wildcard ``*`` suppresses every finding on the target line regardless
of rule id. Multiple rule ids are comma-separated.

Per-language dispatch
---------------------
We pick candidate comment prefixes by file extension (with a couple of
explicit filename overrides like ``Dockerfile``). When the extension is
unrecognised we fall back to all three known prefixes — false positives
on lines that happen to contain the marker are acceptable; we'd rather
have suppression work on ``.unknown`` files than not.

Known limitations
-----------------
* We do NOT parse string literals vs. comments. A ``# securescan:``
  marker that lives inside a multi-line string still triggers
  suppression. Users should avoid the literal ``securescan:`` namespace
  inside string content (or use case-mangling like ``Securescan:`` —
  the regex is case-insensitive but the marker still needs the literal
  ``securescan:`` prefix to be intentional code, which strings rarely
  contain by accident).
* ``ignore-next-line`` targets ``line + 1`` literally; if the user
  inserts a blank line between the comment and the finding, the
  suppression will not apply. This is intentional (predictable
  semantics > clever guessing).

Failure contract
----------------
``parse_file_ignores`` and ``IgnoreMap.applies_to`` NEVER raise. Missing
files, unreadable files, binary blobs, ``None`` arguments — every
failure mode degrades to "no suppression", because a parser that crashes
the scan is worse than one that occasionally misses a directive.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# Recognised comment prefixes.  We deliberately keep this small and
# extensible: most languages use one of these three styles.
_COMMENT_PREFIXES: dict[str, tuple[str, ...]] = {
    "#":  ("py", "rb", "sh", "bash", "zsh", "yml", "yaml", "toml", "ini",
           "cfg", "conf", "tf", "tfvars", "dockerfile", "pl", "pm", "r"),
    "//": ("js", "mjs", "cjs", "ts", "jsx", "tsx", "go", "java", "kt",
           "kts", "rs", "c", "cc", "cpp", "cxx", "h", "hpp", "hh", "swift",
           "scala", "groovy", "dart", "cs", "php"),
    "--": ("sql", "lua", "hs", "elm", "ada"),
}
_ALL_PREFIXES: tuple[str, ...] = tuple(_COMMENT_PREFIXES.keys())

# Filenames (lower-cased, no extension) that map to a known prefix.
_FILENAME_OVERRIDES: dict[str, str] = {
    "dockerfile": "#",
    "containerfile": "#",
    "makefile": "#",
    "gnumakefile": "#",
    "rakefile": "#",
    "gemfile": "#",
}

# The token "securescan:" is the namespace marker.  We match it loosely
# (case-insensitive, optional whitespace around the colon) but require
# one of: ignore | ignore-this-line | ignore-next-line.  Longer
# directives are listed first in the alternation so they win the match.
#
# The leading ``(?:^|\s)`` is a poor-man's word boundary: it prevents
# accidental matches inside identifiers like ``mysecurescan:foo`` while
# still allowing the marker to follow any whitespace (i.e. any comment
# prefix).  We do NOT anchor on a comment prefix here; callers handle
# the per-language pre-filter.
_IGNORE_RE = re.compile(
    r"""
    (?:^|\s)                        # word boundary or start of comment payload
    securescan
    \s*:\s*
    (ignore-next-line|ignore-this-line|ignore)
    \s+
    ([A-Za-z0-9._\-/*,\s]+?)        # comma-separated rule IDs (or '*')
    (?:\s*$|\s+\#|\s+--|\s+//)      # end-of-comment terminator
    """,
    re.IGNORECASE | re.VERBOSE,
)


@dataclass(frozen=True)
class IgnoreMark:
    """A single ignore directive parsed from a source comment.

    Targets the line the comment is on (for ``ignore`` /
    ``ignore-this-line``) or ``line + 1`` (for ``ignore-next-line``).
    """

    file: Path
    line: int
    target_line: int
    rule_ids: frozenset[str]
    directive: str


def _prefixes_for(path: Path) -> tuple[str, ...]:
    """Return the comment prefixes worth scanning for on this path.

    Falls back to every known prefix when the extension/filename isn't
    recognised — see module docstring for the rationale.
    """
    name = path.name.lower()
    if name in _FILENAME_OVERRIDES:
        return (_FILENAME_OVERRIDES[name],)
    # Allow ``Dockerfile.dev`` / ``Makefile.inc`` style siblings.
    stem = name.split(".", 1)[0]
    if stem in _FILENAME_OVERRIDES:
        return (_FILENAME_OVERRIDES[stem],)

    suffix = path.suffix.lower().lstrip(".")
    if suffix:
        for prefix, exts in _COMMENT_PREFIXES.items():
            if suffix in exts:
                return (prefix,)

    return _ALL_PREFIXES


def parse_file_ignores(path: Path) -> list[IgnoreMark]:
    """Extract every inline ignore directive from ``path``.

    Returns an empty list on any failure (missing file, permission
    error, decode error). NEVER raises.
    """
    if path is None:
        return []
    try:
        if not path.exists() or not path.is_file():
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return []

    prefixes = _prefixes_for(path)
    marks: list[IgnoreMark] = []

    for line_no, line in enumerate(text.splitlines(), start=1):
        # Cheap pre-filter: a real ignore directive must live in a
        # comment, so the line must contain at least one applicable
        # comment prefix. This is conservative — see "Known limitations".
        if not any(p in line for p in prefixes):
            continue

        for match in _IGNORE_RE.finditer(line):
            directive = match.group(1).lower()
            raw_ids = match.group(2)
            ids = frozenset(
                token.strip()
                for token in raw_ids.split(",")
                if token.strip()
            )
            if not ids:
                continue

            target_line = (
                line_no + 1 if directive == "ignore-next-line" else line_no
            )
            marks.append(
                IgnoreMark(
                    file=path,
                    line=line_no,
                    target_line=target_line,
                    rule_ids=ids,
                    directive=directive,
                )
            )

    return marks


class IgnoreMap:
    """Lazy per-file cache of inline ignore directives.

    ``parse_file_ignores`` is potentially expensive (file IO + regex on
    every line); the typical scan touches the same file many times
    across many findings, so we memoise per-path within a single scan
    run. The cache is unbounded by design — a scan run rarely touches
    more than a few thousand files and the per-file footprint is tiny.
    """

    def __init__(self) -> None:
        self._cache: dict[Path, list[IgnoreMark]] = {}

    def _marks_for(self, path: Path | str | None) -> list[IgnoreMark]:
        if path is None:
            return []
        p = path if isinstance(path, Path) else Path(path)
        if p not in self._cache:
            # Resolve through the module attribute so tests can
            # monkey-patch ``parse_file_ignores`` and observe the
            # cache behaviour.
            self._cache[p] = parse_file_ignores(p)
        return self._cache[p]

    def applies_to(
        self,
        path: Path | str | None,
        line: int | None,
        rule_id: str | None,
    ) -> bool:
        """True iff there is an inline ignore directive at ``path:line``
        for ``rule_id``.

        Returns ``False`` (does NOT suppress) when ``path``, ``line`` or
        ``rule_id`` is missing or unreadable.
        """
        return bool(self.reasons(path, line, rule_id))

    def reasons(
        self,
        path: Path | str | None,
        line: int | None,
        rule_id: str | None,
    ) -> list[IgnoreMark]:
        """Same as :meth:`applies_to`, but returns the matching
        :class:`IgnoreMark` instances for audit logging."""
        if path is None or line is None or rule_id is None:
            return []

        marks = self._marks_for(path)
        return [
            mark
            for mark in marks
            if mark.target_line == line
            and ("*" in mark.rule_ids or rule_id in mark.rule_ids)
        ]
