"""Map (file_path, line_number) to GitHub PR Review API position offsets.

GitHub requires the ``position`` integer on each inline review comment;
it's the line index INSIDE the unified diff (not the source file's
line number). This module parses the unified diff produced by
``git diff <base>..<head>`` and builds the mapping.

Position semantics (per the GitHub Reviews API docs):

* The position counter starts at the first ``@@`` hunk header in a file.
  The ``@@`` line itself is conceptually "position 0"; the line just
  below it is position 1.
* The counter increments on EVERY line of the diff body for that file:
  hunk headers (including subsequent ``@@``), context lines (`` ``),
  added lines (``+``), and removed lines (``-``).
* The counter resets when a new file starts (a fresh ``diff --git``).
* Lines NOT counted toward position: ``diff --git``, ``index``,
  ``--- a/...``, ``+++ b/...``, mode/similarity/rename headers,
  ``Binary files ...`` markers, and ``\\ No newline at end of file``.
* Only context (`` ``) and added (``+``) lines have a head-side line
  number; only those go into the lookup map. Removed lines exist only
  in the base, so a comment with their head-line number is meaningless.
"""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass
from pathlib import Path

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _unquote_path(token: str) -> str:
    """Decode a git-style quoted path.

    Git quotes paths containing special characters (spaces, non-ASCII,
    control bytes) with C-style escapes inside double quotes. For our
    purposes the common case is just spaces, but we decode the full
    escape syntax so unusual paths round-trip correctly.
    """
    if len(token) < 2 or not (token.startswith('"') and token.endswith('"')):
        return token
    inner = token[1:-1]
    try:
        decoded, _ = codecs.escape_decode(inner.encode("utf-8"))
        return decoded.decode("utf-8", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return inner


def _strip_diff_prefix(path: str, prefix: str) -> str:
    if path.startswith(prefix):
        return path[len(prefix) :]
    return path


def _extract_target_path(plus_line: str) -> str | None:
    """Parse a ``+++ b/<path>`` line into the head-side path.

    Returns ``None`` for ``+++ /dev/null`` (file deleted in the head).
    """
    rest = plus_line[4:]
    if rest == "/dev/null":
        return None
    rest = _unquote_path(rest)
    return _strip_diff_prefix(rest, "b/")


@dataclass(frozen=True)
class DiffPositionMap:
    """Lookup table for GitHub review-comment positions.

    Public API:
      * ``lookup(file_path, line) -> int | None``
      * ``files() -> list[str]``

    Position is ``None`` when:
      * the file is not in the diff at all;
      * the line wasn't added or in context (e.g. it's a removed line,
        an untouched line outside any hunk, or any line the parser had
        no head-side line number for).
    """

    _by_file: dict[str, dict[int, int]]

    def lookup(self, file_path: str | Path, line: int | None) -> int | None:
        if line is None:
            return None
        key = str(file_path)
        file_map = self._by_file.get(key)
        if file_map is None:
            return None
        return file_map.get(line)

    def files(self) -> list[str]:
        return sorted(self._by_file)


def parse_unified_diff(diff_text: str) -> DiffPositionMap:
    """Build a position lookup from a unified diff string.

    The diff is expected to be the output of ``git diff`` (with the
    default ``a/`` / ``b/`` prefixes). The function never raises on
    malformed input; unknown lines are skipped silently so the parser
    is forgiving of git-version-specific framing differences.
    """
    by_file: dict[str, dict[int, int]] = {}
    current_file: str | None = None
    current_map: dict[int, int] | None = None
    position = -1
    head_line = 0
    in_binary = False

    if not diff_text:
        return DiffPositionMap(_by_file={})

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            current_file = None
            current_map = None
            position = -1
            head_line = 0
            in_binary = False
            continue
        if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
            in_binary = True
            current_file = None
            current_map = None
            continue
        if line.startswith("--- "):
            continue
        if line.startswith("+++ "):
            target = _extract_target_path(line)
            if target is None:
                current_file = None
                current_map = None
            else:
                current_file = target
                current_map = by_file.setdefault(target, {})
            position = -1
            head_line = 0
            continue
        if line.startswith("@@"):
            if current_file is None or in_binary:
                continue
            position += 1
            m = _HUNK_RE.match(line)
            if m:
                head_line = int(m.group(1))
            continue

        if current_file is None or in_binary or current_map is None:
            continue
        if not line:
            position += 1
            current_map[head_line] = position
            head_line += 1
            continue
        marker = line[0]
        if marker == " ":
            position += 1
            current_map[head_line] = position
            head_line += 1
        elif marker == "+":
            position += 1
            current_map[head_line] = position
            head_line += 1
        elif marker == "-":
            position += 1
        elif marker == "\\":
            continue
        else:
            continue

    return DiffPositionMap(_by_file=by_file)
