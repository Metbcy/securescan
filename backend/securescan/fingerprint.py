"""Stable per-finding fingerprint.

Foundational primitive used by the diff classifier (SS4) and the PR-comment
renderer (SS7). The goal is a content-addressable identity for a finding that
survives trivial code edits (whitespace tweaks, line shifts, trailing
comments) but distinguishes genuinely different findings (different scanner,
file, rule, or CWE).

Hash recipe (sha256, hex, 64 chars):

    scanner | rule_id | file_path | normalized_line_context | cwe

Empty fields are kept as empty strings (not skipped) so the order remains
unambiguous. File paths are normalized to forward slashes; if absolute and
the working directory is a prefix, they are made repo-relative.

Line-context normalization is best-effort, not a real Python parser. It
lowercases, collapses whitespace, joins multi-line snippets with a single
space, and strips trailing comments (#, //, --, /* */). When no snippet is
available, the fallback context is "" so two findings with the same scanner
+ file + rule + cwe still collide stably (which is what we want for the diff
classifier when scanners do not give us a code snippet).
"""
from __future__ import annotations

import hashlib
import os
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Finding


_WS_RE = re.compile(r"\s+")
_TRAILING_HASH_COMMENT = re.compile(r"\s*#.*$")
_TRAILING_DBLSLASH_COMMENT = re.compile(r"\s*//.*$")
_TRAILING_DBLDASH_COMMENT = re.compile(r"\s*--.*$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _normalize_file_path(file_path: str | None) -> str:
    if not file_path:
        return ""
    path = file_path.replace("\\", "/")
    if os.path.isabs(path):
        cwd = os.getcwd().replace("\\", "/").rstrip("/")
        if cwd and path.startswith(cwd + "/"):
            path = path[len(cwd) + 1 :]
    return path


def _strip_comments(line: str) -> str:
    line = _BLOCK_COMMENT.sub(" ", line)
    line = _TRAILING_HASH_COMMENT.sub("", line)
    line = _TRAILING_DBLSLASH_COMMENT.sub("", line)
    line = _TRAILING_DBLDASH_COMMENT.sub("", line)
    return line


def normalized_line_context(finding: "Finding") -> str:
    """Return a fuzzy, stable representation of the finding's code context.

    A line that is moved up or down, re-indented, or annotated with a trailing
    comment must produce the same string. When no snippet is available we
    return "" — the fingerprint then falls back to (scanner, rule, file, cwe)
    identity, which is still stable across line-shift refactors.
    """
    snippet = ""
    if finding.metadata:
        raw = finding.metadata.get("line_snippet")
        if isinstance(raw, str):
            snippet = raw
        elif isinstance(raw, (list, tuple)):
            snippet = " ".join(str(part) for part in raw)

    if not snippet:
        return ""

    snippet = snippet.replace("\r\n", "\n").replace("\r", "\n")
    cleaned_lines = [_strip_comments(line) for line in snippet.split("\n")]
    joined = " ".join(cleaned_lines)
    joined = _WS_RE.sub(" ", joined).strip().lower()
    return joined


def fingerprint(finding: "Finding") -> str:
    """Return a 64-char hex sha256 fingerprint of a finding.

    See module docstring for the hash recipe and rationale.
    """
    parts = [
        finding.scanner or "",
        finding.rule_id or "",
        _normalize_file_path(finding.file_path),
        normalized_line_context(finding),
        finding.cwe or "",
    ]
    payload = "|".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def populate_fingerprints(findings: list["Finding"]) -> None:
    """Mutate findings in place, setting `fingerprint` on each one.

    Only findings whose `fingerprint` is empty are touched, so this is
    idempotent and safe to call repeatedly. Findings that already carry a
    fingerprint (e.g. loaded from the DB after an earlier run) are left as-is.
    """
    for f in findings:
        if not getattr(f, "fingerprint", ""):
            f.fingerprint = fingerprint(f)
