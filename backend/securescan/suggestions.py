"""GitHub ``suggestion`` block builders for mechanical fixes.

v0.4.0 ships two suggestion types:

  1. inline-ignore: when reviewing a finding the team agrees should
     be suppressed locally, suggest adding the
     ``# securescan: ignore <RULE-ID>`` comment one line above
     (matches TS2's parsing rules; one-click commit by reviewer).

  2. severity-pin: when a finding fires at the wrong severity for
     this codebase, suggest the matching ``severity_overrides:`` line
     for ``.securescan.yml``. This is a comment-only suggestion (it
     edits a file the inline comment isn't anchored to), rendered
     in a fenced block but NOT a ``suggestion`` block -- it's a copy-
     paste reference, not a one-click commit.

Future versions can add typosquat-fix suggestions (replace
``plain-crypto-js`` with ``crypto-js`` in package.json), AI-generated
refactor suggestions, etc.

Why two flavours, not one
-------------------------
GitHub's ``suggestion`` code-fence is interpreted by the UI as a
one-click commit that REPLACES the comment-anchored line(s). That's a
perfect fit for an in-file edit (case 1) but a footgun for a
cross-file edit (case 2): a one-click commit on an inline comment
about ``src/auth.py:42`` cannot edit ``.securescan.yml`` -- GitHub
would rewrite line 42 of ``src/auth.py`` with literal YAML. So the
severity-pin builder deliberately emits a ``yaml`` fence, NOT a
``suggestion`` fence; the reviewer copy-pastes it into the config
file. The distinction is enforced by tests so a future refactor can't
silently turn the YAML reference into a destructive one-click action.

Anchor-shift contract (inline-ignore)
-------------------------------------
``build_inline_ignore_suggestion`` emits a single-line suggestion that
is intended to REPLACE the line ABOVE the finding (the line at
``finding.line_start - 1``). The renderer in IR4 must therefore anchor
the inline review comment one line above ``finding.line_start``, NOT
on the finding's own line. See the function docstring for details;
this is a behavioural contract pinned by tests.
"""
from __future__ import annotations

from pathlib import Path

from .models import Finding

# File extensions and their canonical comment prefix.
#
# Synced with suppression._COMMENT_PREFIXES (TS2). When TS2 grows a
# new extension, mirror the change here so an inline-ignore
# suggestion produced for that file type round-trips cleanly through
# the next scan's parser. The shape is flipped (ext -> prefix) for
# O(1) lookup; semantically identical to TS2's prefix -> exts map.
_COMMENT_PREFIX_BY_EXT: dict[str, str] = {
    # ``#``-style
    ".py": "#",
    ".rb": "#",
    ".sh": "#",
    ".bash": "#",
    ".zsh": "#",
    ".yml": "#",
    ".yaml": "#",
    ".toml": "#",
    ".ini": "#",
    ".cfg": "#",
    ".conf": "#",
    ".tf": "#",
    ".tfvars": "#",
    ".dockerfile": "#",
    ".pl": "#",
    ".pm": "#",
    ".r": "#",
    # ``//``-style
    ".js": "//",
    ".mjs": "//",
    ".cjs": "//",
    ".ts": "//",
    ".jsx": "//",
    ".tsx": "//",
    ".go": "//",
    ".java": "//",
    ".kt": "//",
    ".kts": "//",
    ".rs": "//",
    ".c": "//",
    ".cc": "//",
    ".cpp": "//",
    ".cxx": "//",
    ".h": "//",
    ".hpp": "//",
    ".hh": "//",
    ".swift": "//",
    ".scala": "//",
    ".groovy": "//",
    ".dart": "//",
    ".cs": "//",
    ".php": "//",
    # ``--``-style
    ".sql": "--",
    ".lua": "--",
    ".hs": "--",
    ".elm": "--",
    ".ada": "--",
}

# Filenames with no (useful) extension. Synced with
# suppression._FILENAME_OVERRIDES (TS2).
_COMMENT_PREFIX_BY_FILENAME: dict[str, str] = {
    "dockerfile": "#",
    "containerfile": "#",
    "makefile": "#",
    "gnumakefile": "#",
    "rakefile": "#",
    "gemfile": "#",
}

# Fallback prefix for unknown extensions. ``#`` is the most common
# comment style across the languages SecureScan scans, and TS2 will
# parse it on any file regardless of extension (the TS2 parser falls
# back to all three known prefixes when the file type is unknown).
_DEFAULT_COMMENT_PREFIX = "#"

# Severity demotion chain used by ``build_severity_pin_suggestion``
# when no explicit ``new_severity`` is given. ``info -> info`` is the
# floor: there's no severity below info, so we suggest pinning at
# info rather than something nonsensical.
_DEMOTION_CHAIN: dict[str, str] = {
    "critical": "high",
    "high": "medium",
    "medium": "low",
    "low": "info",
    "info": "info",
}


def comment_prefix_for(file_path: str | Path) -> str:
    """Return the canonical inline-comment prefix for ``file_path``.

    Lookup order:

      1. Lowercased extension (``Path(file_path).suffix.lower()``).
      2. Lowercased basename (catches extensionless names like
         ``Dockerfile``, ``Makefile``).
      3. ``_DEFAULT_COMMENT_PREFIX`` (``#``).

    Mirrors TS2's per-language dispatch closely enough that an
    inline-ignore comment built for any path here will be parseable
    by ``securescan.suppression.parse_file_ignores`` on the next scan.
    """
    p = Path(file_path)
    ext = p.suffix.lower()
    if ext in _COMMENT_PREFIX_BY_EXT:
        return _COMMENT_PREFIX_BY_EXT[ext]
    name = p.name.lower()
    if name in _COMMENT_PREFIX_BY_FILENAME:
        return _COMMENT_PREFIX_BY_FILENAME[name]
    return _DEFAULT_COMMENT_PREFIX


def build_inline_ignore_suggestion(
    finding: Finding,
    *,
    indent: str = "",
) -> str | None:
    """Return a GitHub ``suggestion`` block proposing the inline-ignore
    comment one line above the finding.

    Anchor-shift contract
    ---------------------
    The emitted ``suggestion`` block is intended to REPLACE the line
    ABOVE the finding -- i.e., the line at ``finding.line_start - 1``
    in the file. The IR4 renderer that consumes this markdown MUST
    therefore anchor the inline review comment at
    ``finding.line_start - 1``, NOT at the finding's own line. If the
    renderer instead anchored on ``finding.line_start``, GitHub would
    overwrite the line containing the finding with the ignore comment,
    silently deleting the offending code instead of suppressing the
    rule. This contract is pinned by tests; do not "simplify" it
    without updating IR4.

    Why we don't include the original line above
    --------------------------------------------
    A safer suggestion would carry the original content of line N-1
    plus a new ignore comment so committing it inserts rather than
    replaces. Doing so requires reading the file from this builder,
    which would couple a pure markdown helper to the filesystem and
    break determinism in unit tests. Reviewers preview the diff
    GitHub renders before clicking "Commit suggestion", so the
    replacement semantics are visible at click time.

    The ``indent`` parameter is the leading whitespace the caller
    wants preserved on the inserted comment line; pass the original
    line N-1's indent so the inserted comment lines up with the
    surrounding code.

    Returns ``None`` (and emits no suggestion) when:

      * ``finding.rule_id`` is ``None`` -- nothing to ignore by name.
      * ``finding.file_path`` is ``None`` -- can't pick a comment style.
      * ``finding.line_start`` is ``None`` or ``<= 1`` -- there is no
        "line above" to anchor on.
    """
    rule_id = getattr(finding, "rule_id", None)
    file_path = getattr(finding, "file_path", None)
    line_start = getattr(finding, "line_start", None)

    if rule_id is None or file_path is None:
        return None
    if line_start is None or line_start <= 1:
        return None

    prefix = comment_prefix_for(file_path)
    return (
        "Suppress this finding for the line below by committing this:\n"
        "\n"
        "```suggestion\n"
        f"{indent}{prefix} securescan: ignore {rule_id}\n"
        "```\n"
    )


def build_severity_pin_suggestion(
    finding: Finding,
    *,
    new_severity: str | None = None,
) -> str | None:
    """Return a copy-paste-only Markdown block showing the
    ``.securescan.yml`` YAML edit to pin this finding's severity.

    This is intentionally NOT a GitHub ``suggestion`` block: the edit
    targets ``.securescan.yml`` at the repo root, but the inline
    review comment is anchored on the finding's source line in some
    other file. A ``suggestion`` fence here would let a reviewer
    one-click-commit literal YAML on top of their source file --
    almost always the wrong thing. The fenced block uses ``yaml`` so
    the reviewer gets syntax highlighting and a copy button without
    the destructive one-click behaviour.

    ``new_severity`` defaults to one step below ``finding.severity``:
    critical -> high -> medium -> low -> info -> info. ``info`` is the
    floor (info stays info). Pass an explicit string to override.

    Returns ``None`` when ``finding.rule_id`` is ``None`` (no rule to
    pin).
    """
    rule_id = getattr(finding, "rule_id", None)
    if rule_id is None:
        return None

    if new_severity is None:
        current = getattr(finding, "severity", None)
        # ``Severity`` is a ``str``-Enum; .value is the lowercase name.
        current_value = getattr(current, "value", current)
        current_key = str(current_value or "").lower()
        new_severity = _DEMOTION_CHAIN.get(current_key, "info")

    return (
        "Pin this rule's severity in `.securescan.yml`:\n"
        "\n"
        "```yaml\n"
        "severity_overrides:\n"
        f"  {rule_id}: {new_severity}\n"
        "```\n"
    )
