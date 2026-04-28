"""Thin synchronous git wrappers used by the ``securescan diff`` subcommand.

The diff command's ref-based mode needs to:

* read the current ref so it can restore on the way out;
* check out a base ref, scan, then check out the head ref, scan;
* refuse to clobber a dirty working tree;
* resolve ``HEAD`` (or any other symbolic ref) to a concrete sha so the
  rendered PR-comment links point at an immutable commit even when the
  user passes ``--head-ref HEAD``.

Every helper here is sync, ``cwd``-scoped, and raises ``GitOpError`` (with
the captured stderr) on failure. The diff command catches and surfaces
the message and -- crucially -- always restores the original ref in a
``try/finally`` block.

We intentionally do not use any third-party Git library: ``git`` is
already a hard dependency of the diff workflow (you can't have refs
without a git repo), and shelling out keeps the dependency surface zero
which matters for the wheel-only install path.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


class GitOpError(RuntimeError):
    """Raised when a git subprocess fails. The captured stderr is included
    verbatim in the message so the diff command can surface it to the
    user without further parsing.
    """


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
    )


def is_git_repo(target: Path) -> bool:
    """Return True iff ``target`` is inside a git working tree.

    Returns False on any failure (missing git binary, target outside a
    repo, etc.) -- callers treat "not a repo" as a user error and the
    underlying reason isn't actionable.
    """
    try:
        _run(["rev-parse", "--is-inside-work-tree"], cwd=target)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def current_ref(target: Path) -> str:
    """Return the current HEAD as a concrete sha.

    A sha (not a branch name) is returned on purpose: the diff command
    uses this value to restore the working tree at the end of a run via
    ``checkout``, and a sha works whether the user started on a branch,
    on a tag, or on a detached HEAD. The cost is that a user who
    started on ``main`` will end up on a detached HEAD pointing at
    main's sha; the working tree contents are identical and they can
    ``git checkout main`` themselves to re-attach. This is a deliberate
    trade-off in favour of "always restorable" semantics.
    """
    try:
        result = _run(["rev-parse", "HEAD"], cwd=target)
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise GitOpError(
            f"git rev-parse HEAD failed: {exc.stderr.strip()}"
        ) from exc


def rev_parse(target: Path, ref: str) -> str:
    """Resolve any symbolic ref to a concrete sha. Raises ``GitOpError``
    if ``ref`` cannot be resolved.

    Used by the diff command to pin ``--head-ref HEAD`` to the immutable
    commit sha *before* the base checkout, so the rendered PR comment's
    file links remain stable even though HEAD will move during the run.
    """
    try:
        result = _run(["rev-parse", ref], cwd=target)
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise GitOpError(
            f"git rev-parse {ref!r} failed: {exc.stderr.strip()}"
        ) from exc


def is_clean(target: Path) -> bool:
    """Return True iff the working tree has no uncommitted changes.

    The diff command uses this as a guard rail before any ``checkout``:
    if the user has unstaged edits we refuse rather than risk losing
    their work. A failure to query status itself raises ``GitOpError``;
    callers should treat that as a hard failure rather than "assume
    clean".
    """
    try:
        result = _run(["status", "--porcelain"], cwd=target)
        return result.stdout.strip() == ""
    except subprocess.CalledProcessError as exc:
        raise GitOpError(f"git status failed: {exc.stderr.strip()}") from exc


def checkout(target: Path, ref: str) -> None:
    """Check out ``ref`` in ``target``. Raises ``GitOpError`` on failure
    with the underlying git stderr included verbatim so the diff
    command can surface it (typical failure modes: dirty tree, ref not
    found, conflicting local changes).
    """
    try:
        _run(["checkout", ref], cwd=target)
    except subprocess.CalledProcessError as exc:
        raise GitOpError(
            f"git checkout {ref!r} failed: {exc.stderr.strip()}"
        ) from exc
