"""Tests for the ``securescan.git_ops`` thin git wrappers.

The diff command's ref-based mode depends on these helpers being
correct *and* on ``GitOpError`` carrying the underlying stderr -- the
diff command surfaces the error message verbatim to the user, so a
silent / generic failure mode here would make CI failures undebuggable.
"""
from __future__ import annotations

import subprocess

import pytest

from securescan.git_ops import (
    GitOpError,
    checkout,
    current_ref,
    is_clean,
    is_git_repo,
    rev_parse,
)


def _run(args, cwd):
    subprocess.run(args, cwd=str(cwd), check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    target = tmp_path / "r"
    target.mkdir()
    _run(["git", "init", "-b", "main"], target)
    _run(["git", "config", "user.email", "ss6@test.local"], target)
    _run(["git", "config", "user.name", "ss6-test"], target)
    _run(["git", "config", "commit.gpgsign", "false"], target)
    (target / "a.txt").write_text("hello\n")
    _run(["git", "add", "."], target)
    _run(["git", "commit", "-m", "initial"], target)
    return target


def test_is_git_repo_true_for_initialized(repo):
    assert is_git_repo(repo) is True


def test_is_git_repo_false_for_plain_dir(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert is_git_repo(plain) is False


def test_current_ref_returns_sha(repo):
    """``current_ref`` must return a concrete sha so the diff command's
    ``finally`` checkout can restore the user wherever they started --
    branch, tag, or detached HEAD."""
    ref = current_ref(repo)
    assert len(ref) == 40
    assert all(c in "0123456789abcdef" for c in ref)


def test_rev_parse_resolves_head(repo):
    head_sha = rev_parse(repo, "HEAD")
    assert head_sha == current_ref(repo)


def test_rev_parse_unknown_ref_raises_GitOpError(repo):
    with pytest.raises(GitOpError) as exc_info:
        rev_parse(repo, "no-such-ref-zzz")
    assert "no-such-ref-zzz" in str(exc_info.value)


def test_checkout_changes_ref(repo):
    initial_sha = current_ref(repo)
    _run(["git", "checkout", "-b", "feature"], repo)
    (repo / "b.txt").write_text("world\n")
    _run(["git", "add", "."], repo)
    _run(["git", "commit", "-m", "feature commit"], repo)
    feature_sha = current_ref(repo)
    assert feature_sha != initial_sha
    assert (repo / "b.txt").exists()

    checkout(repo, initial_sha)
    assert current_ref(repo) == initial_sha
    assert not (repo / "b.txt").exists()

    checkout(repo, feature_sha)
    assert current_ref(repo) == feature_sha
    assert (repo / "b.txt").exists()


def test_is_clean_true_for_fresh_clone(repo):
    assert is_clean(repo) is True


def test_is_clean_false_when_dirty(repo):
    (repo / "a.txt").write_text("changed\n")
    assert is_clean(repo) is False


def test_is_clean_false_when_untracked_file(repo):
    (repo / "untracked.txt").write_text("new\n")
    assert is_clean(repo) is False


def test_checkout_unknown_ref_raises_GitOpError_with_stderr(repo):
    with pytest.raises(GitOpError) as exc_info:
        checkout(repo, "nonexistent-ref-zzz")
    msg = str(exc_info.value)
    assert "nonexistent-ref-zzz" in msg
    assert "git checkout" in msg.lower() or "failed" in msg.lower()
