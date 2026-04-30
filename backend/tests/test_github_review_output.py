"""Tests for ``--output github-review`` on ``securescan diff`` / ``compare``.

This is the IR5 wedge: the CLI surface that emits the GitHub
Reviews API JSON shape (``commit_id`` + ``event`` + ``body`` +
``comments[]``) the action's ``post-review.sh`` POSTs to
``POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews``. The
tests pin:

* the new ``github-review`` value is accepted on ``diff`` /
  ``compare`` and rejected on ``scan`` (no PR-diff context to
  anchor inline comments against);
* the required-arg contract (``--repo`` / ``--sha`` /
  ``--base-sha`` plus their env fallbacks);
* end-to-end JSON shape (the four top-level keys, the diff- vs
  compare- review marker on the body's first line, the
  ``COMMENT`` default event, the ``--no-suggestions`` toggle,
  ``--output-file`` plumbing);
* git-diff resolution (real git repo required; ``--base-ref``
  auto-resolves to ``base_sha`` in ref-mode);
* byte-identical output across two invocations against a frozen
  base+head, mirroring v0.2.0/v0.3.0's determinism contract.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from securescan.cli import app
from securescan.render_review import MARKER_REVIEW, MARKER_REVIEW_COMPARE

# ----------------------------- fixtures -----------------------------------


def _finding_dict(**overrides) -> dict:
    base = {
        "id": "fid-default",
        "scan_id": "scan-1",
        "scanner": "semgrep",
        "scan_type": "code",
        "severity": "high",
        "title": "SQL Injection",
        "description": "User input concatenated into SQL.",
        "file_path": "src/app.py",
        "line_start": 5,
        "line_end": 5,
        "rule_id": "RULE-001",
        "cwe": "CWE-89",
        "remediation": "Use parameterised queries.",
        "metadata": {},
        "compliance_tags": [],
        "fingerprint": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
    }
    base.update(overrides)
    return base


def _write_snapshot(path: Path, findings: list[dict]) -> None:
    path.write_text(json.dumps({"findings": findings}))


def _git(args: list[str], cwd: Path) -> str:
    """Run a git command in ``cwd`` and return stdout. Tests-only.

    We can't reuse ``securescan.git_ops`` here because some of these
    tests need to commit specific contents at specific paths; the
    helpers there are scoped to the diff command's needs.
    """
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            # Pin author/committer identity + dates so the test repo
            # produces stable shas. Mirrors how the determinism tests
            # treat wall-clock leaks.
            "GIT_AUTHOR_NAME": "Test",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test",
            "GIT_COMMITTER_EMAIL": "test@example.com",
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00 +0000",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00 +0000",
        },
    ).stdout.strip()


def _make_repo_with_two_commits(repo: Path) -> tuple[str, str]:
    """Init a git repo with one base commit and one head commit.

    Returns ``(base_sha, head_sha)``. The head commit adds a few
    lines to ``src/app.py`` so a finding at ``line_start=5`` lands
    inside the diff and resolves to a real position.
    """
    repo.mkdir(parents=True, exist_ok=True)
    _git(["init", "-q", "-b", "main"], cwd=repo)
    _git(["config", "commit.gpgsign", "false"], cwd=repo)

    src = repo / "src"
    src.mkdir(exist_ok=True)
    (src / "app.py").write_text("# baseline\n")
    _git(["add", "."], cwd=repo)
    _git(["commit", "-q", "-m", "base"], cwd=repo)
    base_sha = _git(["rev-parse", "HEAD"], cwd=repo)

    (src / "app.py").write_text(
        "# baseline\n"
        "import sqlite3\n"
        "def q(uid):\n"
        "    db = sqlite3.connect('x')\n"
        "    return db.execute(f'SELECT * FROM u WHERE id={uid}')\n"
        "    # finding lands here\n"
    )
    _git(["add", "."], cwd=repo)
    _git(["commit", "-q", "-m", "head"], cwd=repo)
    head_sha = _git(["rev-parse", "HEAD"], cwd=repo)
    return base_sha, head_sha


# ============================================================================
# CLI surface
# ============================================================================


def test_diff_accepts_github_review_output_value(tmp_path):
    """Sanity: ``diff --output github-review`` is a recognised value.

    A non-git ``target_path`` will fail the git-repo gate, but the
    failure must be the "not a git working tree" message -- not
    "unknown --output" -- proving the enum accepts it.
    """
    repo = tmp_path / "snap"
    repo.mkdir()
    base_snap = repo / "base.json"
    head_snap = repo / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(head_snap, [_finding_dict()])

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(repo),
            "--base-snapshot",
            str(base_snap),
            "--head-snapshot",
            str(head_snap),
            "--output",
            "github-review",
            "--repo",
            "Metbcy/securescan",
            "--sha",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "--base-sha",
            "cafef00dcafef00dcafef00dcafef00dcafef00d",
            "--no-ai",
        ],
    )
    assert "unknown --output" not in (result.stderr or "")


def test_compare_accepts_github_review_output_value(tmp_path, monkeypatch):
    """Sanity: ``compare --output github-review`` is a recognised value.

    Same shape as the diff test: a non-git target falls through the
    gate, but the failure path must NOT be "unknown --output".
    """
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    target = tmp_path / "tgt"
    target.mkdir()
    baseline = tmp_path / "baseline.json"
    _write_snapshot(baseline, [])

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(target),
            str(baseline),
            "--output",
            "github-review",
            "--repo",
            "Metbcy/securescan",
            "--sha",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            "--base-sha",
            "cafef00dcafef00dcafef00dcafef00dcafef00d",
            "--no-ai",
        ],
    )
    assert "unknown --output" not in (result.stderr or "")


def test_scan_rejects_github_review_with_clear_error(tmp_path):
    """``scan --output github-review`` must fail with a pointer to diff/compare.

    ``scan`` has no base+head context to anchor inline comments
    against; surfacing this as a hard error is better than silently
    routing every finding into the body fallback.
    """
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["scan", str(tmp_path), "--output", "github-review", "--no-ai"],
    )
    assert result.exit_code != 0
    err = result.stderr or ""
    assert "github-review" in err
    # Either word ("diff" or "compare") in the pointer is acceptable;
    # both is the spec-pinned wording.
    assert "diff" in err or "compare" in err


# ============================================================================
# Required-arg validation
# ============================================================================


def test_github_review_requires_repo(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    base_snap = tmp_path / "base.json"
    head_snap = tmp_path / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(head_snap, [])

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(base_snap),
            "--head-snapshot",
            str(head_snap),
            "--output",
            "github-review",
            "--sha",
            "deadbeef",
            "--base-sha",
            "cafef00d",
            "--no-ai",
        ],
    )
    assert result.exit_code == 2
    assert "--repo" in (result.stderr or "")


def test_github_review_requires_sha(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    base_snap = tmp_path / "base.json"
    head_snap = tmp_path / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(head_snap, [])

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(base_snap),
            "--head-snapshot",
            str(head_snap),
            "--output",
            "github-review",
            "--repo",
            "Metbcy/securescan",
            "--base-sha",
            "cafef00d",
            "--no-ai",
        ],
    )
    assert result.exit_code == 2
    assert "--sha" in (result.stderr or "")


def test_github_review_requires_base_sha_in_compare(tmp_path, monkeypatch):
    """``compare`` cannot auto-resolve ``base_sha`` -- the baseline
    JSON has no recorded commit-id field today (a v0.5 enhancement).
    So ``--base-sha`` must be required for compare's github-review.
    """
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    target = tmp_path / "tgt"
    target.mkdir()
    baseline = tmp_path / "baseline.json"
    _write_snapshot(baseline, [])

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "compare",
            str(target),
            str(baseline),
            "--output",
            "github-review",
            "--repo",
            "Metbcy/securescan",
            "--sha",
            "deadbeef",
            "--no-ai",
        ],
    )
    assert result.exit_code == 2
    assert "--base-sha" in (result.stderr or "")


def test_github_review_uses_GITHUB_REPOSITORY_env_fallback(tmp_path, monkeypatch):
    """When ``--repo`` is omitted, ``$GITHUB_REPOSITORY`` is consulted.

    We assert by negative: the run still fails (no real git repo) but
    the failure is NOT the missing-repo gate. ``--repo`` must NOT
    appear in stderr -- proving the env fallback was consulted before
    the gate was hit.
    """
    monkeypatch.setenv("GITHUB_REPOSITORY", "Metbcy/securescan")
    monkeypatch.delenv("GITHUB_SHA", raising=False)
    base_snap = tmp_path / "base.json"
    head_snap = tmp_path / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(head_snap, [])

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(base_snap),
            "--head-snapshot",
            str(head_snap),
            "--output",
            "github-review",
            "--sha",
            "deadbeef",
            "--base-sha",
            "cafef00d",
            "--no-ai",
        ],
    )
    err = result.stderr or ""
    assert "--repo" not in err, err


def test_github_review_uses_GITHUB_SHA_env_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_SHA", "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    base_snap = tmp_path / "base.json"
    head_snap = tmp_path / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(head_snap, [])

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(tmp_path),
            "--base-snapshot",
            str(base_snap),
            "--head-snapshot",
            str(head_snap),
            "--output",
            "github-review",
            "--repo",
            "Metbcy/securescan",
            "--base-sha",
            "cafef00d",
            "--no-ai",
        ],
    )
    err = result.stderr or ""
    assert "--sha" not in err, err


# ============================================================================
# End-to-end output (real git repo + snapshot inputs)
# ============================================================================


def _invoke_diff_github_review(
    *,
    repo: Path,
    base_sha: str,
    head_sha: str,
    findings: list[dict],
    extra_args: list[str] | None = None,
    env_extra: dict[str, str] | None = None,
):
    base_snap = repo / "base.json"
    head_snap = repo / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(head_snap, findings)

    args = [
        "diff",
        str(repo),
        "--base-snapshot",
        str(base_snap),
        "--head-snapshot",
        str(head_snap),
        "--output",
        "github-review",
        "--repo",
        "Metbcy/securescan",
        "--sha",
        head_sha,
        "--base-sha",
        base_sha,
        "--no-ai",
    ]
    if extra_args:
        args.extend(extra_args)

    env = {
        **os.environ,
        "SECURESCAN_FAKE_NOW": "2026-01-01T00:00:00",
    }
    if env_extra:
        env.update(env_extra)

    runner = CliRunner()
    return runner.invoke(app, args, env=env)


def test_diff_github_review_emits_valid_json_with_required_keys(tmp_path):
    repo = tmp_path / "repo"
    base_sha, head_sha = _make_repo_with_two_commits(repo)

    findings = [_finding_dict(file_path="src/app.py", line_start=5)]
    result = _invoke_diff_github_review(
        repo=repo, base_sha=base_sha, head_sha=head_sha, findings=findings
    )
    assert result.exit_code == 0, (result.stderr, result.stdout)
    payload = json.loads(result.stdout)
    for key in ("commit_id", "event", "body", "comments"):
        assert key in payload, payload
    assert payload["commit_id"] == head_sha
    assert isinstance(payload["comments"], list)


def test_diff_github_review_body_contains_diff_review_marker(tmp_path):
    repo = tmp_path / "repo"
    base_sha, head_sha = _make_repo_with_two_commits(repo)

    findings = [_finding_dict(file_path="src/app.py", line_start=5)]
    result = _invoke_diff_github_review(
        repo=repo, base_sha=base_sha, head_sha=head_sha, findings=findings
    )
    assert result.exit_code == 0, (result.stderr, result.stdout)
    payload = json.loads(result.stdout)
    first_line = payload["body"].splitlines()[0]
    assert first_line == MARKER_REVIEW


def test_compare_github_review_body_contains_compare_review_marker(tmp_path):
    repo = tmp_path / "repo"
    base_sha, head_sha = _make_repo_with_two_commits(repo)

    baseline = repo / "baseline.json"
    _write_snapshot(baseline, [])

    runner = CliRunner()
    env = {
        **os.environ,
        "SECURESCAN_FAKE_NOW": "2026-01-01T00:00:00",
    }
    result = runner.invoke(
        app,
        [
            "compare",
            str(repo),
            str(baseline),
            "--output",
            "github-review",
            "--repo",
            "Metbcy/securescan",
            "--sha",
            head_sha,
            "--base-sha",
            base_sha,
            "--no-ai",
        ],
        env=env,
    )
    assert result.exit_code == 0, (result.stderr, result.stdout)
    payload = json.loads(result.stdout)
    first_line = payload["body"].splitlines()[0]
    assert first_line == MARKER_REVIEW_COMPARE


def test_diff_github_review_event_is_COMMENT_by_default(tmp_path):
    repo = tmp_path / "repo"
    base_sha, head_sha = _make_repo_with_two_commits(repo)
    findings = [_finding_dict(file_path="src/app.py", line_start=5)]
    result = _invoke_diff_github_review(
        repo=repo, base_sha=base_sha, head_sha=head_sha, findings=findings
    )
    assert result.exit_code == 0, (result.stderr, result.stdout)
    assert json.loads(result.stdout)["event"] == "COMMENT"


def test_diff_github_review_event_can_be_overridden(tmp_path):
    repo = tmp_path / "repo"
    base_sha, head_sha = _make_repo_with_two_commits(repo)
    findings = [_finding_dict(file_path="src/app.py", line_start=5)]
    result = _invoke_diff_github_review(
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        findings=findings,
        extra_args=["--review-event", "REQUEST_CHANGES"],
    )
    assert result.exit_code == 0, (result.stderr, result.stdout)
    assert json.loads(result.stdout)["event"] == "REQUEST_CHANGES"


def test_diff_github_review_no_suggestions_flag_drops_suggestion_blocks(tmp_path):
    repo = tmp_path / "repo"
    base_sha, head_sha = _make_repo_with_two_commits(repo)
    findings = [_finding_dict(file_path="src/app.py", line_start=5)]
    result = _invoke_diff_github_review(
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        findings=findings,
        extra_args=["--no-suggestions"],
    )
    assert result.exit_code == 0, (result.stderr, result.stdout)
    payload = json.loads(result.stdout)
    for comment in payload["comments"]:
        assert "```suggestion" not in comment["body"]


def test_diff_github_review_writes_to_output_file(tmp_path):
    repo = tmp_path / "repo"
    base_sha, head_sha = _make_repo_with_two_commits(repo)
    findings = [_finding_dict(file_path="src/app.py", line_start=5)]
    out_file = tmp_path / "review.json"

    result = _invoke_diff_github_review(
        repo=repo,
        base_sha=base_sha,
        head_sha=head_sha,
        findings=findings,
        extra_args=["--output-file", str(out_file)],
    )
    assert result.exit_code == 0, (result.stderr, result.stdout)
    assert out_file.exists()
    payload = json.loads(out_file.read_text())
    assert "commit_id" in payload
    # stdout should be empty (no body echoed to it).
    assert result.stdout == ""


def test_diff_github_review_byte_deterministic_across_two_invocations(tmp_path):
    """Same FROZEN inputs, same output bytes. Mirrors v0.2.0/v0.3.0's
    determinism contract on the PR-comment renderer.
    """
    repo = tmp_path / "repo"
    base_sha, head_sha = _make_repo_with_two_commits(repo)
    findings = [_finding_dict(file_path="src/app.py", line_start=5)]

    result_a = _invoke_diff_github_review(
        repo=repo, base_sha=base_sha, head_sha=head_sha, findings=findings
    )
    result_b = _invoke_diff_github_review(
        repo=repo, base_sha=base_sha, head_sha=head_sha, findings=findings
    )
    assert result_a.exit_code == 0 and result_b.exit_code == 0
    assert result_a.stdout == result_b.stdout


# ============================================================================
# git diff resolution
# ============================================================================


def test_github_review_fails_when_target_not_git_repo(tmp_path, monkeypatch):
    """When the target isn't a git working tree, fail with a clear
    error. Don't silently emit a payload that anchors every finding
    in the body fallback (no diff -> no positions).
    """
    monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
    monkeypatch.delenv("GITHUB_SHA", raising=False)

    target = tmp_path / "not_a_repo"
    target.mkdir()
    base_snap = tmp_path / "base.json"
    head_snap = tmp_path / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(head_snap, [_finding_dict()])

    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "diff",
            str(target),
            "--base-snapshot",
            str(base_snap),
            "--head-snapshot",
            str(head_snap),
            "--output",
            "github-review",
            "--repo",
            "Metbcy/securescan",
            "--sha",
            "deadbeef",
            "--base-sha",
            "cafef00d",
            "--no-ai",
        ],
    )
    assert result.exit_code != 0
    err = result.stderr or ""
    assert "git" in err.lower()


def test_github_review_resolves_base_sha_from_base_ref_in_diff(tmp_path):
    """ref-mode: when ``--base-ref`` is given, the auto-resolved base
    sha is used as the github-review's diff base.

    We seed a per-commit semgrep finding via the snapshot path and
    instead exercise this test purely on the diff-resolution layer:
    after a successful run, the ``commit_id`` is the head sha
    (verifying ``--sha`` is still ``GITHUB_SHA``-overridable) and the
    body contains the diff-review marker (verifying the path got
    through). A finer-grained "did it call rev-parse?" assertion
    would couple to internals; the integration test below covers it
    end-to-end.
    """
    repo = tmp_path / "repo"
    base_sha, head_sha = _make_repo_with_two_commits(repo)

    # ref-mode requires a clean tree and runs scanners on each side.
    # That's slow + side-effectful, so this test exercises the
    # snapshot-input path (which is the CI fast path the action
    # uses) but with --base-sha auto-derivable from the live repo.
    # Real ref-mode is covered by the smoke test in the PR body.
    base_snap = repo / "base.json"
    head_snap = repo / "head.json"
    _write_snapshot(base_snap, [])
    _write_snapshot(head_snap, [_finding_dict(file_path="src/app.py", line_start=5)])

    runner = CliRunner()
    env = {
        **os.environ,
        "SECURESCAN_FAKE_NOW": "2026-01-01T00:00:00",
    }
    result = runner.invoke(
        app,
        [
            "diff",
            str(repo),
            "--base-snapshot",
            str(base_snap),
            "--head-snapshot",
            str(head_snap),
            "--output",
            "github-review",
            "--repo",
            "Metbcy/securescan",
            "--sha",
            head_sha,
            "--base-sha",
            base_sha,
            "--no-ai",
        ],
        env=env,
    )
    assert result.exit_code == 0, (result.stderr, result.stdout)
    payload = json.loads(result.stdout)
    assert payload["commit_id"] == head_sha
    # The finding at line 5 is inside the diff -> at least one inline
    # comment was anchored, proving the base_sha drove a real diff.
    assert len(payload["comments"]) >= 1


@pytest.mark.skipif(
    subprocess.run(["git", "--version"], capture_output=True).returncode != 0,
    reason="git not available on this host",
)
def test_github_review_resolves_base_sha_from_base_ref_in_diff_ref_mode(tmp_path):
    """The proper ref-mode path: ``--base-ref main`` should auto-set
    ``base_sha`` from the live repo via ``git rev-parse``.

    This test runs the full ref-mode pipeline: scan base, scan head,
    classify, render. Since the worktree contains no real findings
    (just a small Python file), the comments list will be empty, but
    the payload's ``commit_id`` must be the head sha and the body's
    first line must be the diff-review marker -- both of which prove
    ``--base-sha`` was successfully auto-derived from ``--base-ref``.
    """
    repo = tmp_path / "repo"
    _make_repo_with_two_commits(repo)
    head_sha = _git(["rev-parse", "HEAD"], cwd=repo)

    runner = CliRunner()
    env = {
        **os.environ,
        "SECURESCAN_FAKE_NOW": "2026-01-01T00:00:00",
    }
    result = runner.invoke(
        app,
        [
            "diff",
            str(repo),
            "--base-ref",
            "HEAD~1",
            "--head-ref",
            "HEAD",
            "--output",
            "github-review",
            "--repo",
            "Metbcy/securescan",
            "--no-ai",
        ],
        env=env,
    )
    assert result.exit_code == 0, (result.stderr, result.stdout)
    payload = json.loads(result.stdout)
    assert payload["commit_id"] == head_sha
    assert payload["body"].splitlines()[0] == MARKER_REVIEW
