"""Tests for ``securescan/scanners/baseline.py`` mode selection.

The v0.4 ``BaselineScanner`` ignored ``target_path`` entirely and
always probed the running host's ``/etc/ssh/sshd_config``,
``/etc/passwd``, etc. That made every project-directory scan return
findings about the SCANNER HOST'S ssh config, not the codebase the
user typed -- UX gap #3 in the v0.5 plan.

These tests cover the new HOST/TARGET dispatch in
:meth:`BaselineScanner.scan`:

* ``target_path`` of ``"/"`` / ``""`` / ``None`` -> HOST mode
  (preserves v0.4 behavior so existing CLI users aren't broken).
* A real directory -> TARGET mode (probe ``<target>/etc/ssh/...``,
  ``<target>/etc/passwd``, ``<target>/etc/shadow``; skip host-scope
  checks like ``~/.ssh`` perms).
* ``baseline_host_probes=True`` kwarg forces HOST mode regardless --
  the escape hatch for power users.
* Every produced finding is stamped with
  ``metadata["baseline_scope"] = "host" | "target"`` so downstream
  renderers can label scope.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from securescan.models import Severity
from securescan.scanners.baseline import BaselineScanner


def _run(coro):
    return asyncio.run(coro)


def _make_target_with_sshd(tmp_path: Path, sshd_body: str) -> Path:
    """Build a fake target directory containing ``etc/ssh/sshd_config``."""
    sshd = tmp_path / "etc" / "ssh" / "sshd_config"
    sshd.parent.mkdir(parents=True)
    sshd.write_text(sshd_body)
    return tmp_path


def test_target_path_root_uses_host_mode():
    """``target_path="/"`` keeps v0.4 host-wide behavior.

    We can't assert specific findings (the running host's actual
    config is unpredictable in CI), so we assert the SCOPE STAMP --
    every produced finding must be labeled ``host``.
    """
    scanner = BaselineScanner()
    findings = _run(scanner.scan("/", "scan-id"))

    for f in findings:
        assert f.metadata.get("baseline_scope") == "host"


def test_target_path_empty_uses_host_mode():
    scanner = BaselineScanner()
    findings = _run(scanner.scan("", "scan-id"))

    for f in findings:
        assert f.metadata.get("baseline_scope") == "host"


def test_target_path_none_uses_host_mode():
    """``target_path=None`` (rare but possible if upstream forgets to
    coerce) must NOT crash and must run HOST mode."""
    scanner = BaselineScanner()
    findings = _run(scanner.scan(None, "scan-id"))  # type: ignore[arg-type]

    for f in findings:
        assert f.metadata.get("baseline_scope") == "host"


def test_target_path_directory_uses_target_mode(tmp_path: Path):
    """A real directory with ``etc/ssh/sshd_config`` -> TARGET mode,
    SSH probes run THERE (not on the host)."""
    target = _make_target_with_sshd(
        tmp_path,
        "PermitRootLogin yes\nPasswordAuthentication no\n",
    )

    scanner = BaselineScanner()
    findings = _run(scanner.scan(str(target), "scan-id"))

    assert findings, "expected at least one finding from etc/ssh/sshd_config"
    for f in findings:
        assert f.metadata.get("baseline_scope") == "target"

    titles = [f.title for f in findings]
    assert any("root login" in t.lower() for t in titles), (
        f"expected a root-login finding from PermitRootLogin yes; got {titles!r}"
    )

    # Every finding must point at the TARGET'S sshd_config, not
    # the host's. This catches accidental reuse of the v0.4 hardcoded
    # path.
    sshd_path = str(target / "etc" / "ssh" / "sshd_config")
    ssh_findings = [f for f in findings if f.rule_id and f.rule_id.startswith("BASELINE-SSH-")]
    assert ssh_findings, "expected SSH-rule findings from sshd_config"
    for f in ssh_findings:
        assert f.file_path == sshd_path


def test_target_path_directory_without_etc_files_emits_info_finding(tmp_path: Path):
    """An empty target dir produces ONE info finding pointing the user
    at the host-mode escape hatches.

    The alternative (silent zero findings) would be indistinguishable
    from a clean scan -- bad UX. The info finding makes the scope
    decision visible.
    """
    scanner = BaselineScanner()
    findings = _run(scanner.scan(str(tmp_path), "scan-id"))

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.INFO
    assert "no host-config files" in f.description.lower()
    assert f.metadata.get("baseline_scope") == "target"
    # The remediation should mention both escape hatches.
    assert "/" in (f.remediation or "")
    assert "--baseline-host-probes" in (f.remediation or "")


def test_target_path_directory_partial_etc_files(tmp_path: Path):
    """Only ``etc/passwd`` exists -> only the passwd checks run.

    Specifically:
    * No SSH-config findings (no sshd_config to probe).
    * No shadow findings (no shadow to probe).
    * Either a passwd-perms finding (if mode is too permissive) or a
      passwd-uid-zero finding (if a non-root UID-0 user is present)
      -- depending on what we put in the file.

    This is the "if some exist: probe only those that exist" branch
    of the TARGET-mode dispatch.
    """
    passwd = tmp_path / "etc" / "passwd"
    passwd.parent.mkdir(parents=True)
    # An evil UID-0 entry so we get a deterministic finding.
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\nbadguy:x:0:0:::/bin/bash\n")
    # Make perms loose-but-existent (0o644 is fine; 0o666 would also
    # produce a perm finding -- we just want SOMETHING etc/passwd-y).
    os.chmod(passwd, 0o644)

    scanner = BaselineScanner()
    findings = _run(scanner.scan(str(tmp_path), "scan-id"))

    assert findings, "expected at least one finding from etc/passwd"
    rule_ids = {f.rule_id for f in findings}

    # No SSH or shadow probes ran.
    assert not any(rid and rid.startswith("BASELINE-SSH-") for rid in rule_ids)
    assert not any(rid == "BASELINE-USER-002" for rid in rule_ids), (
        "shadow probe should not have run"
    )

    # The UID-0 detector should have fired on `badguy`.
    assert "BASELINE-USER-001" in rule_ids
    uid_findings = [f for f in findings if f.rule_id == "BASELINE-USER-001"]
    assert any("badguy" in f.title for f in uid_findings)

    # Scope stamp.
    for f in findings:
        assert f.metadata.get("baseline_scope") == "target"


def test_baseline_host_probes_kwarg_overrides_target(tmp_path: Path):
    """``baseline_host_probes=True`` forces HOST mode even when a real
    target_path is passed. This is the v0.5 escape hatch for power
    users who want host scope alongside their directory scan."""
    target = _make_target_with_sshd(
        tmp_path,
        "PermitRootLogin yes\n",
    )

    scanner = BaselineScanner()
    findings = _run(scanner.scan(str(target), "scan-id", baseline_host_probes=True))

    # No findings should reference the TARGET'S sshd_config -- HOST
    # mode probes /etc/ssh/sshd_config, not the tmp dir.
    target_sshd = str(target / "etc" / "ssh" / "sshd_config")
    assert not any(f.file_path == target_sshd for f in findings), (
        "host-probes mode must not pick up the target's sshd_config"
    )

    # Every finding must be stamped HOST.
    for f in findings:
        assert f.metadata.get("baseline_scope") == "host"


def test_baseline_finding_includes_metadata_baseline_scope(tmp_path: Path):
    """Smoke test: every produced finding -- in either mode -- carries
    a ``baseline_scope`` key. Documented contract for the v0.6
    dashboard PR.
    """
    # TARGET-mode case: empty dir -> info finding with scope=target.
    scanner = BaselineScanner()
    target_findings = _run(scanner.scan(str(tmp_path), "scan-id"))
    for f in target_findings:
        assert "baseline_scope" in f.metadata
        assert f.metadata["baseline_scope"] in {"host", "target"}

    # HOST-mode case: scope=host on every finding.
    host_findings = _run(scanner.scan("/", "scan-id"))
    for f in host_findings:
        assert "baseline_scope" in f.metadata
        assert f.metadata["baseline_scope"] == "host"


def test_baseline_skips_home_ssh_perms_in_target_mode(tmp_path: Path, monkeypatch):
    """TARGET mode must NOT probe ``~/.ssh/authorized_keys`` -- that's
    a host-scope check.

    We monkey-patch HOME to a known path containing a wide-open
    ``~/.ssh`` directory; in TARGET mode no finding should reference
    it (because the home-perm check is host-only).
    """
    fake_home = tmp_path / "fake-home"
    ssh_dir = fake_home / ".ssh"
    ssh_dir.mkdir(parents=True)
    (ssh_dir / "authorized_keys").write_text("ssh-rsa AAAA fake\n")
    # World-writable -- would absolutely produce a v0.4 finding.
    os.chmod(ssh_dir, 0o777)
    os.chmod(ssh_dir / "authorized_keys", 0o666)

    monkeypatch.setenv("HOME", str(fake_home))

    # Build a target dir with a passwd file so we're firmly in
    # TARGET mode (not in the empty-dir info-finding branch).
    passwd = tmp_path / "target" / "etc" / "passwd"
    passwd.parent.mkdir(parents=True)
    passwd.write_text("root:x:0:0:root:/root:/bin/bash\n")

    scanner = BaselineScanner()
    findings = _run(scanner.scan(str(tmp_path / "target"), "scan-id"))

    # No finding may reference the home .ssh path. The scope stamp
    # must be 'target'.
    for f in findings:
        assert ".ssh" not in (f.file_path or ""), (
            f"unexpected ~/.ssh probe in TARGET mode: {f.file_path}"
        )
        assert f.metadata.get("baseline_scope") == "target"


def test_baseline_target_mode_ignores_unrelated_files(tmp_path: Path):
    """A target dir with ONLY non-host-config files (e.g. source code)
    must produce the single info finding -- not run any probes against
    files that happen to share a name like ``etc.txt``.

    Regression guard against accidental loose matching.
    """
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text("print('hi')\n")
    (tmp_path / "etc.txt").write_text("not a config file\n")  # red herring

    scanner = BaselineScanner()
    findings = _run(scanner.scan(str(tmp_path), "scan-id"))

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert findings[0].rule_id == "BASELINE-SCOPE-001"


def test_baseline_target_mode_with_only_shadow(tmp_path: Path):
    """Only ``etc/shadow`` exists -> shadow checks run, nothing else.

    Pairs with the partial-passwd test to lock down the per-file
    dispatch in :meth:`BaselineScanner._scan_target`.
    """
    shadow = tmp_path / "etc" / "shadow"
    shadow.parent.mkdir(parents=True)
    # An entry with `!!` triggers the no-password finding.
    shadow.write_text("alice:!!:0:0:99999:7:::\n")
    os.chmod(shadow, 0o600)  # tighter than 640 -> no perm finding

    scanner = BaselineScanner()
    findings = _run(scanner.scan(str(tmp_path), "scan-id"))

    rule_ids = {f.rule_id for f in findings}
    assert "BASELINE-USER-002" in rule_ids
    # No SSH or passwd-uid-zero probes ran.
    assert not any(rid and rid.startswith("BASELINE-SSH-") for rid in rule_ids)
    assert "BASELINE-USER-001" not in rule_ids
    for f in findings:
        assert f.metadata.get("baseline_scope") == "target"


def test_baseline_host_probes_kwarg_default_false_runs_target_mode(tmp_path: Path):
    """Sanity-check: ``baseline_host_probes`` defaults to False, so
    omitting the kwarg with a real target_path picks TARGET mode.
    """
    _make_target_with_sshd(tmp_path, "PermitRootLogin yes\n")

    scanner = BaselineScanner()
    findings = _run(scanner.scan(str(tmp_path), "scan-id"))

    assert findings
    for f in findings:
        assert f.metadata.get("baseline_scope") == "target"


@pytest.mark.parametrize("non_target", ["/", "", None])
def test_baseline_host_probes_with_host_target_is_idempotent(non_target):
    """Passing ``baseline_host_probes=True`` alongside a host-target
    is harmless -- still HOST mode. (No exception, no double-probing.)
    """
    scanner = BaselineScanner()
    findings = _run(scanner.scan(non_target, "scan-id", baseline_host_probes=True))  # type: ignore[arg-type]

    for f in findings:
        assert f.metadata.get("baseline_scope") == "host"
