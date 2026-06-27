"""Tests for the reachability scaffold.

Two tiers:

  * **Implemented-now** tests (data model, demotion, dispatch contract,
    pipeline integration, config) assert real behavior and must pass on the
    scaffold as shipped.
  * **Stub-marked** tests (the import-closure analyzer's actual verdicts) are
    written against the *intended* behavior and skipped with a reason that
    points at ``CLAUDE_TASK.md``. The handoff task is to implement the graph
    walk and flip these from skip to pass by deleting the skip marker.

Keeping both tiers in one file means the contributor filling in the logic sees
exactly which assertions their implementation must satisfy.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from securescan.config_file import SecureScanConfig, parse_config
from securescan.models import Finding, ScanType, Severity
from securescan.reachability import analyze
from securescan.reachability.python_imports import (
    PythonImportClosureAnalyzer,
    _module_for_path,
)
from securescan.reachability_demote import demote_unreachable_findings
from securescan.reachability_model import (
    REACHABILITY_KEY,
    Reachability,
    get_reachability,
    set_reachability,
)


def _finding(
    severity: Severity = Severity.HIGH,
    *,
    scanner: str = "bandit",
    scan_type: ScanType = ScanType.CODE,
    file_path: str | None = "app/main.py",
) -> Finding:
    return Finding(
        scan_id="scan-1",
        scanner=scanner,
        scan_type=scan_type,
        severity=severity,
        title="t",
        description="d",
        file_path=file_path,
    )


# --------------------------------------------------------------------------- #
# Data model (implemented now)                                                #
# --------------------------------------------------------------------------- #


def test_get_reachability_absent_is_none_not_unknown():
    # No analyzer ran -> None. Distinct from UNKNOWN (analyzer ran, undecided).
    assert get_reachability({}) is None


def test_set_then_get_roundtrips():
    md: dict = {}
    set_reachability(md, Reachability.REACHABLE, "imported by app/main.py")
    assert get_reachability(md) is Reachability.REACHABLE
    assert md[REACHABILITY_KEY] == "reachable"
    assert md["reachability_reason"] == "imported by app/main.py"


def test_get_reachability_tolerates_unknown_string():
    # A verdict string written by a newer version must not crash an older read.
    assert get_reachability({REACHABILITY_KEY: "teleported"}) is Reachability.UNKNOWN


def test_set_without_reason_does_not_clobber_existing_reason():
    md: dict = {}
    set_reachability(md, Reachability.REACHABLE, "first reason")
    set_reachability(md, Reachability.UNREACHABLE)  # no reason arg
    assert md["reachability_reason"] == "first reason"
    assert get_reachability(md) is Reachability.UNREACHABLE


# --------------------------------------------------------------------------- #
# Demotion (fully implemented now)                                            #
# --------------------------------------------------------------------------- #


def test_demote_lowers_only_unreachable_one_step():
    crit_unreach = _finding(Severity.CRITICAL)
    set_reachability(crit_unreach.metadata, Reachability.UNREACHABLE)
    crit_reach = _finding(Severity.CRITICAL)
    set_reachability(crit_reach.metadata, Reachability.REACHABLE)
    high_unknown = _finding(Severity.HIGH)
    set_reachability(high_unknown.metadata, Reachability.UNKNOWN)
    low_unstamped = _finding(Severity.LOW)

    n = demote_unreachable_findings([crit_unreach, crit_reach, high_unknown, low_unstamped])

    assert n == 1
    assert crit_unreach.severity is Severity.HIGH  # demoted
    assert crit_reach.severity is Severity.CRITICAL  # untouched
    assert high_unknown.severity is Severity.HIGH  # untouched
    assert low_unstamped.severity is Severity.LOW  # untouched


def test_demote_is_idempotent():
    f = _finding(Severity.CRITICAL)
    set_reachability(f.metadata, Reachability.UNREACHABLE)
    assert demote_unreachable_findings([f]) == 1
    assert f.severity is Severity.HIGH
    # second pass must not demote again
    assert demote_unreachable_findings([f]) == 0
    assert f.severity is Severity.HIGH


def test_demote_floor_at_info():
    f = _finding(Severity.INFO)
    set_reachability(f.metadata, Reachability.UNREACHABLE)
    assert demote_unreachable_findings([f]) == 0  # already at floor
    assert f.severity is Severity.INFO


# --------------------------------------------------------------------------- #
# Dispatch contract (implemented now; verdict values are stub UNKNOWN)        #
# --------------------------------------------------------------------------- #


def test_analyze_disabled_is_noop():
    f = _finding()
    result = analyze([f], target_path=Path("."), enabled=False)
    assert result.analyzed == 0
    assert result.skipped == 1
    assert get_reachability(f.metadata) is None  # nothing stamped


def test_analyze_skips_findings_no_analyzer_claims():
    # A network finding with no file_path: no analyzer claims it (yet).
    net = _finding(scan_type=ScanType.NETWORK, scanner="nmap", file_path=None)
    result = analyze([net], target_path=Path("."), enabled=True)
    assert result.skipped == 1
    assert get_reachability(net.metadata) is None


def test_analyze_stamps_claimed_python_finding():
    # The python analyzer claims a .py finding and stamps *some* verdict.
    # On the scaffold that verdict is UNKNOWN (safe default); after CLAUDE_TASK
    # it becomes a real reachable/unreachable verdict.
    f = _finding(file_path=str(Path(__file__)))
    result = analyze([f], target_path=Path(__file__).parent, enabled=True)
    assert result.analyzed == 1
    assert get_reachability(f.metadata) is not None  # a verdict was stamped


def test_python_analyzer_claims_only_py_files():
    a = PythonImportClosureAnalyzer()
    assert a.claims(_finding(file_path="x/y.py")) is True
    assert a.claims(_finding(file_path="x/y.go")) is False
    assert a.claims(_finding(file_path=None)) is False


def test_module_for_path_maps_under_root():
    root = Path("/proj/backend")
    assert _module_for_path("/proj/backend/securescan/api/triage.py", root) == "securescan.api.triage"
    assert _module_for_path("/proj/backend/securescan/__init__.py", root) == "securescan"
    assert _module_for_path("/elsewhere/foo.py", root) is None
    assert _module_for_path("/proj/backend/x.txt", root) is None


# --------------------------------------------------------------------------- #
# Config (implemented now)                                                    #
# --------------------------------------------------------------------------- #


def test_reachability_config_defaults_off():
    cfg = SecureScanConfig()
    assert cfg.reachability.enabled is False
    assert cfg.reachability.demote_unreachable is False


def test_reachability_config_parses_from_yaml():
    cfg = parse_config("reachability:\n  enabled: true\n  demote_unreachable: true\n")
    assert cfg.reachability.enabled is True
    assert cfg.reachability.demote_unreachable is True


def test_reachability_config_rejects_unknown_key():
    # extra="forbid" must reject a typo'd subkey.
    with pytest.raises(Exception):
        parse_config("reachability:\n  enbaled: true\n")


# --------------------------------------------------------------------------- #
# Stub-marked: real verdict logic (CLAUDE_TASK.md flips these on)             #
# --------------------------------------------------------------------------- #

_PENDING = "import-closure logic stubbed; see CLAUDE_TASK.md"


@pytest.mark.skip(reason=_PENDING)
def test_unimported_file_is_unreachable(tmp_path: Path):
    # A .py file that no entrypoint imports must classify UNREACHABLE.
    (tmp_path / "main.py").write_text("import used\n")
    (tmp_path / "used.py").write_text("x = 1\n")
    (tmp_path / "orphan.py").write_text("y = 2\n")  # nothing imports this
    f = _finding(file_path=str(tmp_path / "orphan.py"))
    analyze([f], target_path=tmp_path, enabled=True)
    assert get_reachability(f.metadata) is Reachability.UNREACHABLE


@pytest.mark.skip(reason=_PENDING)
def test_imported_file_is_reachable(tmp_path: Path):
    (tmp_path / "main.py").write_text("import used\n")
    (tmp_path / "used.py").write_text("x = 1\n")
    f = _finding(file_path=str(tmp_path / "used.py"))
    analyze([f], target_path=tmp_path, enabled=True)
    assert get_reachability(f.metadata) is Reachability.REACHABLE


@pytest.mark.skip(reason=_PENDING)
def test_dynamic_import_forces_unknown(tmp_path: Path):
    # importlib usage anywhere reachable makes the static closure unsound;
    # every verdict in the project should be UNKNOWN, never a false UNREACHABLE.
    (tmp_path / "main.py").write_text("import importlib\nm = importlib.import_module('plugin')\n")
    (tmp_path / "plugin.py").write_text("z = 3\n")
    f = _finding(file_path=str(tmp_path / "plugin.py"))
    analyze([f], target_path=tmp_path, enabled=True)
    assert get_reachability(f.metadata) is Reachability.UNKNOWN
