"""Tests for the TS3 ``SuppressionContext`` precedence resolver.

These tests pin down:

* the four-input construction contract (``from_paths`` happy paths and
  the missing / malformed baseline degrade-gracefully promise)
* the documented precedence order: inline > config > baseline, with
  the ``no_suppress`` switch short-circuiting all three
* the ``apply`` partition contract: kept / suppressed lists, the
  ``metadata['suppressed_by']`` audit stamp, and its idempotency
* defensive handling of partial findings (missing ``rule_id``, empty
  ``fingerprint``) so the resolver matches the "NEVER raise" promise
  the rest of ``suppression.py`` already makes
"""
from __future__ import annotations

import json
from pathlib import Path

from securescan.config_file import SecureScanConfig
from securescan.models import Finding, ScanType, Severity
from securescan.suppression import (
    REASON_BASELINE,
    REASON_CONFIG,
    REASON_INLINE,
    IgnoreMap,
    SuppressionContext,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> Finding:
    """Build a Finding with sensible defaults; overrides win."""
    base = dict(
        scan_id="scan-1",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=Severity.HIGH,
        title="SQL injection",
        description="...",
        file_path="src/app.py",
        line_start=10,
        line_end=10,
        rule_id="RULE-001",
        fingerprint="fp-001",
        metadata={},
    )
    base.update(overrides)
    return Finding(**base)


def _write_baseline(path: Path, fingerprints: list[str]) -> None:
    """Write a minimal baseline JSON with the given fingerprints."""
    payload = {
        "findings": [
            {
                "scan_id": "scan-old",
                "scanner": "semgrep",
                "scan_type": "code",
                "severity": "high",
                "title": "old",
                "description": "...",
                "fingerprint": fp,
            }
            for fp in fingerprints
        ]
    }
    path.write_text(json.dumps(payload))


# ---------------------------------------------------------------------------
# Construction (from_paths)
# ---------------------------------------------------------------------------


def test_from_paths_default_construction() -> None:
    ctx = SuppressionContext.from_paths()

    assert ctx.config.ignored_rules == []
    assert ctx.baseline_fingerprints == frozenset()
    assert ctx.no_suppress is False
    assert isinstance(ctx.ignore_map, IgnoreMap)


def test_from_paths_with_baseline_loads_fingerprints(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    _write_baseline(baseline, ["fp-a", "fp-b", "fp-c"])

    ctx = SuppressionContext.from_paths(baseline_path=baseline)

    assert ctx.baseline_fingerprints == frozenset({"fp-a", "fp-b", "fp-c"})


def test_from_paths_with_baseline_flat_list_shape(tmp_path: Path) -> None:
    """The flat-list baseline shape (just a JSON array) should also work."""
    baseline = tmp_path / "baseline.json"
    baseline.write_text(
        json.dumps(
            [
                {
                    "scan_id": "s",
                    "scanner": "semgrep",
                    "scan_type": "code",
                    "severity": "high",
                    "title": "t",
                    "description": "d",
                    "fingerprint": "fp-flat",
                }
            ]
        )
    )

    ctx = SuppressionContext.from_paths(baseline_path=baseline)

    assert ctx.baseline_fingerprints == frozenset({"fp-flat"})


def test_from_paths_missing_baseline_warns_and_continues(
    tmp_path: Path, capsys
) -> None:
    missing = tmp_path / "does-not-exist.json"

    ctx = SuppressionContext.from_paths(baseline_path=missing)

    assert ctx.baseline_fingerprints == frozenset()
    captured = capsys.readouterr()
    assert "baseline file not found" in captured.err
    assert str(missing) in captured.err


def test_from_paths_malformed_baseline_warns_and_continues(
    tmp_path: Path, capsys
) -> None:
    malformed = tmp_path / "broken.json"
    malformed.write_text("{not json at all,,,")

    ctx = SuppressionContext.from_paths(baseline_path=malformed)

    assert ctx.baseline_fingerprints == frozenset()
    captured = capsys.readouterr()
    assert "could not parse baseline file" in captured.err


def test_from_paths_passes_through_config_and_no_suppress() -> None:
    cfg = SecureScanConfig(ignored_rules=["RULE-X"])
    ctx = SuppressionContext.from_paths(config=cfg, no_suppress=True)

    assert ctx.config.ignored_rules == ["RULE-X"]
    assert ctx.no_suppress is True


# ---------------------------------------------------------------------------
# resolve(): no-match baseline
# ---------------------------------------------------------------------------


def test_resolve_returns_none_for_unsuppressed_finding() -> None:
    ctx = SuppressionContext()
    finding = _make_finding()

    assert ctx.resolve(finding) is None


# ---------------------------------------------------------------------------
# resolve(): single-mechanism matches
# ---------------------------------------------------------------------------


def test_resolve_returns_inline_when_only_inline_matches(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text("password = 'x'  # securescan: ignore RULE-001\n")

    ctx = SuppressionContext()
    finding = _make_finding(file_path=str(src), line_start=1, fingerprint="fp-not-in-baseline")

    assert ctx.resolve(finding) == REASON_INLINE


def test_resolve_returns_config_when_only_config_matches() -> None:
    ctx = SuppressionContext(config=SecureScanConfig(ignored_rules=["RULE-001"]))
    finding = _make_finding(rule_id="RULE-001", fingerprint="fp-not-in-baseline")

    assert ctx.resolve(finding) == REASON_CONFIG


def test_resolve_returns_baseline_when_only_baseline_matches() -> None:
    ctx = SuppressionContext(baseline_fingerprints=frozenset({"fp-001"}))
    finding = _make_finding(rule_id="RULE-NOT-IGNORED", fingerprint="fp-001")

    assert ctx.resolve(finding) == REASON_BASELINE


# ---------------------------------------------------------------------------
# resolve(): precedence wars
# ---------------------------------------------------------------------------


def test_resolve_inline_beats_config(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text("x = 1  # securescan: ignore RULE-001\n")

    ctx = SuppressionContext(config=SecureScanConfig(ignored_rules=["RULE-001"]))
    finding = _make_finding(file_path=str(src), line_start=1)

    assert ctx.resolve(finding) == REASON_INLINE


def test_resolve_inline_beats_baseline(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text("x = 1  # securescan: ignore RULE-001\n")

    ctx = SuppressionContext(baseline_fingerprints=frozenset({"fp-001"}))
    finding = _make_finding(file_path=str(src), line_start=1, fingerprint="fp-001")

    assert ctx.resolve(finding) == REASON_INLINE


def test_resolve_config_beats_baseline() -> None:
    ctx = SuppressionContext(
        config=SecureScanConfig(ignored_rules=["RULE-001"]),
        baseline_fingerprints=frozenset({"fp-001"}),
    )
    finding = _make_finding(rule_id="RULE-001", fingerprint="fp-001")

    assert ctx.resolve(finding) == REASON_CONFIG


def test_resolve_no_suppress_short_circuits_to_none(tmp_path: Path) -> None:
    """All three mechanisms would suppress, but no_suppress=True wins."""
    src = tmp_path / "app.py"
    src.write_text("x = 1  # securescan: ignore RULE-001\n")

    ctx = SuppressionContext(
        config=SecureScanConfig(ignored_rules=["RULE-001"]),
        baseline_fingerprints=frozenset({"fp-001"}),
        no_suppress=True,
    )
    finding = _make_finding(file_path=str(src), line_start=1, fingerprint="fp-001")

    assert ctx.resolve(finding) is None


# ---------------------------------------------------------------------------
# resolve(): defensive partial-finding handling
# ---------------------------------------------------------------------------


def test_resolve_with_none_rule_id_skips_inline_and_config(tmp_path: Path) -> None:
    """A finding without rule_id matches by baseline only, not inline/config."""
    src = tmp_path / "app.py"
    # The file has an inline ignore for RULE-001, but the finding has no rule_id;
    # inline cannot match. Config also indexes by rule_id and shouldn't match.
    src.write_text("x = 1  # securescan: ignore RULE-001\n")

    ctx = SuppressionContext(
        config=SecureScanConfig(ignored_rules=["RULE-001"]),
        baseline_fingerprints=frozenset({"fp-orphan"}),
    )
    finding = _make_finding(
        file_path=str(src),
        line_start=1,
        rule_id=None,
        fingerprint="fp-orphan",
    )

    assert ctx.resolve(finding) == REASON_BASELINE


def test_resolve_with_empty_fingerprint_skips_baseline() -> None:
    """An empty fingerprint must not accidentally match the empty-string sentinel."""
    ctx = SuppressionContext(baseline_fingerprints=frozenset({""}))
    finding = _make_finding(rule_id="RULE-NOT-IGNORED", fingerprint="")

    assert ctx.resolve(finding) is None


# ---------------------------------------------------------------------------
# apply(): partition + stamp
# ---------------------------------------------------------------------------


def test_apply_partitions_into_kept_and_suppressed(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text("x = 1  # securescan: ignore RULE-A\n")

    ctx = SuppressionContext(
        config=SecureScanConfig(ignored_rules=["RULE-B"]),
        baseline_fingerprints=frozenset({"fp-c"}),
    )
    findings = [
        _make_finding(rule_id="RULE-A", file_path=str(src), line_start=1, fingerprint="fp-a"),
        _make_finding(rule_id="RULE-B", fingerprint="fp-b"),
        _make_finding(rule_id="RULE-D", fingerprint="fp-c"),
        _make_finding(rule_id="RULE-LIVE", fingerprint="fp-live"),
    ]

    kept, suppressed = ctx.apply(findings)

    assert [f.rule_id for f in suppressed] == ["RULE-A", "RULE-B", "RULE-D"]
    assert [f.rule_id for f in kept] == ["RULE-LIVE"]


def test_apply_stamps_suppressed_by_metadata(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text("x = 1  # securescan: ignore RULE-A\n")

    ctx = SuppressionContext(
        config=SecureScanConfig(ignored_rules=["RULE-B"]),
        baseline_fingerprints=frozenset({"fp-c"}),
    )
    inline_f = _make_finding(
        rule_id="RULE-A", file_path=str(src), line_start=1, fingerprint="fp-a"
    )
    config_f = _make_finding(rule_id="RULE-B", fingerprint="fp-b")
    baseline_f = _make_finding(rule_id="RULE-D", fingerprint="fp-c")
    live_f = _make_finding(rule_id="RULE-LIVE", fingerprint="fp-live")

    _, suppressed = ctx.apply([inline_f, config_f, baseline_f, live_f])

    assert inline_f.metadata["suppressed_by"] == REASON_INLINE
    assert config_f.metadata["suppressed_by"] == REASON_CONFIG
    assert baseline_f.metadata["suppressed_by"] == REASON_BASELINE
    assert "suppressed_by" not in live_f.metadata
    assert suppressed == [inline_f, config_f, baseline_f]


def test_apply_idempotent_does_not_restamp() -> None:
    """A pre-set ``suppressed_by`` is preserved on a second apply pass."""
    ctx = SuppressionContext(
        config=SecureScanConfig(ignored_rules=["RULE-001"]),
    )
    finding = _make_finding(
        rule_id="RULE-001",
        metadata={"suppressed_by": "previous-tag"},
    )

    _, suppressed = ctx.apply([finding])

    assert suppressed == [finding]
    assert finding.metadata["suppressed_by"] == "previous-tag"


def test_apply_no_suppress_returns_all_kept_no_stamps(tmp_path: Path) -> None:
    src = tmp_path / "app.py"
    src.write_text("x = 1  # securescan: ignore RULE-A\n")

    ctx = SuppressionContext(
        config=SecureScanConfig(ignored_rules=["RULE-B"]),
        baseline_fingerprints=frozenset({"fp-c"}),
        no_suppress=True,
    )
    findings = [
        _make_finding(rule_id="RULE-A", file_path=str(src), line_start=1, fingerprint="fp-a"),
        _make_finding(rule_id="RULE-B", fingerprint="fp-b"),
        _make_finding(rule_id="RULE-D", fingerprint="fp-c"),
    ]

    kept, suppressed = ctx.apply(findings)

    assert kept == findings
    assert suppressed == []
    for f in findings:
        assert "suppressed_by" not in f.metadata


def test_apply_returns_distinct_lists_not_aliases_of_input() -> None:
    ctx = SuppressionContext()
    findings = [_make_finding(rule_id="RULE-LIVE", fingerprint="fp-live")]

    kept, suppressed = ctx.apply(findings)

    assert kept is not findings
    assert suppressed is not findings
    # Mutating returned lists must not poison the input.
    kept.append(_make_finding(rule_id="RULE-MUTATED"))
    assert len(findings) == 1


def test_apply_no_suppress_returns_distinct_list() -> None:
    """The kill-switch path also returns a fresh list, not an alias."""
    ctx = SuppressionContext(no_suppress=True)
    findings = [_make_finding()]

    kept, suppressed = ctx.apply(findings)

    assert kept == findings
    assert kept is not findings
    assert suppressed == []
