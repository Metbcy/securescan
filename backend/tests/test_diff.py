"""Tests for the pure-functional diff classifier.

The classifier is the wedge that makes SecureScan tolerable in CI: a PR
comment that only lists NEW findings (not the legacy backlog) is what
keeps developers from disabling the check after the first noisy run.
These tests pin down the contract:

- new / fixed / unchanged buckets keyed strictly on fingerprint
- idempotent and pure (no input mutation other than fingerprint pop)
- canonical ordering across all three buckets
- line-shift invariance via SS2's fingerprint
- JSON loader accepts both ``{"findings": [...]}`` and flat-list shapes
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from securescan.diff import ChangeSet, classify, load_findings_json
from securescan.fingerprint import populate_fingerprints
from securescan.models import Finding, ScanType, Severity
from securescan.ordering import sort_findings_canonical


def _make_finding(**overrides) -> Finding:
    base = dict(
        scan_id="scan-1",
        scanner="semgrep",
        scan_type=ScanType.CODE,
        severity=Severity.HIGH,
        title="SQL injection",
        description="...",
        file_path="src/x.py",
        line_start=10,
        line_end=10,
        rule_id="RULE-001",
        cwe="CWE-89",
        metadata={"line_snippet": "x = 1"},
    )
    base.update(overrides)
    return Finding(**base)


def _a():
    return _make_finding(file_path="src/a.py", rule_id="RULE-A", cwe="CWE-89")


def _b():
    return _make_finding(file_path="src/b.py", rule_id="RULE-B", cwe="CWE-79")


def _c():
    return _make_finding(file_path="src/c.py", rule_id="RULE-C", cwe="CWE-22")


def test_empty_old_yields_all_new():
    a, b, c = _a(), _b(), _c()
    cs = classify([], [a, b, c])
    assert {f.fingerprint for f in cs.new} == {a.fingerprint, b.fingerprint, c.fingerprint}
    assert cs.fixed == []
    assert cs.unchanged == []


def test_empty_new_yields_all_fixed():
    a, b, c = _a(), _b(), _c()
    cs = classify([a, b, c], [])
    assert {f.fingerprint for f in cs.fixed} == {a.fingerprint, b.fingerprint, c.fingerprint}
    assert cs.new == []
    assert cs.unchanged == []


def test_identical_sets_yield_all_unchanged():
    a, b, c = _a(), _b(), _c()
    a2, b2, c2 = _a(), _b(), _c()
    cs = classify([a, b, c], [a2, b2, c2])
    assert cs.new == []
    assert cs.fixed == []
    assert {f.fingerprint for f in cs.unchanged} == {a.fingerprint, b.fingerprint, c.fingerprint}


def test_subset_removal_yields_fixed():
    a, b = _a(), _b()
    a2 = _a()
    cs = classify([a, b], [a2])
    assert [f.fingerprint for f in cs.fixed] == [b.fingerprint]
    assert [f.fingerprint for f in cs.unchanged] == [a.fingerprint]
    assert cs.new == []


def test_subset_addition_yields_new():
    a = _a()
    a2, b = _a(), _b()
    cs = classify([a], [a2, b])
    assert [f.fingerprint for f in cs.new] == [b.fingerprint]
    assert [f.fingerprint for f in cs.unchanged] == [a.fingerprint]
    assert cs.fixed == []


def test_line_shift_does_not_reclassify():
    # SS2 fingerprint is line-shift invariant: same finding moved from
    # line 10 to line 15 must classify as unchanged, not new+fixed.
    old = _make_finding(line_start=10, line_end=10)
    new = _make_finding(line_start=15, line_end=15)
    cs = classify([old], [new])
    assert cs.new == []
    assert cs.fixed == []
    assert len(cs.unchanged) == 1
    assert cs.unchanged[0].line_start == 15  # the new version is retained


def test_classify_is_idempotent():
    old = [_a(), _b()]
    new = [_a(), _c()]
    first = classify(old, new)
    second = classify(old, new)
    assert [f.fingerprint for f in first.new] == [f.fingerprint for f in second.new]
    assert [f.fingerprint for f in first.fixed] == [f.fingerprint for f in second.fixed]
    assert [f.fingerprint for f in first.unchanged] == [f.fingerprint for f in second.unchanged]


def test_classify_is_pure_does_not_mutate_input_other_than_fingerprint():
    # Snapshot inputs both before AND after pre-populating fingerprints,
    # so the only legal diff between snapshot and post-classify is the
    # fingerprint field itself.
    old = [_a(), _b()]
    new = [_a(), _c()]
    populate_fingerprints(old)
    populate_fingerprints(new)
    old_snapshot = copy.deepcopy(old)
    new_snapshot = copy.deepcopy(new)

    classify(old, new)

    assert [f.model_dump() for f in old] == [f.model_dump() for f in old_snapshot]
    assert [f.model_dump() for f in new] == [f.model_dump() for f in new_snapshot]


def test_unchanged_uses_new_finding_version():
    # Same fingerprint (same scanner+rule+file+context+cwe) but different
    # incidental metadata between runs. The unchanged bucket must hold
    # the NEW one so renderers report the current line number / snippet.
    old = _make_finding(line_start=10, metadata={"line_snippet": "x = 1", "tag": "old"})
    new = _make_finding(line_start=42, metadata={"line_snippet": "x = 1", "tag": "new"})
    cs = classify([old], [new])
    assert len(cs.unchanged) == 1
    assert cs.unchanged[0].line_start == 42
    assert cs.unchanged[0].metadata.get("tag") == "new"


def test_changeset_is_empty_helper():
    assert ChangeSet().is_empty() is True
    assert ChangeSet(new=[_a()]).is_empty() is False
    assert ChangeSet(fixed=[_a()]).is_empty() is False
    assert ChangeSet(unchanged=[_a()]).is_empty() is False


def test_changeset_total_changes_excludes_unchanged():
    cs = ChangeSet(new=[_a(), _b()], fixed=[_c()], unchanged=[_a(), _b(), _c()])
    assert cs.total_changes() == 3


def test_changeset_lists_are_sorted_canonically():
    # Build inputs in scrambled order across all three buckets and assert
    # the result lists come back in canonical order.
    crit = _make_finding(
        severity=Severity.CRITICAL,
        file_path="src/zzz.py",
        rule_id="R-CRIT",
        cwe="CWE-1",
    )
    high = _make_finding(
        severity=Severity.HIGH, file_path="src/aaa.py", rule_id="R-HIGH", cwe="CWE-2"
    )
    low = _make_finding(severity=Severity.LOW, file_path="src/mmm.py", rule_id="R-LOW", cwe="CWE-3")
    medium = _make_finding(
        severity=Severity.MEDIUM, file_path="src/bbb.py", rule_id="R-MED", cwe="CWE-4"
    )

    # Old has the high+low (which will fix), and a "shared" carry-over.
    shared_old = _make_finding(
        severity=Severity.HIGH, file_path="src/shared.py", rule_id="R-SHARED", cwe="CWE-5"
    )
    shared_new = _make_finding(
        severity=Severity.HIGH, file_path="src/shared.py", rule_id="R-SHARED", cwe="CWE-5"
    )
    shared_other_old = _make_finding(
        severity=Severity.MEDIUM, file_path="src/shared2.py", rule_id="R-S2", cwe="CWE-6"
    )
    shared_other_new = _make_finding(
        severity=Severity.MEDIUM, file_path="src/shared2.py", rule_id="R-S2", cwe="CWE-6"
    )

    old_input = [low, shared_old, high, shared_other_old]  # scrambled
    new_input = [medium, shared_other_new, crit, shared_new]  # scrambled

    cs = classify(old_input, new_input)

    assert cs.new == sort_findings_canonical(cs.new)
    assert cs.fixed == sort_findings_canonical(cs.fixed)
    assert cs.unchanged == sort_findings_canonical(cs.unchanged)

    # Spot-check: critical comes before medium in the new bucket.
    assert [f.severity for f in cs.new] == [Severity.CRITICAL, Severity.MEDIUM]
    # Spot-check: high comes before low in the fixed bucket.
    assert [f.severity for f in cs.fixed] == [Severity.HIGH, Severity.LOW]


def test_load_findings_json_accepts_flat_list(tmp_path: Path):
    f = _a()
    populate_fingerprints([f])
    payload = [f.model_dump(mode="json")]
    p = tmp_path / "flat.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_findings_json(p)
    assert len(loaded) == 1
    assert loaded[0].fingerprint == f.fingerprint
    assert loaded[0].file_path == "src/a.py"


def test_load_findings_json_accepts_object_with_findings_key(tmp_path: Path):
    a, b = _a(), _b()
    populate_fingerprints([a, b])
    payload = {
        "scan_id": "scan-xyz",
        "findings": [a.model_dump(mode="json"), b.model_dump(mode="json")],
    }
    p = tmp_path / "envelope.json"
    p.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_findings_json(p)
    assert {f.fingerprint for f in loaded} == {a.fingerprint, b.fingerprint}


def test_load_findings_json_handles_missing_fingerprint_field(tmp_path: Path):
    f = _a()
    raw = f.model_dump(mode="json")
    raw.pop("fingerprint", None)
    p = tmp_path / "no_fp.json"
    p.write_text(json.dumps([raw]), encoding="utf-8")

    loaded = load_findings_json(p)
    assert len(loaded) == 1
    assert loaded[0].fingerprint == ""

    # And the classifier must still work end-to-end via fingerprint backfill.
    cs = classify([], loaded)
    assert len(cs.new) == 1
    assert cs.new[0].fingerprint != ""


def test_load_findings_json_raises_on_malformed_json(tmp_path: Path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        load_findings_json(p)
