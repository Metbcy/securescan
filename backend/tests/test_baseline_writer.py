"""Tests for ``securescan.baseline_writer``.

The baseline JSON is what ``compare`` / ``diff --baseline`` consume,
and what teams check into git. The contract pinned here:

* serialization is byte-deterministic for the same logical input;
* findings are sorted via ``sort_findings_canonical`` regardless of
  input order;
* the trimmed shape drops noisy / non-deterministic fields
  (``id``, ``scan_id``, ``description``, ``remediation``, ``metadata``,
  ``hashes``, ``compliance_tags``);
* the ``target_path`` field in the envelope is path-relative-to-baseline
  when possible (so the file is portable across clones);
* writes are atomic (no half-written files left if interrupted);
* the file round-trips through ``securescan.diff.load_findings_json``
  with fingerprints intact.
"""
from __future__ import annotations

import json

import pytest

from securescan.baseline_writer import (
    BASELINE_VERSION,
    serialize_baseline,
    write_baseline,
)
from securescan.diff import load_findings_json
from securescan.fingerprint import populate_fingerprints
from securescan.models import Finding, ScanType, Severity


def _make_finding(
    *,
    scanner: str = "semgrep",
    rule_id: str = "RULE-001",
    file_path: str = "src/app.py",
    line_start: int = 10,
    title: str = "SQL Injection",
    severity: Severity = Severity.HIGH,
    cwe: str = "CWE-89",
) -> Finding:
    return Finding(
        scan_id="scan-x",
        scanner=scanner,
        scan_type=ScanType.CODE,
        severity=severity,
        title=title,
        description="long bulky description that should not appear in baseline",
        file_path=file_path,
        line_start=line_start,
        rule_id=rule_id,
        cwe=cwe,
        remediation="long remediation text that should not appear in baseline either",
        metadata={"k": "v"},
        compliance_tags=["soc2"],
    )


def _sample_findings() -> list[Finding]:
    findings = [
        _make_finding(rule_id="RULE-001", file_path="src/a.py", line_start=10),
        _make_finding(
            rule_id="RULE-002",
            file_path="src/b.py",
            line_start=5,
            severity=Severity.CRITICAL,
            title="Hardcoded Secret",
            cwe="CWE-798",
        ),
        _make_finding(
            rule_id="RULE-003",
            file_path="src/a.py",
            line_start=42,
            severity=Severity.MEDIUM,
            title="Weak crypto",
            cwe="CWE-327",
        ),
    ]
    populate_fingerprints(findings)
    return findings


def test_serialize_baseline_is_byte_deterministic(tmp_path):
    findings = _sample_findings()
    out = tmp_path / "baseline.json"
    a = serialize_baseline(
        findings,
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    b = serialize_baseline(
        findings,
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    assert a == b
    assert a.encode("utf-8") == b.encode("utf-8")


def test_serialize_baseline_sorts_findings_canonically(tmp_path):
    from securescan.ordering import sort_findings_canonical

    findings = _sample_findings()
    shuffled = [findings[2], findings[0], findings[1]]

    out = tmp_path / "baseline.json"
    a = serialize_baseline(
        findings,
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    b = serialize_baseline(
        shuffled,
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    assert a == b

    parsed = json.loads(a)
    canonical = sort_findings_canonical(findings)
    assert [x["fingerprint"] for x in parsed["findings"]] == [
        f.fingerprint for f in canonical
    ]


def test_serialize_baseline_includes_version_field(tmp_path):
    out = tmp_path / "baseline.json"
    text = serialize_baseline(
        _sample_findings(),
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    parsed = json.loads(text)
    assert parsed["version"] == BASELINE_VERSION
    assert parsed["version"] == 1
    assert parsed["generated_by"] == "securescan"


def test_serialize_baseline_omits_metadata_and_id(tmp_path):
    out = tmp_path / "baseline.json"
    text = serialize_baseline(
        _sample_findings(),
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    parsed = json.loads(text)
    forbidden = {
        "id",
        "scan_id",
        "description",
        "remediation",
        "metadata",
        "hashes",
        "compliance_tags",
    }
    for entry in parsed["findings"]:
        leaked = forbidden.intersection(entry.keys())
        assert not leaked, f"baseline leaked forbidden keys: {leaked}"


def test_serialize_baseline_includes_fingerprint(tmp_path):
    findings = _sample_findings()
    expected_fps = {f.fingerprint for f in findings}
    out = tmp_path / "baseline.json"
    text = serialize_baseline(
        findings,
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    parsed = json.loads(text)
    got = {entry["fingerprint"] for entry in parsed["findings"]}
    assert got == expected_fps
    assert all(len(entry["fingerprint"]) == 64 for entry in parsed["findings"])


def test_serialize_baseline_relative_target_path_when_inside_dir(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    out = repo / ".securescan" / "baseline.json"
    out.parent.mkdir()

    text = serialize_baseline(
        _sample_findings(),
        target_path=repo,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    parsed = json.loads(text)
    assert parsed["target_path"] == ".."
    assert "/" not in parsed["target_path"].replace("..", "")


def test_serialize_baseline_absolute_target_path_when_outside_dir(tmp_path, monkeypatch):
    inside = tmp_path / "proj" / ".securescan" / "baseline.json"
    inside.parent.mkdir(parents=True)
    outside = tmp_path / "totally" / "other" / "tree"
    outside.mkdir(parents=True)

    text = serialize_baseline(
        _sample_findings(),
        target_path=outside,
        scan_types=[ScanType.CODE],
        output_file=inside,
    )
    parsed = json.loads(text)
    assert ".." in parsed["target_path"] or parsed["target_path"].startswith("/")


def test_write_baseline_creates_parent_dir(tmp_path):
    out = tmp_path / "deeply" / "nested" / "dir" / "baseline.json"
    assert not out.parent.exists()
    n = write_baseline(
        _sample_findings(),
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    assert out.exists()
    assert n > 0
    assert n == len(out.read_bytes())


def test_write_baseline_is_atomic_no_partial_files_left_on_disk(tmp_path):
    out = tmp_path / "baseline.json"
    write_baseline(
        _sample_findings(),
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    leftover = list(tmp_path.glob("*.tmp"))
    assert leftover == []
    assert out.exists()

    write_baseline(
        _sample_findings(),
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    leftover_after_overwrite = list(tmp_path.glob("*.tmp"))
    assert leftover_after_overwrite == []


def test_write_baseline_round_trips_through_load_findings_json(tmp_path):
    findings = _sample_findings()
    expected_fps = sorted(f.fingerprint for f in findings)

    out = tmp_path / "baseline.json"
    write_baseline(
        findings,
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )

    loaded = load_findings_json(out)
    got_fps = sorted(f.fingerprint for f in loaded)
    assert got_fps == expected_fps


def test_serialize_baseline_pretty_with_sorted_keys(tmp_path):
    out = tmp_path / "baseline.json"
    text = serialize_baseline(
        _sample_findings(),
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    assert "\n" in text
    assert text.endswith("\n")

    parsed = json.loads(text)
    top_keys = list(parsed.keys())
    assert top_keys == sorted(top_keys), f"top-level keys not sorted: {top_keys}"

    for entry in parsed["findings"]:
        assert list(entry.keys()) == sorted(entry.keys())


def test_serialize_baseline_omits_timestamps(tmp_path):
    out = tmp_path / "baseline.json"
    text = serialize_baseline(
        _sample_findings(),
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    parsed = json.loads(text)
    assert "created_at" not in parsed
    assert "generated_at" not in parsed
    assert "timestamp" not in parsed
    for entry in parsed["findings"]:
        assert "created_at" not in entry
        assert "timestamp" not in entry


def test_serialize_baseline_handles_empty_findings(tmp_path):
    out = tmp_path / "baseline.json"
    text = serialize_baseline(
        [],
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    parsed = json.loads(text)
    assert parsed["findings"] == []
    assert parsed["version"] == BASELINE_VERSION


def test_serialize_baseline_scan_types_serialized_as_string_values(tmp_path):
    out = tmp_path / "baseline.json"
    text = serialize_baseline(
        _sample_findings(),
        target_path=tmp_path,
        scan_types=[ScanType.CODE, ScanType.DEPENDENCY],
        output_file=out,
    )
    parsed = json.loads(text)
    assert parsed["scan_types"] == ["code", "dependency"]


@pytest.mark.parametrize("call", [1, 2, 3])
def test_write_baseline_repeated_calls_byte_identical(tmp_path, call):
    findings = _sample_findings()
    out = tmp_path / f"baseline_{call}.json"
    write_baseline(
        findings,
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    bytes_a = out.read_bytes()
    write_baseline(
        findings,
        target_path=tmp_path,
        scan_types=[ScanType.CODE],
        output_file=out,
    )
    bytes_b = out.read_bytes()
    assert bytes_a == bytes_b
