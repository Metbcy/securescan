"""Tests for ``backend/src/baseline.py``."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from src.baseline import filter_against_baseline


@dataclass
class _StubFinding:
    """Minimal duck-typed Finding used until SS2 lands the real field."""
    fingerprint: str
    title: str = "stub"


def test_filter_against_baseline_suppresses_matching_fingerprints(tmp_path: Path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([
        {"fingerprint": "fp-old-1"},
        {"fingerprint": "fp-old-2"},
    ]))

    findings = [
        _StubFinding(fingerprint="fp-old-1"),
        _StubFinding(fingerprint="fp-new"),
        _StubFinding(fingerprint="fp-old-2"),
    ]

    kept, suppressed = filter_against_baseline(findings, baseline)

    assert suppressed == 2
    assert len(kept) == 1
    assert kept[0].fingerprint == "fp-new"


def test_filter_against_baseline_keeps_findings_not_in_baseline(tmp_path: Path):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([{"fingerprint": "never-matches"}]))

    findings = [
        _StubFinding(fingerprint="fp-a"),
        _StubFinding(fingerprint="fp-b"),
    ]

    kept, suppressed = filter_against_baseline(findings, baseline)

    assert suppressed == 0
    assert len(kept) == 2
    assert {f.fingerprint for f in kept} == {"fp-a", "fp-b"}


def test_filter_against_baseline_handles_missing_file_gracefully(
    tmp_path: Path, capsys
):
    findings = [_StubFinding(fingerprint="fp-a")]
    missing = tmp_path / "does-not-exist.json"

    kept, suppressed = filter_against_baseline(findings, missing)

    assert suppressed == 0
    assert kept == findings
    captured = capsys.readouterr()
    assert "baseline file not found" in captured.err
    assert str(missing) in captured.err


def test_filter_against_baseline_handles_malformed_json_gracefully(
    tmp_path: Path, capsys
):
    baseline = tmp_path / "broken.json"
    baseline.write_text("{not valid json,,,")

    findings = [_StubFinding(fingerprint="fp-a"), _StubFinding(fingerprint="fp-b")]

    kept, suppressed = filter_against_baseline(findings, baseline)

    assert suppressed == 0
    assert kept == findings
    captured = capsys.readouterr()
    assert "could not parse baseline file" in captured.err


def test_filter_against_baseline_accepts_wrapped_findings_shape(tmp_path: Path):
    """The output of ``securescan scan --output json`` is a list of full
    Finding dicts; the helper should accept that shape too."""
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({
        "findings": [
            {"fingerprint": "fp-old", "title": "legacy SQLi"},
        ]
    }))

    findings = [
        _StubFinding(fingerprint="fp-old"),
        _StubFinding(fingerprint="fp-new"),
    ]

    kept, suppressed = filter_against_baseline(findings, baseline)

    assert suppressed == 1
    assert kept[0].fingerprint == "fp-new"


def test_filter_against_baseline_handles_findings_without_fingerprint(tmp_path: Path):
    """Until SS2 lands the field, some Findings won't have a fingerprint
    attribute. Those should never be suppressed."""

    class _Bare:
        def __init__(self, name):
            self.name = name

    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps([{"fingerprint": "fp-old"}]))

    findings = [_Bare("a"), _Bare("b")]

    kept, suppressed = filter_against_baseline(findings, baseline)

    assert suppressed == 0
    assert len(kept) == 2
