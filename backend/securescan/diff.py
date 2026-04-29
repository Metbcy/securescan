"""Pure-functional diff classifier for findings.

The wedge for SecureScan v0.2.0: PR comments only show NEW findings
introduced by the PR, not legacy findings that already existed on
``base``. That's what makes a security tool tolerable to leave on across
an org -- the same lesson bomdrift learned in v0.1.0.

Classification is keyed entirely on the per-finding ``fingerprint``
field (added by SS2). Two findings collide iff their fingerprints are
equal -- i.e. same scanner + rule + file + normalized line context +
CWE -- which means line shifts and whitespace edits inside the same
file do NOT reclassify a finding as "new + fixed".

This module is intentionally I/O-free except for the JSON loader helper,
so the classifier can be unit-tested without a filesystem and reused
both by the ``securescan diff`` CLI (SS6) and the GitHub Action
(SS9/SS10) which feeds it pre-scanned base/head JSONs.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .fingerprint import populate_fingerprints
from .models import Finding
from .ordering import sort_findings_canonical


@dataclass
class ChangeSet:
    """Result of comparing two finding lists.

    - ``new``: findings present in ``new_findings`` but not in ``old_findings``.
    - ``fixed``: findings present in ``old_findings`` but not in ``new_findings``.
    - ``unchanged``: findings present in both. The version retained is the
      one from ``new_findings`` so downstream renderers see the latest line
      number / metadata.

    All three lists are returned in canonical order (see
    ``ordering.sort_findings_canonical``) so PR-comment bodies and SARIF
    files are byte-identical across re-runs against the same inputs.
    """

    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    unchanged: list[Finding] = field(default_factory=list)

    def is_empty(self) -> bool:
        """True when there are no findings of any kind in this changeset."""
        return not (self.new or self.fixed or self.unchanged)

    def total_changes(self) -> int:
        """Count of findings that actually changed between old and new.

        Excludes ``unchanged`` on purpose: this is what drives the
        "post a PR comment?" / "fail the build?" decisions, and neither
        should fire when nothing meaningful moved.
        """
        return len(self.new) + len(self.fixed)


def classify(
    old_findings: list[Finding],
    new_findings: list[Finding],
) -> ChangeSet:
    """Classify findings into new / fixed / unchanged buckets.

    Pure-functional and idempotent: ``classify(a, b) == classify(a, b)``
    for any inputs ``a`` and ``b``. No I/O, no DB access, no global
    state.

    Fingerprints are populated lazily via ``populate_fingerprints`` --
    that helper is itself idempotent (it only writes to findings whose
    fingerprint is empty), so callers can pass either fully-fingerprinted
    findings or pre-fingerprint legacy data and get the same result.

    For the ``unchanged`` bucket we retain the entry from ``new_findings``
    rather than ``old_findings``, because the new one carries the most
    up-to-date line number, snippet, and metadata even though the
    fingerprint hasn't moved.
    """
    populate_fingerprints(old_findings)
    populate_fingerprints(new_findings)

    old_by_fp: dict[str, Finding] = {}
    for f in old_findings:
        old_by_fp.setdefault(f.fingerprint, f)

    new_by_fp: dict[str, Finding] = {}
    for f in new_findings:
        new_by_fp.setdefault(f.fingerprint, f)

    new_bucket: list[Finding] = []
    unchanged_bucket: list[Finding] = []
    for fp, finding in new_by_fp.items():
        if fp in old_by_fp:
            unchanged_bucket.append(finding)
        else:
            new_bucket.append(finding)

    fixed_bucket: list[Finding] = [
        finding for fp, finding in old_by_fp.items() if fp not in new_by_fp
    ]

    return ChangeSet(
        new=sort_findings_canonical(new_bucket),
        fixed=sort_findings_canonical(fixed_bucket),
        unchanged=sort_findings_canonical(unchanged_bucket),
    )


def load_findings_json(path: Path) -> list[Finding]:
    """Load findings from a ``securescan scan --output json`` file.

    Accepts either of two shapes so the GitHub Action can hand us either
    the full scan envelope or a flat array dumped from ``jq``:

    * ``{"findings": [...], ...}`` -- the full envelope
    * ``[...]``                     -- a flat list of finding dicts

    Each entry is parsed via ``Finding.model_validate`` (Pydantic v2).
    Missing ``fingerprint`` fields are tolerated (defaulted to "")
    because the classifier will recompute them on the way through.

    The loader is also intentionally lenient about the noisy fields the
    canonical baseline format (TS8) drops -- ``scan_id``, ``description``,
    ``remediation``, ``metadata``, ``compliance_tags``. These are not
    inputs to the fingerprint and not consumed by the diff classifier,
    so we default them to empty values rather than rejecting a baseline
    JSON the user just generated. This makes ``baseline_writer``
    output round-trippable through this loader.

    Raises ``json.JSONDecodeError`` on malformed input -- callers (the
    CLI / GH Action) are responsible for surfacing that to the user.
    """
    raw = Path(path).read_text(encoding="utf-8")
    data = json.loads(raw)

    if isinstance(data, dict) and "findings" in data:
        items = data["findings"]
    elif isinstance(data, list):
        items = data
    else:
        items = []

    findings: list[Finding] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        item.setdefault("fingerprint", "")
        item.setdefault("scan_id", "")
        item.setdefault("description", "")
        item.setdefault("remediation", "")
        item.setdefault("metadata", {})
        item.setdefault("compliance_tags", [])
        findings.append(Finding.model_validate(item))
    return findings
