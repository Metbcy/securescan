"""Canonical baseline JSON writer/serializer.

The baseline format is what ``securescan compare`` and
``securescan diff --baseline`` consume. Pinning the shape and
ordering here in a single helper means CI diffs of the baseline
stay tiny and readable.

Determinism contract
--------------------
* No wall-clock fields (no ``created_at``, no ``now()``). The git
  history is the timestamp.
* Findings are sorted via :func:`securescan.ordering.sort_findings_canonical`
  before serialization, so two runs over the same logical input produce
  byte-identical output.
* JSON is emitted with ``indent=2`` and ``sort_keys=True`` so key order
  inside each finding object is also stable.
* ``ensure_ascii=False`` so non-ASCII rule names render readably in the
  diff view.

Trimmed JSON shape
------------------
The baseline keeps only what the diff/compare consumers actually need:

* ``fingerprint`` -- identity for classify().
* ``scanner``, ``rule_id``, ``file_path``, ``line_start``, ``cwe`` --
  the inputs to :func:`securescan.fingerprint.fingerprint`, kept so
  the file is self-describing without a key.
* ``severity``, ``scan_type``, ``title`` -- minimal context for
  human readers and renderer output.

Explicitly dropped: ``id``, ``scan_id``, ``description``, ``remediation``,
``metadata``, ``compliance_tags``. Either runtime-generated, bulky, or
non-deterministic across runs.

Atomic writes
-------------
:func:`write_baseline` writes to a sibling ``*.tmp`` file in the same
directory and then ``os.replace``s it onto the target path. This means
a SIGINT mid-write leaves either the previous file or no file at all,
never a half-written one a downstream ``compare`` would silently parse.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .models import Finding, ScanType
from .ordering import sort_findings_canonical

BASELINE_VERSION = 1

_FINDING_KEYS: tuple[str, ...] = (
    "fingerprint",
    "scanner",
    "scan_type",
    "severity",
    "title",
    "rule_id",
    "file_path",
    "line_start",
    "cwe",
)


def _finding_to_baseline_dict(f: Finding) -> dict:
    """Project a Finding to the trimmed baseline shape.

    Optional fields that are ``None`` (``rule_id``, ``file_path``,
    ``line_start``, ``cwe``) are emitted as ``null`` in JSON to keep
    the per-finding key set stable across rows -- a missing key would
    make line-based diffs noisier when one run picks up a CWE another
    didn't.
    """
    return {
        "fingerprint": getattr(f, "fingerprint", "") or "",
        "scanner": f.scanner,
        "scan_type": f.scan_type.value if hasattr(f.scan_type, "value") else f.scan_type,
        "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
        "title": f.title,
        "rule_id": f.rule_id,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "cwe": f.cwe,
    }


def _baseline_target_path(target_path: Path, output_file: Path) -> str:
    """Render the ``target_path`` field for the baseline envelope.

    Absolute paths are bad UX in a checked-in artifact: the same repo
    cloned to ``/home/alice/repo`` and ``/home/bob/repo`` would diff on
    every line of the file. We emit a path **relative to the baseline
    file's parent directory** when possible (the common case: baseline
    lives at ``<repo>/.securescan/baseline.json`` and the target is the
    repo root, yielding ``..``), and fall back to the absolute target
    only when ``relpath`` would have to cross drives / unrelated trees.
    """
    target_abs = Path(target_path).resolve()
    output_dir = Path(output_file).resolve().parent
    try:
        rel = os.path.relpath(target_abs, output_dir)
    except ValueError:
        return str(target_abs)
    return rel


def serialize_baseline(
    findings: list[Finding],
    *,
    target_path: Path,
    scan_types: list[ScanType],
    output_file: Path,
) -> str:
    """Return the JSON text for the baseline file. Pure function; no IO.

    The output is byte-deterministic for a given logical input:

    * Findings sorted via :func:`sort_findings_canonical`.
    * JSON pretty-printed (``indent=2``) with ``sort_keys=True``.
    * Trailing newline so POSIX tools and ``git diff`` behave cleanly.
    * Non-ASCII passed through verbatim (``ensure_ascii=False``).
    """
    sorted_findings = sort_findings_canonical(list(findings))

    envelope = {
        "version": BASELINE_VERSION,
        "generated_by": "securescan",
        "target_path": _baseline_target_path(Path(target_path), Path(output_file)),
        "scan_types": sorted(t.value if hasattr(t, "value") else str(t) for t in scan_types),
        "findings": [_finding_to_baseline_dict(f) for f in sorted_findings],
    }

    text = json.dumps(
        envelope,
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
    if not text.endswith("\n"):
        text += "\n"
    return text


def write_baseline(
    findings: list[Finding],
    *,
    target_path: Path,
    scan_types: list[ScanType],
    output_file: Path,
) -> int:
    """Write the baseline to ``output_file`` atomically. Returns bytes written.

    The parent directory is created if missing (``mkdir(parents=True,
    exist_ok=True)``). The write goes to a sibling ``<name>.tmp`` file
    in the same directory and is then ``os.replace``-d onto the target,
    so a crash mid-write leaves either the previous version of the
    baseline or no file at all -- never a half-written file that
    ``securescan compare`` would silently parse.
    """
    output_file = Path(output_file)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    text = serialize_baseline(
        findings,
        target_path=Path(target_path),
        scan_types=scan_types,
        output_file=output_file,
    )
    payload = text.encode("utf-8")

    tmp = output_file.with_suffix(output_file.suffix + ".tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, output_file)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass

    return len(payload)
