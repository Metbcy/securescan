"""Verify the PDF report path raises a clear, actionable error when
the [pdf] extra isn't installed.

This guards against future refactors that might silently swallow the
ImportError or replace it with a generic "no module named weasyprint"
message that doesn't tell the user how to fix it.

WeasyPrint is moved to an optional ``[pdf]`` extra in v0.10.3 because
it pulls in Cairo / Pango / GObject system libraries and is a common
``pip install`` failure mode on bare Linux containers. Users who don't
need PDF reporting now install SecureScan without the heavyweight
chain; users who do install via ``pip install 'securescan[pdf]'`` or
use the container image (which ships weasyprint pre-installed).
"""

from __future__ import annotations

import builtins
import sys

import pytest


def test_generate_pdf_raises_clear_error_when_weasyprint_missing(monkeypatch):
    """Calling ``ReportGenerator.generate_pdf`` without weasyprint installed
    must raise a ``RuntimeError`` whose message points the user at the
    ``[pdf]`` extra (and not a bare ``ImportError`` or "no module named ..."
    message).

    Strategy: the import is lazy (inside the method body), so we patch
    ``builtins.__import__`` to raise ``ImportError`` specifically for the
    ``weasyprint`` module, then call ``generate_pdf`` and assert the wrapped
    error fires. This works regardless of whether weasyprint is actually
    installed in the test environment (it is in the dev venv via the
    ``[dev]`` extra).
    """
    # Drop any cached weasyprint module so the lazy import re-runs through
    # our patched __import__.
    for name in list(sys.modules):
        if name == "weasyprint" or name.startswith("weasyprint."):
            monkeypatch.delitem(sys.modules, name, raising=False)

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "weasyprint" or name.startswith("weasyprint."):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    from securescan.models import Scan, ScanStatus, ScanType
    from securescan.reports import ReportGenerator
    from securescan.scoring import build_summary

    scan = Scan(
        id="test-scan",
        scan_types=[ScanType.CODE],
        target_path=".",
        status=ScanStatus.COMPLETED,
    )
    summary = build_summary([], [])

    template_dir = (
        __import__("pathlib").Path(__file__).resolve().parents[1] / "securescan" / "templates"
    )
    generator = ReportGenerator(template_dir)

    with pytest.raises(RuntimeError, match=r"securescan\[pdf\]"):
        generator.generate_pdf(scan, [], summary, compliance_coverage=[])
