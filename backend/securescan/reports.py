"""Security assessment report generation (HTML + PDF).

The HTML render path is deterministic for the same logical inputs:
findings are passed through ``sort_findings_canonical`` and the
``scanners_run`` list shown in the summary section is sorted. Wall-clock
strings in the rendered output come exclusively from the ``Scan``
model's ``started_at``/``completed_at`` (real audit data passed in by
the caller); no ``datetime.now()`` is called inside render. The PDF path
is intentionally NOT covered by byte-identity tests for v0.2.0 — its
binary form depends on font cache state.
"""

from pathlib import Path

import jinja2

from .models import Finding, Scan, ScanSummary, Severity
from .ordering import sort_findings_canonical


class ReportGenerator:
    """Generate HTML and PDF security assessment reports from scan results."""

    def __init__(self, template_dir: Path):
        # autoescape is already on (autoescape=True is identical), but
        # semgrep's direct-use-of-jinja2 rule looks for the explicit
        # select_autoescape() call shape and won't recognise the bool
        # form. Functionally equivalent; satisfies the lint.
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )

    def generate_html(
        self,
        scan: Scan,
        findings: list[Finding],
        summary: ScanSummary,
        compliance_coverage: list[dict],
    ) -> str:
        """Render findings into an HTML report string.

        Output is byte-identical for the same ``scan``/``findings``/
        ``summary``/``compliance_coverage`` inputs: findings are sorted
        canonically and ``summary.scanners_run`` is rendered in sorted
        order so dict/set iteration order doesn't leak into the page.
        """
        sorted_findings = sort_findings_canonical(findings)
        top_findings = [
            f for f in sorted_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]
        sorted_summary = summary.model_copy(
            update={"scanners_run": sorted(summary.scanners_run)},
        )
        template = self._env.get_template("report.html")
        return template.render(
            scan=scan,
            findings=sorted_findings,
            summary=sorted_summary,
            compliance_coverage=compliance_coverage,
            top_findings=top_findings,
        )

    def generate_pdf(
        self,
        scan: Scan,
        findings: list[Finding],
        summary: ScanSummary,
        compliance_coverage: list[dict],
    ) -> bytes:
        """Render findings into a PDF report via WeasyPrint.

        Note: PDF byte-identity is NOT guaranteed across runs even when
        the input HTML is identical, because WeasyPrint embeds font and
        producer metadata that depends on the host's font cache. PDF
        determinism is deferred for v0.2.0; use ``generate_html`` if
        byte-identical output is required.

        WeasyPrint is an optional dependency. Install with the ``[pdf]``
        extra (``pip install 'securescan[pdf]'``) or use the container
        image, which ships it pre-installed. If it isn't available we
        raise a ``RuntimeError`` with that hint instead of letting the
        bare ``ImportError`` (which on bare Linux containers usually
        surfaces as a missing Cairo / Pango / GObject system library)
        bubble up unexplained.
        """
        try:
            from weasyprint import HTML  # type: ignore[import-not-found]
        except ImportError as e:
            raise RuntimeError(
                "PDF reports require the 'pdf' extra. "
                "Install with: pip install 'securescan[pdf]' "
                "(or use the container image, which ships weasyprint pre-installed)."
            ) from e
        html_string = self.generate_html(scan, findings, summary, compliance_coverage)
        return HTML(string=html_string).write_pdf()
