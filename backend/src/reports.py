"""Security assessment report generation (HTML + PDF)."""
from pathlib import Path

import jinja2

from .models import Finding, Scan, ScanSummary, Severity


class ReportGenerator:
    """Generate HTML and PDF security assessment reports from scan results."""

    def __init__(self, template_dir: Path):
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=True,
        )

    def generate_html(
        self,
        scan: Scan,
        findings: list[Finding],
        summary: ScanSummary,
        compliance_coverage: list[dict],
    ) -> str:
        """Render findings into an HTML report string."""
        severity_rank = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4,
        }
        sorted_findings = sorted(findings, key=lambda f: severity_rank.get(f.severity, 5))
        top_findings = [f for f in sorted_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        template = self._env.get_template("report.html")
        return template.render(
            scan=scan,
            findings=sorted_findings,
            summary=summary,
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
        """Render findings into a PDF report via WeasyPrint."""
        from weasyprint import HTML
        html_string = self.generate_html(scan, findings, summary, compliance_coverage)
        return HTML(string=html_string).write_pdf()
