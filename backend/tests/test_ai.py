"""Tests for AI enrichment."""

from securescan.ai import AIEnricher
from securescan.models import ScanSummary


def test_enricher_unavailable_without_key():
    enricher = AIEnricher()
    assert enricher.is_available is False


def test_enricher_available_with_key():
    enricher = AIEnricher(api_key="test-key")
    assert enricher.is_available is True


def test_basic_summary_no_findings():
    enricher = AIEnricher()
    summary = ScanSummary(
        total_findings=0,
        critical=0,
        high=0,
        medium=0,
        low=0,
        info=0,
        risk_score=0.0,
        scanners_run=[],
    )
    result = enricher._basic_summary(summary)
    assert "No security findings" in result


def test_basic_summary_with_findings():
    enricher = AIEnricher()
    summary = ScanSummary(
        total_findings=5,
        critical=1,
        high=2,
        medium=1,
        low=1,
        info=0,
        risk_score=50.0,
        scanners_run=["semgrep"],
    )
    result = enricher._basic_summary(summary)
    assert "5 security issues" in result
    assert "1 critical" in result
