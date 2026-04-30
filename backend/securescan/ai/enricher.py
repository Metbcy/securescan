"""AI enrichment for security findings using Groq API."""

import os

import httpx

from ..models import Finding, ScanSummary

GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


class AIEnricher:
    def __init__(self, api_key: str | None = None):
        self.api_key = (
            api_key or os.environ.get("GROQ_API_KEY") or os.environ.get("SECURESCAN_GROQ_API_KEY")
        )
        self.model = "llama-3.3-70b-versatile"

    @property
    def is_available(self) -> bool:
        return self.api_key is not None

    async def enrich_finding(self, finding: Finding) -> Finding:
        """Add AI-generated remediation advice to a finding."""
        if not self.is_available:
            return finding

        prompt = f"""You are a security expert. Analyze this security finding and provide a concise remediation suggestion.

Finding:
- Title: {finding.title}
- Severity: {finding.severity.value}
- Description: {finding.description}
- File: {finding.file_path or "N/A"}
- Rule: {finding.rule_id or "N/A"}
- CWE: {finding.cwe or "N/A"}

Respond with ONLY a concise remediation suggestion (2-3 sentences max). Include a code fix example if applicable."""

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    GROQ_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.3,
                        "max_tokens": 300,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    remediation = data["choices"][0]["message"]["content"].strip()
                    finding.remediation = remediation
        except Exception:
            pass  # Fail silently — AI enrichment is optional

        return finding

    async def enrich_findings(self, findings: list[Finding]) -> list[Finding]:
        """Enrich multiple findings. Only enriches HIGH and CRITICAL to save API quota."""
        if not self.is_available:
            return findings

        for finding in findings:
            if finding.severity.value in ("critical", "high"):
                await self.enrich_finding(finding)
        return findings

    async def generate_summary(self, findings: list[Finding], summary: ScanSummary) -> str:
        """Generate an executive summary of the scan results."""
        if not self.is_available:
            return self._basic_summary(summary)

        # Build a condensed view of findings for the prompt
        findings_text = ""
        for f in findings[:20]:  # Limit to avoid token overflow
            findings_text += f"- [{f.severity.value.upper()}] {f.title}"
            if f.file_path:
                findings_text += f" ({f.file_path})"
            findings_text += "\n"

        prompt = f"""You are a security analyst. Write a brief executive summary (3-4 sentences) of these scan results.

Stats: {summary.total_findings} findings — {summary.critical} critical, {summary.high} high, {summary.medium} medium, {summary.low} low
Risk Score: {summary.risk_score}/100

Top findings:
{findings_text}

Be specific about the types of issues found and prioritize what to fix first."""

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(
                    GROQ_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.5,
                        "max_tokens": 300,
                    },
                )
                if response.status_code == 200:
                    data = response.json()
                    return data["choices"][0]["message"]["content"].strip()
        except Exception:
            pass

        return self._basic_summary(summary)

    def _basic_summary(self, summary: ScanSummary) -> str:
        """Fallback summary without AI."""
        if summary.total_findings == 0:
            return "No security findings detected. The codebase appears clean."
        parts = []
        if summary.critical > 0:
            parts.append(f"{summary.critical} critical")
        if summary.high > 0:
            parts.append(f"{summary.high} high")
        if summary.medium > 0:
            parts.append(f"{summary.medium} medium")
        if summary.low > 0:
            parts.append(f"{summary.low} low")
        return f"Found {summary.total_findings} security issues ({', '.join(parts)}). Address critical and high severity findings first."
