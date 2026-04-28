"""OWASP ZAP scanner wrapper.

Wraps the python-owasp-zap-v2.4 library (optional dependency).  If zapv2
is not installed, or if a running ZAP instance cannot be reached, the
scanner reports itself as unavailable and returns no findings.
"""
import asyncio
import time
from typing import Optional

try:
    from zapv2 import ZAPv2 as zapv2_cls
    _ZAP_AVAILABLE = True
except ImportError:
    zapv2_cls = None  # type: ignore[assignment,misc]
    _ZAP_AVAILABLE = False

from .base import BaseScanner
from ..models import Finding, ScanType, Severity
from ..config import settings

# Map ZAP integer risk levels to Finding severities
_RISK_MAP: dict[int, Severity] = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
}


class ZapScanner(BaseScanner):
    name = "zap"
    scan_type = ScanType.DAST
    description = (
        "OWASP ZAP active scanner wrapper. Spiders the target URL then runs "
        "an active scan to discover vulnerabilities."
    )
    checks = [
        "Active web-application vulnerability scanning (XSS, SQLi, etc.)",
        "Spider/crawl of the target URL",
        "Alert collection mapped to severity levels",
    ]

    @property
    def install_hint(self) -> str:
        return (
            "pip install python-owasp-zap-v2.4  "
            "and start the ZAP daemon: "
            "zap.sh -daemon -port 8080 -config api.key=<key>"
        )

    def _make_zap(self) -> Optional[object]:
        """Return a ZAPv2 client, or None if unavailable."""
        if not _ZAP_AVAILABLE:
            return None
        return zapv2_cls(
            apikey=settings.zap_api_key or "",
            proxies={"http": settings.zap_address, "https": settings.zap_address},
        )

    async def is_available(self) -> bool:
        if not _ZAP_AVAILABLE:
            return False
        try:
            zap = self._make_zap()
            # Run the blocking version() call in a thread so we don't block the
            # event loop.
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: zap.core.version
            )
            return True
        except Exception:
            return False

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        target_url: Optional[str] = kwargs.get("target_url")
        if not target_url:
            return []

        zap = self._make_zap()
        if zap is None:
            return []

        loop = asyncio.get_event_loop()

        def _run_zap() -> list[Finding]:
            # --- Spider ---
            spider_id = zap.spider.scan(target_url)
            while int(zap.spider.status(spider_id)) < 100:
                time.sleep(1)

            # --- Active scan ---
            ascan_id = zap.ascan.scan(target_url)
            while int(zap.ascan.status(ascan_id)) < 100:
                time.sleep(2)

            # --- Collect alerts ---
            alerts = zap.core.alerts(baseurl=target_url)
            return self._alerts_to_findings(alerts, scan_id, target_url)

        findings = await loop.run_in_executor(None, _run_zap)
        return findings

    def _alerts_to_findings(
        self,
        alerts: list[dict],
        scan_id: str,
        target_url: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for alert in alerts:
            risk_level = int(alert.get("riskcode", 0))
            severity = _RISK_MAP.get(risk_level, Severity.INFO)
            findings.append(
                Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=severity,
                    title=alert.get("alert", "ZAP Alert"),
                    description=alert.get("description", ""),
                    rule_id=f"zap-{alert.get('pluginid', 'unknown')}",
                    remediation=alert.get("solution", ""),
                    metadata={
                        "target_url": target_url,
                        "url": alert.get("url", ""),
                        "param": alert.get("param", ""),
                        "evidence": alert.get("evidence", ""),
                        "cweid": alert.get("cweid", ""),
                        "wascid": alert.get("wascid", ""),
                    },
                )
            )
        return findings
