"""Built-in DAST scanner using httpx.

Checks for missing security headers, information-disclosure headers, and
insecure cookie flags without requiring any external tool.
"""

import httpx

from ..config import settings
from ..models import Finding, ScanType, Severity
from .base import BaseScanner

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

INFO_DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
]


class BuiltinDastScanner(BaseScanner):
    name = "builtin_dast"
    scan_type = ScanType.DAST
    description = (
        "Lightweight DAST scanner that checks HTTP response headers and cookies "
        "for common security misconfigurations."
    )
    checks = [
        "Missing security headers (HSTS, CSP, X-Content-Type-Options, etc.)",
        "Information-disclosure headers (Server, X-Powered-By)",
        "Insecure cookie flags (missing Secure or HttpOnly)",
    ]

    async def is_available(self) -> bool:
        return True

    @property
    def install_hint(self) -> str:
        return "pip install httpx  # already bundled with SecureScan"

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        target_url: str | None = kwargs.get("target_url")
        if not target_url:
            return []

        findings: list[Finding] = []
        try:
            async with httpx.AsyncClient(
                follow_redirects=True,
                timeout=settings.dast_timeout,
                verify=False,  # intentional: we want to reach misconfigured targets
            ) as client:
                response = await client.get(target_url)

            findings.extend(self._check_security_headers(response, scan_id, target_url))
            findings.extend(self._check_info_disclosure_headers(response, scan_id, target_url))
            findings.extend(self._check_cookies(response, scan_id, target_url))
        except httpx.RequestError as exc:
            findings.append(
                Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.INFO,
                    title="DAST scan error: request failed",
                    description=str(exc),
                    metadata={"target_url": target_url},
                )
            )
        return findings

    def _check_security_headers(
        self,
        response: httpx.Response,
        scan_id: str,
        target_url: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for header in SECURITY_HEADERS:
            if header.lower() not in response.headers:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.MEDIUM,
                        title=f"Missing security header: {header}",
                        description=(
                            f"The response from {target_url} is missing the '{header}' "
                            "HTTP security header, which helps protect against common "
                            "web attacks."
                        ),
                        rule_id=f"missing-header-{header.lower()}",
                        remediation=f"Add the '{header}' header to all HTTP responses.",
                        metadata={"target_url": target_url, "header": header},
                    )
                )
        return findings

    def _check_info_disclosure_headers(
        self,
        response: httpx.Response,
        scan_id: str,
        target_url: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for header in INFO_DISCLOSURE_HEADERS:
            value = response.headers.get(header.lower())
            if value:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.LOW,
                        title=f"Information disclosure header: {header}",
                        description=(
                            f"The response from {target_url} includes the '{header}' "
                            f"header with value '{value}', which discloses server "
                            "technology information to potential attackers."
                        ),
                        rule_id=f"info-disclosure-{header.lower()}",
                        remediation=(
                            f"Remove or obfuscate the '{header}' header in your "
                            "web server / application configuration."
                        ),
                        metadata={"target_url": target_url, "header": header, "value": value},
                    )
                )
        return findings

    def _check_cookies(
        self,
        response: httpx.Response,
        scan_id: str,
        target_url: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        # httpx exposes raw Set-Cookie headers; iterate them to inspect flags
        set_cookie_headers = response.headers.get_list("set-cookie")
        for raw_cookie in set_cookie_headers:
            cookie_name = raw_cookie.split("=")[0].strip()
            parts_lower = [p.strip().lower() for p in raw_cookie.split(";")]

            if "secure" not in parts_lower:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.MEDIUM,
                        title=f"Cookie missing Secure flag: {cookie_name}",
                        description=(
                            f"The cookie '{cookie_name}' set by {target_url} does not "
                            "have the Secure flag, meaning it can be transmitted over "
                            "unencrypted HTTP connections."
                        ),
                        rule_id="cookie-missing-secure",
                        remediation="Set the Secure flag on all cookies.",
                        metadata={"target_url": target_url, "cookie": cookie_name},
                    )
                )

            if "httponly" not in parts_lower:
                findings.append(
                    Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.MEDIUM,
                        title=f"Cookie missing HttpOnly flag: {cookie_name}",
                        description=(
                            f"The cookie '{cookie_name}' set by {target_url} does not "
                            "have the HttpOnly flag, making it accessible to JavaScript "
                            "and increasing the risk of XSS-based session theft."
                        ),
                        rule_id="cookie-missing-httponly",
                        remediation="Set the HttpOnly flag on all session/auth cookies.",
                        metadata={"target_url": target_url, "cookie": cookie_name},
                    )
                )
        return findings
