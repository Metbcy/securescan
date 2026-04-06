"""Dockerfile security scanner — checks Dockerfiles for security best practices."""
import re
from pathlib import Path
from .base import BaseScanner
from ..models import Finding, ScanType, Severity

# Security rules for Dockerfiles
RULES = [
    {
        "id": "DL001",
        "pattern": r"^\s*FROM\s+.*:latest",
        "title": "Using ':latest' tag in FROM",
        "severity": Severity.MEDIUM,
        "description": "Using the ':latest' tag makes builds non-reproducible and may introduce unexpected vulnerabilities.",
        "remediation": "Pin to a specific image version, e.g., 'FROM python:3.12-slim'.",
    },
    {
        "id": "DL002",
        "pattern": r"^\s*USER\s+root\s*$",
        "title": "Running as root user",
        "severity": Severity.HIGH,
        "description": "Container runs as root, which increases the attack surface if compromised.",
        "remediation": "Add 'USER nonroot' or create a dedicated user with 'RUN useradd -r appuser && USER appuser'.",
    },
    {
        "id": "DL003",
        "pattern": r"^\s*RUN\s+.*curl.*\|\s*(sh|bash)",
        "title": "Piping curl to shell",
        "severity": Severity.HIGH,
        "description": "Downloading and executing scripts from the internet in one step is risky — the script could be compromised.",
        "remediation": "Download the script first, verify its checksum, then execute it.",
    },
    {
        "id": "DL004",
        "pattern": r"^\s*RUN\s+.*apt-get\s+install(?!.*--no-install-recommends)",
        "title": "apt-get install without --no-install-recommends",
        "severity": Severity.LOW,
        "description": "Installing recommended packages increases image size and attack surface.",
        "remediation": "Use 'apt-get install --no-install-recommends' to minimize installed packages.",
    },
    {
        "id": "DL005",
        "pattern": r"^\s*EXPOSE\s+(22|23|25|3389)\s*$",
        "title": "Exposing sensitive port",
        "severity": Severity.HIGH,
        "description": "Exposing SSH (22), Telnet (23), SMTP (25), or RDP (3389) ports suggests insecure services in the container.",
        "remediation": "Remove the EXPOSE directive for sensitive ports. Use secure alternatives.",
    },
    {
        "id": "DL006",
        "pattern": r"^\s*ADD\s+https?://",
        "title": "Using ADD to fetch remote URLs",
        "severity": Severity.MEDIUM,
        "description": "ADD with URLs is unpredictable — use COPY with a prior RUN curl/wget for better control and caching.",
        "remediation": "Replace 'ADD <url>' with 'RUN curl -o <file> <url>' followed by 'COPY'.",
    },
    {
        "id": "DL007",
        "pattern": r"^\s*ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN|CREDENTIAL).*=",
        "title": "Secret stored in ENV directive",
        "severity": Severity.CRITICAL,
        "description": "Secrets in ENV directives are visible in image history and to anyone with access to the image.",
        "remediation": "Use Docker secrets, build args with --secret, or runtime environment variables instead.",
    },
    {
        "id": "DL008",
        "pattern": r"^\s*RUN\s+.*chmod\s+777",
        "title": "Setting world-writable permissions (777)",
        "severity": Severity.MEDIUM,
        "description": "chmod 777 gives all users read, write, and execute permissions, which is a security risk.",
        "remediation": "Use more restrictive permissions like 755 for directories or 644 for files.",
    },
    {
        "id": "DL009",
        "pattern": r"^\s*RUN\s+.*pip\s+install(?!.*--no-cache-dir)",
        "title": "pip install without --no-cache-dir",
        "severity": Severity.LOW,
        "description": "pip caches downloaded packages, increasing image size unnecessarily.",
        "remediation": "Use 'pip install --no-cache-dir' to reduce image size.",
    },
    {
        "id": "DL010",
        "pattern": None,  # Special: check if no USER directive exists
        "title": "No USER directive found",
        "severity": Severity.MEDIUM,
        "description": "No USER directive means the container runs as root by default.",
        "remediation": "Add a USER directive to run the container as a non-root user.",
    },
]


class DockerfileScanner(BaseScanner):
    name = "dockerfile"
    scan_type = ScanType.IAC
    description = "Checks Dockerfiles for security best practices including root user, exposed secrets, insecure commands, and image pinning."
    checks = [
        "Running containers as root",
        "Secrets in ENV directives",
        "Unpinned base image tags (:latest)",
        "Piping curl to shell (curl | sh)",
        "Exposing sensitive ports (SSH, Telnet, RDP)",
        "World-writable file permissions (chmod 777)",
        "Insecure ADD from remote URLs",
        "Missing --no-install-recommends",
    ]

    async def is_available(self) -> bool:
        return True  # Built-in, no external tool needed

    @property
    def install_hint(self) -> str:
        return "Built-in scanner, always available"

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        findings = []
        target = Path(target_path)

        dockerfiles = []
        if target.is_file() and target.name in ("Dockerfile", ".dockerignore"):
            if target.name == "Dockerfile":
                dockerfiles = [target]
        elif target.is_dir():
            # Find all Dockerfiles
            dockerfiles = list(target.rglob("Dockerfile"))
            dockerfiles += list(target.rglob("Dockerfile.*"))
            dockerfiles += list(target.rglob("*.dockerfile"))

        for dockerfile in dockerfiles:
            findings.extend(self._check_file(dockerfile, scan_id))

        return findings

    def _check_file(self, filepath: Path, scan_id: str) -> list[Finding]:
        findings = []
        try:
            content = filepath.read_text(errors="ignore")
            lines = content.split("\n")

            has_user_directive = any(
                re.match(r"^\s*USER\s+", line, re.IGNORECASE) for line in lines
            )

            for line_num, line in enumerate(lines, 1):
                for rule in RULES:
                    if rule["pattern"] is None:
                        continue
                    if re.search(rule["pattern"], line, re.IGNORECASE):
                        findings.append(Finding(
                            scan_id=scan_id,
                            scanner=self.name,
                            scan_type=self.scan_type,
                            severity=rule["severity"],
                            title=rule["title"],
                            description=rule["description"],
                            file_path=str(filepath),
                            line_start=line_num,
                            rule_id=f"dockerfile/{rule['id']}",
                            remediation=rule["remediation"],
                        ))

            # Check for missing USER directive
            if not has_user_directive and any(
                re.match(r"^\s*FROM\s+", line, re.IGNORECASE) for line in lines
            ):
                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.MEDIUM,
                    title="No USER directive found",
                    description="No USER directive means the container runs as root by default.",
                    file_path=str(filepath),
                    rule_id="dockerfile/DL010",
                    remediation="Add a USER directive to run the container as a non-root user.",
                ))
        except Exception:
            pass
        return findings
