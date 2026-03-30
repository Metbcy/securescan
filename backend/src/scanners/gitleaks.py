"""Git hygiene scanner — checks .gitignore coverage and repo security practices."""
from pathlib import Path
from .base import BaseScanner
from ..models import Finding, ScanType, Severity

# Files/patterns that should be in .gitignore
SHOULD_BE_IGNORED = {
    ".env": Severity.CRITICAL,
    ".env.local": Severity.CRITICAL,
    ".env.production": Severity.CRITICAL,
    ".env.staging": Severity.CRITICAL,
    "*.pem": Severity.CRITICAL,
    "*.key": Severity.CRITICAL,
    "*.p12": Severity.CRITICAL,
    "*.pfx": Severity.CRITICAL,
    "id_rsa": Severity.CRITICAL,
    "id_ed25519": Severity.CRITICAL,
    "node_modules/": Severity.LOW,
    "venv/": Severity.LOW,
    "__pycache__/": Severity.LOW,
    ".DS_Store": Severity.INFO,
    "Thumbs.db": Severity.INFO,
    "*.pyc": Severity.LOW,
    "*.sqlite3": Severity.MEDIUM,
    "*.db": Severity.MEDIUM,
    "*.log": Severity.LOW,
    "coverage/": Severity.LOW,
    ".coverage": Severity.LOW,
    "dist/": Severity.LOW,
    "build/": Severity.LOW,
}

# Sensitive files that should never be in a repo
SENSITIVE_FILES = [
    (".env", Severity.CRITICAL, "Environment file with potential secrets"),
    (".env.local", Severity.CRITICAL, "Local environment file with potential secrets"),
    (".env.production", Severity.CRITICAL, "Production environment file"),
    ("id_rsa", Severity.CRITICAL, "SSH private key"),
    ("id_ed25519", Severity.CRITICAL, "SSH private key"),
    ("credentials.json", Severity.CRITICAL, "Credentials file"),
    ("service-account.json", Severity.CRITICAL, "Cloud service account key"),
    (".htpasswd", Severity.HIGH, "HTTP authentication file"),
    ("wp-config.php", Severity.HIGH, "WordPress config with database credentials"),
]


class GitHygieneScanner(BaseScanner):
    name = "git-hygiene"
    scan_type = ScanType.CODE
    description = "Checks .gitignore coverage, detects sensitive files that shouldn't be in version control, and audits git security practices."
    checks = [
        "Missing .gitignore entries for secrets (.env, keys)",
        "Sensitive files committed to repo",
        "Missing .gitignore file",
        "Database files in version control",
        "Build artifacts committed",
        "SSH/TLS private keys in repo",
    ]

    async def is_available(self) -> bool:
        return True

    @property
    def install_hint(self) -> str:
        return "Built-in scanner, always available"

    async def scan(self, target_path: str, scan_id: str) -> list[Finding]:
        findings = []
        target = Path(target_path)

        if not target.is_dir():
            return findings

        # Check for .gitignore
        gitignore = target / ".gitignore"
        gitignore_content = ""
        if not gitignore.exists():
            findings.append(Finding(
                scan_id=scan_id, scanner=self.name, scan_type=self.scan_type,
                severity=Severity.MEDIUM,
                title="No .gitignore file found",
                description="Project has no .gitignore file. Sensitive files, build artifacts, and dependencies may be committed to version control.",
                file_path=str(target),
                rule_id="git-hygiene/no-gitignore",
                remediation="Create a .gitignore file. Use gitignore.io or GitHub's templates for your project type.",
            ))
        else:
            gitignore_content = gitignore.read_text(errors="ignore")

        # Check for missing .gitignore entries
        if gitignore_content:
            for pattern, severity in SHOULD_BE_IGNORED.items():
                clean_pattern = pattern.rstrip("/").lstrip("*.")
                if clean_pattern not in gitignore_content and pattern not in gitignore_content:
                    # Only warn if the file/dir actually exists in the project
                    exists = False
                    if pattern.endswith("/"):
                        exists = (target / pattern.rstrip("/")).is_dir()
                    elif "*" in pattern:
                        exists = bool(list(target.glob(pattern))[:1])
                    else:
                        exists = (target / pattern).exists()

                    if exists and severity in (Severity.CRITICAL, Severity.HIGH):
                        findings.append(Finding(
                            scan_id=scan_id, scanner=self.name, scan_type=self.scan_type,
                            severity=severity,
                            title=f"'{pattern}' not in .gitignore but exists in project",
                            description=f"'{pattern}' exists in the project but is not listed in .gitignore. This file may contain sensitive data.",
                            file_path=str(gitignore),
                            rule_id=f"git-hygiene/missing-ignore-{clean_pattern}",
                            remediation=f"Add '{pattern}' to your .gitignore file.",
                        ))

        # Check for sensitive files in the project
        for filename, severity, desc in SENSITIVE_FILES:
            for found in target.rglob(filename):
                if "node_modules" in str(found) or "venv" in str(found) or ".git/" in str(found):
                    continue
                findings.append(Finding(
                    scan_id=scan_id, scanner=self.name, scan_type=self.scan_type,
                    severity=severity,
                    title=f"Sensitive file in project: {filename}",
                    description=f"{desc}. File found at {found.relative_to(target)}.",
                    file_path=str(found),
                    rule_id=f"git-hygiene/sensitive-file-{filename.replace('.', '-')}",
                    remediation=f"Remove '{filename}' from version control, add it to .gitignore, and rotate any credentials it contains.",
                ))

        return findings
