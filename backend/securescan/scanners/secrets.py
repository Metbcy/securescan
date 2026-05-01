"""Secrets scanner — detects hardcoded API keys, tokens, passwords in source files and git history."""

import asyncio
import os
import re
from pathlib import Path

from ..models import Finding, ScanType, Severity
from .base import BaseScanner

# Regex patterns for common secret types
SECRET_PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
    (
        "AWS Secret Key",
        r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
        Severity.CRITICAL,
    ),
    ("GitHub Token", r"gh[ps]_[A-Za-z0-9_]{36,}", Severity.CRITICAL),
    ("GitHub Personal Access Token (Classic)", r"ghp_[A-Za-z0-9_]{36}", Severity.CRITICAL),
    (
        "Generic API Key",
        r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
        Severity.HIGH,
    ),
    (
        "Generic Secret",
        r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']',
        Severity.HIGH,
    ),
    ("Private Key", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", Severity.CRITICAL),
    ("Slack Token", r"xox[baprs]-[A-Za-z0-9\-]{10,}", Severity.HIGH),
    (
        "Slack Webhook",
        r"https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}",
        Severity.HIGH,
    ),
    ("Google API Key", r"AIza[0-9A-Za-z_\-]{35}", Severity.HIGH),
    (
        "Heroku API Key",
        r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        Severity.HIGH,
    ),
    (
        "JWT Token",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        Severity.MEDIUM,
    ),
    (
        "Generic Token",
        r'(?i)(token|bearer)\s*[=:]\s*["\']?([A-Za-z0-9_\-\.]{20,})',
        Severity.MEDIUM,
    ),
    (
        "Connection String",
        r'(?i)(mongodb|postgres|mysql|redis|amqp):\/\/[^\s"\']+:[^\s"\']+@',
        Severity.HIGH,
    ),
    (
        "Base64 Encoded Secret",
        r'(?i)(password|secret|key|token)\s*[=:]\s*["\']?[A-Za-z0-9+/]{40,}={0,2}["\']?',
        Severity.MEDIUM,
    ),
]

# File extensions to skip
SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".zip",
    ".tar",
    ".gz",
    ".pdf",
    ".exe",
    ".dll",
    ".so",
    ".pyc",
    ".lock",
    ".min.js",
    ".min.css",
}

# Directories to skip
SKIP_DIRS = {
    "node_modules",
    ".git",
    "venv",
    "__pycache__",
    ".next",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
}


class SecretsScanner(BaseScanner):
    name = "secrets"
    scan_type = ScanType.CODE
    description = "Detects hardcoded credentials, API keys, and tokens in source files, .env files, and git history."
    checks = [
        "AWS access keys & secret keys",
        "GitHub & GitLab tokens",
        "Private keys (RSA, EC, DSA)",
        "Database connection strings",
        "Slack, Google, Heroku API keys",
        "JWT tokens & generic secrets",
        "Secrets committed in git history",
        ".env files with sensitive values",
    ]

    async def is_available(self) -> bool:
        return True

    @property
    def install_hint(self) -> str:
        return "Built-in scanner, always available"

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        findings = []
        target = Path(target_path)

        if not target.exists():
            return findings

        # File enumeration is sync I/O; offload to a thread so a 12k-file
        # tree doesn't block the event loop and stall /health + SSE.
        files = await asyncio.to_thread(self._get_scannable_files, target)

        # Per-file read+regex is the dominant blocking work on large
        # trees — we route the full batch through one worker thread
        # rather than one to_thread call per file (avoids thread-pool
        # churn) and avoids interleaving with the event loop entirely.
        findings.extend(await asyncio.to_thread(self._scan_files_sync, files, scan_id))

        # Scan git history (last 50 commits)
        if (target / ".git").exists() or self._find_git_root(target):
            git_findings = await self._scan_git_history(target, scan_id)
            findings.extend(git_findings)

        # Scan .env files specifically
        env_findings = await self._scan_env_files(target, scan_id)
        findings.extend(env_findings)

        return findings

    def _scan_files_sync(self, files: list[Path], scan_id: str) -> list[Finding]:
        """Read + regex-scan a batch of files synchronously. Always
        invoked via asyncio.to_thread() — never call directly from an
        async context, or you'll re-introduce the event-loop block this
        method exists to avoid.
        """
        findings: list[Finding] = []
        for file_path in files:
            findings.extend(self._scan_file_sync(file_path, scan_id))
        return findings

    def _scan_file_sync(self, file_path: Path, scan_id: str) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = file_path.read_text(errors="ignore")
            lines = content.split("\n")
            for line_num, line in enumerate(lines, 1):
                # Skip comments and very long lines (likely minified/binary)
                if len(line) > 1000:
                    continue
                for pattern_name, pattern, severity in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        # Avoid false positives: skip test files, examples, placeholders
                        if self._is_likely_false_positive(line, str(file_path)):
                            continue
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                scanner=self.name,
                                scan_type=self.scan_type,
                                severity=severity,
                                title=f"Potential {pattern_name} detected",
                                description=f"Found potential {pattern_name} in {file_path.name} at line {line_num}. Review and rotate if this is a real credential.",
                                file_path=str(file_path),
                                line_start=line_num,
                                rule_id=f"secrets/{pattern_name.lower().replace(' ', '-')}",
                                remediation=f"Remove the hardcoded {pattern_name.lower()} and use environment variables or a secrets manager instead. If this is a real credential, rotate it immediately.",
                            )
                        )
                        break  # One finding per line
        except Exception:
            pass
        return findings

    async def _scan_file(self, file_path: Path, scan_id: str) -> list[Finding]:
        # Backward-compat wrapper — preserved for tests / external
        # callers that may still invoke this directly. New scan path
        # uses _scan_file_sync inside a single batched to_thread().
        return await asyncio.to_thread(self._scan_file_sync, file_path, scan_id)

    def _get_scannable_files(self, target: Path) -> list[Path]:
        """Synchronous file enumeration — must be called via
        asyncio.to_thread() from any async context. On large trees
        (e.g. a Rust target/ directory with 12k+ files) this can take
        several seconds of blocking I/O that would otherwise stall the
        whole asyncio event loop including /health and SSE delivery.
        """
        files = []
        if target.is_file():
            return [target]
        for root, dirs, filenames in os.walk(target):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in filenames:
                fpath = Path(root) / fname
                if fpath.suffix.lower() not in SKIP_EXTENSIONS:
                    # Skip files larger than 1MB
                    try:
                        if fpath.stat().st_size <= 1_000_000:
                            files.append(fpath)
                    except OSError:
                        pass
        return files

    def _find_git_root(self, path: Path) -> Path | None:
        current = path
        while current != current.parent:
            if (current / ".git").exists():
                return current
            current = current.parent
        return None

    async def _scan_file(self, file_path: Path, scan_id: str) -> list[Finding]:
        # Backward-compat wrapper — preserved for tests / external
        # callers that may still invoke this directly. New scan path
        # uses _scan_file_sync inside a single batched to_thread().
        return await asyncio.to_thread(self._scan_file_sync, file_path, scan_id)

    def _is_likely_false_positive(self, line: str, file_path: str) -> bool:
        lower_line = line.lower().strip()
        lower_path = file_path.lower()
        # Skip test/example/placeholder values
        fp_indicators = [
            "example",
            "placeholder",
            "your_",
            "xxx",
            "changeme",
            "todo",
            "fake",
            "dummy",
            "test_key",
            "sample",
            "<your",
            "{your",
        ]
        if any(ind in lower_line for ind in fp_indicators):
            return True
        # Skip test files
        if any(x in lower_path for x in ["test_", "_test.", ".test.", "fixture", "mock"]):
            return True
        return False

    async def _scan_git_history(self, target: Path, scan_id: str) -> list[Finding]:
        findings = []
        git_root = self._find_git_root(target) or target
        try:
            proc = await asyncio.create_subprocess_exec(
                "git",
                "-C",
                str(git_root),
                "log",
                "--diff-filter=A",
                "-p",
                "--all",
                "-n",
                "50",
                "--",
                "*.env",
                "*.key",
                "*.pem",
                "*.p12",
                "*.pfx",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode(errors="ignore")

            if output.strip():
                # Check if sensitive files were ever committed
                for pattern_name, pattern, severity in SECRET_PATTERNS:
                    if re.search(pattern, output):
                        findings.append(
                            Finding(
                                scan_id=scan_id,
                                scanner=self.name,
                                scan_type=self.scan_type,
                                severity=severity,
                                title=f"{pattern_name} found in git history",
                                description=f"A {pattern_name.lower()} was found in the git commit history. Even if removed from current files, it remains in git history and should be rotated.",
                                rule_id=f"secrets/git-history-{pattern_name.lower().replace(' ', '-')}",
                                remediation=f"Rotate the {pattern_name.lower()} immediately. Consider using git-filter-repo or BFG Repo-Cleaner to remove sensitive data from git history.",
                            )
                        )
        except Exception:
            pass
        return findings

    async def _scan_env_files(self, target: Path, scan_id: str) -> list[Finding]:
        findings = []
        env_patterns = ["*.env", "*.env.*", ".env.local", ".env.production", ".env.staging"]

        # rglob across multiple patterns is sync I/O — collect all matches
        # in a worker thread so a deep tree doesn't block the event loop.
        def _find_env_files() -> list[Path]:
            out: list[Path] = []
            for pattern in env_patterns:
                for env_file in target.rglob(pattern):
                    if any(skip in str(env_file) for skip in SKIP_DIRS):
                        continue
                    out.append(env_file)
            return out

        env_files = await asyncio.to_thread(_find_env_files)
        for env_file in env_files:
            try:
                content = env_file.read_text(errors="ignore")
                for line_num, line in enumerate(content.split("\n"), 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        key, _, value = line.partition("=")
                        value = value.strip().strip('"').strip("'")
                        if (
                            value
                            and len(value) > 5
                            and not self._is_likely_false_positive(line, str(env_file))
                        ):
                            key_lower = key.lower()
                            if any(
                                s in key_lower
                                for s in [
                                    "secret",
                                    "password",
                                    "key",
                                    "token",
                                    "auth",
                                    "credential",
                                ]
                            ):
                                findings.append(
                                    Finding(
                                        scan_id=scan_id,
                                        scanner=self.name,
                                        scan_type=self.scan_type,
                                        severity=Severity.HIGH,
                                        title=f"Secret in env file: {key.strip()}",
                                        description=f"Found secret value for '{key.strip()}' in {env_file.name}. Env files with secrets should not be committed to version control.",
                                        file_path=str(env_file),
                                        line_start=line_num,
                                        rule_id="secrets/env-file-secret",
                                        remediation="Add this file to .gitignore and use a secrets manager or CI/CD environment variables instead.",
                                    )
                                )
            except Exception:
                pass
        return findings
