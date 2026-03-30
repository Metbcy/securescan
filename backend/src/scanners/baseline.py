"""Security baseline configuration scanner."""
import asyncio
import os
import re
import stat

from .base import BaseScanner
from ..models import Finding, ScanType, Severity


class BaselineScanner(BaseScanner):
    name = "baseline"
    scan_type = ScanType.BASELINE

    async def is_available(self) -> bool:
        return True  # No external tool needed

    @property
    def install_hint(self) -> str:
        return "Built-in scanner — always available"

    async def scan(self, target_path: str, scan_id: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_ssh_config(scan_id))
        findings.extend(self._check_file_permissions(scan_id))
        findings.extend(await self._check_firewall(scan_id))
        findings.extend(self._check_password_policy(scan_id))
        findings.extend(self._check_kernel_security(scan_id))
        findings.extend(self._check_env_secrets(scan_id))
        return findings

    def _check_ssh_config(self, scan_id: str) -> list[Finding]:
        """Check SSH server configuration."""
        findings: list[Finding] = []
        config_path = "/etc/ssh/sshd_config"
        try:
            with open(config_path, "r") as f:
                content = f.read()
        except (FileNotFoundError, PermissionError):
            return findings

        # Check PermitRootLogin
        match = re.search(r"^\s*PermitRootLogin\s+(\S+)", content, re.MULTILINE)
        if match and match.group(1).lower() == "yes":
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type,
                severity=Severity.HIGH,
                title="SSH root login enabled",
                description="PermitRootLogin is set to 'yes' in sshd_config. Root login via SSH should be disabled.",
                file_path=config_path,
                rule_id="BASELINE-SSH-001",
                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and run: sudo systemctl restart sshd",
            ))

        # Check PasswordAuthentication
        match = re.search(r"^\s*PasswordAuthentication\s+(\S+)", content, re.MULTILINE)
        if match and match.group(1).lower() != "no":
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type,
                severity=Severity.MEDIUM,
                title="SSH password authentication enabled",
                description="PasswordAuthentication is not set to 'no'. Key-based authentication is more secure.",
                file_path=config_path,
                rule_id="BASELINE-SSH-002",
                remediation="Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and run: sudo systemctl restart sshd",
            ))

        # Check Protocol
        match = re.search(r"^\s*Protocol\s+(\S+)", content, re.MULTILINE)
        if match and match.group(1) != "2":
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type,
                severity=Severity.HIGH,
                title="SSH Protocol version 1 allowed",
                description=f"SSH Protocol is set to '{match.group(1)}'. Only Protocol 2 should be used.",
                file_path=config_path,
                rule_id="BASELINE-SSH-003",
                remediation="Set 'Protocol 2' in /etc/ssh/sshd_config and run: sudo systemctl restart sshd",
            ))

        return findings

    def _check_file_permissions(self, scan_id: str) -> list[Finding]:
        """Check sensitive file permissions."""
        findings: list[Finding] = []
        home = os.path.expanduser("~")

        checks = [
            ("/etc/passwd", 0o644, "644", Severity.HIGH),
            ("/etc/shadow", 0o640, "640", Severity.CRITICAL),
            (os.path.join(home, ".ssh"), 0o700, "700", Severity.HIGH),
            (os.path.join(home, ".ssh", "authorized_keys"), 0o600, "600", Severity.HIGH),
        ]

        for path, max_perm, expected_str, severity in checks:
            try:
                st = os.stat(path)
                actual_perm = stat.S_IMODE(st.st_mode)
                # Check if permissions are MORE permissive than allowed
                if actual_perm & ~max_perm:
                    actual_str = oct(actual_perm)[2:]
                    findings.append(Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=severity,
                        title=f"Insecure permissions on {path}",
                        description=f"Permissions are {actual_str} but should be {expected_str} or more restrictive.",
                        file_path=path,
                        rule_id="BASELINE-PERM-001",
                        remediation=f"Run: sudo chmod {expected_str} {path}",
                    ))
            except (FileNotFoundError, PermissionError):
                continue

        return findings

    async def _check_firewall(self, scan_id: str) -> list[Finding]:
        """Check if a firewall is active."""
        findings: list[Finding] = []
        firewall_active = False

        # Try ufw
        try:
            proc = await asyncio.create_subprocess_exec(
                "ufw", "status",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode().lower()
            if "status: active" in output:
                firewall_active = True
        except (FileNotFoundError, asyncio.TimeoutError, Exception):
            pass

        # Try iptables if ufw not found
        if not firewall_active:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "iptables", "-L", "-n",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode()
                # If iptables has more than default empty chains, firewall is configured
                lines = [l for l in output.strip().split("\n") if l and not l.startswith("Chain") and not l.startswith("target")]
                if lines:
                    firewall_active = True
            except (FileNotFoundError, asyncio.TimeoutError, Exception):
                pass

        if not firewall_active:
            findings.append(Finding(
                scan_id=scan_id,
                scanner=self.name,
                scan_type=self.scan_type,
                severity=Severity.MEDIUM,
                title="No active firewall detected",
                description="Neither ufw nor iptables appear to have an active firewall configuration.",
                rule_id="BASELINE-FW-001",
                remediation="Enable a firewall: sudo ufw enable (Ubuntu/Debian) or configure iptables rules.",
            ))

        return findings

    def _check_password_policy(self, scan_id: str) -> list[Finding]:
        """Check password policy in /etc/login.defs."""
        findings: list[Finding] = []
        config_path = "/etc/login.defs"
        try:
            with open(config_path, "r") as f:
                content = f.read()
        except (FileNotFoundError, PermissionError):
            return findings

        # PASS_MAX_DAYS
        match = re.search(r"^\s*PASS_MAX_DAYS\s+(\d+)", content, re.MULTILINE)
        if match:
            val = int(match.group(1))
            if val > 90:
                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.MEDIUM,
                    title="Password max age too long",
                    description=f"PASS_MAX_DAYS is {val} (should be <= 90). Passwords should expire regularly.",
                    file_path=config_path,
                    rule_id="BASELINE-PWD-001",
                    remediation="Set 'PASS_MAX_DAYS 90' in /etc/login.defs",
                ))

        # PASS_MIN_DAYS
        match = re.search(r"^\s*PASS_MIN_DAYS\s+(\d+)", content, re.MULTILINE)
        if match:
            val = int(match.group(1))
            if val < 1:
                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.LOW,
                    title="Password min age too short",
                    description=f"PASS_MIN_DAYS is {val} (should be >= 1). Users can change passwords too frequently.",
                    file_path=config_path,
                    rule_id="BASELINE-PWD-002",
                    remediation="Set 'PASS_MIN_DAYS 1' in /etc/login.defs",
                ))

        # PASS_MIN_LEN
        match = re.search(r"^\s*PASS_MIN_LEN\s+(\d+)", content, re.MULTILINE)
        if match:
            val = int(match.group(1))
            if val < 8:
                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.MEDIUM,
                    title="Minimum password length too short",
                    description=f"PASS_MIN_LEN is {val} (should be >= 8).",
                    file_path=config_path,
                    rule_id="BASELINE-PWD-003",
                    remediation="Set 'PASS_MIN_LEN 8' in /etc/login.defs",
                ))

        return findings

    def _check_kernel_security(self, scan_id: str) -> list[Finding]:
        """Check kernel security parameters via /proc/sys/."""
        findings: list[Finding] = []

        checks = [
            ("/proc/sys/net/ipv4/ip_forward", "0", Severity.MEDIUM,
             "IP forwarding enabled",
             "IP forwarding is enabled. Unless this is a router, it should be disabled.",
             "BASELINE-KERN-001",
             "Run: sudo sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward=0' | sudo tee -a /etc/sysctl.conf"),
            ("/proc/sys/net/ipv4/conf/all/accept_redirects", "0", Severity.MEDIUM,
             "ICMP redirects accepted",
             "System accepts ICMP redirects which can be used for MITM attacks.",
             "BASELINE-KERN-002",
             "Run: sudo sysctl -w net.ipv4.conf.all.accept_redirects=0"),
            ("/proc/sys/kernel/randomize_va_space", "2", Severity.MEDIUM,
             "ASLR not fully enabled",
             "Address Space Layout Randomization (ASLR) is not set to full randomization (2).",
             "BASELINE-KERN-003",
             "Run: sudo sysctl -w kernel.randomize_va_space=2"),
        ]

        for path, expected, severity, title, desc, rule_id, fix in checks:
            try:
                with open(path, "r") as f:
                    actual = f.read().strip()
                if actual != expected:
                    findings.append(Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=severity,
                        title=title,
                        description=f"{desc} Current value: {actual}, expected: {expected}.",
                        file_path=path,
                        rule_id=rule_id,
                        remediation=fix,
                    ))
            except (FileNotFoundError, PermissionError):
                continue

        return findings

    def _check_env_secrets(self, scan_id: str) -> list[Finding]:
        """Check for sensitive data in environment variables."""
        findings: list[Finding] = []
        secret_patterns = ["API_KEY", "SECRET", "PASSWORD", "TOKEN", "PRIVATE_KEY", "CREDENTIALS"]

        for key, value in os.environ.items():
            if not value or len(value) < 4:
                continue
            key_upper = key.upper()
            for pattern in secret_patterns:
                if pattern in key_upper:
                    # Mask the value for the finding description
                    masked = value[:2] + "*" * min(len(value) - 4, 20) + value[-2:] if len(value) > 4 else "****"
                    findings.append(Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.LOW,
                        title=f"Potential secret in environment: {key}",
                        description=f"Environment variable '{key}' matches secret pattern '{pattern}' and contains a value ({masked}).",
                        rule_id="BASELINE-ENV-001",
                        remediation="Review if this environment variable contains sensitive data. Use a secrets manager instead of env vars for production.",
                    ))
                    break  # Only one finding per env var

        return findings
