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
    description = "Checks system and OS configuration against security best practices inspired by CIS Benchmarks."
    checks = [
        "SSH hardening (root login, key-based auth)",
        "Firewall status & rules",
        "Password policies (age, complexity)",
        "Kernel security (ASLR, IP forwarding)",
        "File permissions on sensitive paths",
        "Sudoers & cron job security",
        "Listening ports & services",
        "User privilege audit",
    ]

    async def is_available(self) -> bool:
        return True  # No external tool needed

    @property
    def install_hint(self) -> str:
        return "Built-in scanner — always available"

    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_ssh_config(scan_id))
        findings.extend(self._check_file_permissions(scan_id))
        findings.extend(await self._check_firewall(scan_id))
        findings.extend(self._check_password_policy(scan_id))
        findings.extend(self._check_kernel_security(scan_id))
        findings.extend(self._check_env_secrets(scan_id))
        findings.extend(self._check_sudoers(scan_id))
        findings.extend(self._check_cron_security(scan_id))
        findings.extend(self._check_user_privileges(scan_id))
        findings.extend(await self._check_listening_ports(scan_id))
        findings.extend(await self._check_package_updates(scan_id))
        findings.extend(await self._check_world_writable_files(scan_id))
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

    def _check_sudoers(self, scan_id: str) -> list[Finding]:
        """Check /etc/sudoers for broad NOPASSWD usage."""
        findings: list[Finding] = []
        sudoers_path = "/etc/sudoers"
        try:
            with open(sudoers_path, "r") as f:
                content = f.read()
        except (FileNotFoundError, PermissionError):
            return findings

        for line_num, line in enumerate(content.split('\n'), 1):
            stripped = line.strip()
            if stripped.startswith('#') or not stripped:
                continue
            if 'NOPASSWD' in stripped:
                # Broad NOPASSWD: applies to ALL commands
                if 'ALL' in stripped.split('NOPASSWD')[-1]:
                    findings.append(Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.HIGH,
                        title="Broad NOPASSWD sudo access",
                        description=f"Line {line_num} in /etc/sudoers grants NOPASSWD access to ALL commands. This should be restricted to specific commands.",
                        file_path=sudoers_path,
                        line_start=line_num,
                        rule_id="BASELINE-SUDO-001",
                        remediation="Restrict NOPASSWD to specific commands instead of ALL. Example: user ALL=(ALL) NOPASSWD: /usr/bin/specific_command",
                    ))

        return findings

    def _check_cron_security(self, scan_id: str) -> list[Finding]:
        """Check crontabs for jobs running as root that execute world-writable scripts."""
        findings: list[Finding] = []
        cron_paths = ["/etc/crontab"]
        # Also check /var/spool/cron/ entries
        spool_dir = "/var/spool/cron/crontabs"
        if os.path.isdir(spool_dir):
            try:
                for entry in os.listdir(spool_dir):
                    cron_paths.append(os.path.join(spool_dir, entry))
            except PermissionError:
                pass

        for cron_path in cron_paths:
            try:
                with open(cron_path, "r") as f:
                    content = f.read()
            except (FileNotFoundError, PermissionError):
                continue

            for line_num, line in enumerate(content.split('\n'), 1):
                stripped = line.strip()
                if stripped.startswith('#') or not stripped:
                    continue
                # Check if root cron job references a script
                parts = stripped.split()
                if len(parts) >= 7 and parts[5] == 'root':
                    script_path = parts[6]
                    try:
                        st = os.stat(script_path)
                        if st.st_mode & stat.S_IWOTH:
                            findings.append(Finding(
                                scan_id=scan_id,
                                scanner=self.name,
                                scan_type=self.scan_type,
                                severity=Severity.CRITICAL,
                                title=f"Root cron job executes world-writable script",
                                description=f"Cron job in {cron_path} at line {line_num} runs as root and executes '{script_path}' which is world-writable. An attacker could modify this script for privilege escalation.",
                                file_path=cron_path,
                                line_start=line_num,
                                rule_id="BASELINE-CRON-001",
                                remediation=f"Remove world-writable permission: chmod o-w {script_path}",
                            ))
                    except (FileNotFoundError, PermissionError, OSError):
                        pass

        return findings

    def _check_user_privileges(self, scan_id: str) -> list[Finding]:
        """Check /etc/passwd for users with UID 0 (should only be root) and users with no password."""
        findings: list[Finding] = []

        # Check for multiple UID 0 users
        try:
            with open("/etc/passwd", "r") as f:
                for line_num, line in enumerate(f, 1):
                    parts = line.strip().split(':')
                    if len(parts) >= 4:
                        username, _, uid_str, _ = parts[0], parts[1], parts[2], parts[3]
                        try:
                            uid = int(uid_str)
                        except ValueError:
                            continue
                        if uid == 0 and username != "root":
                            findings.append(Finding(
                                scan_id=scan_id,
                                scanner=self.name,
                                scan_type=self.scan_type,
                                severity=Severity.CRITICAL,
                                title=f"Non-root user '{username}' has UID 0",
                                description=f"User '{username}' in /etc/passwd has UID 0 (root privileges). Only the root account should have UID 0.",
                                file_path="/etc/passwd",
                                line_start=line_num,
                                rule_id="BASELINE-USER-001",
                                remediation=f"Review and remove or change the UID of user '{username}'. Use: sudo usermod -u <new_uid> {username}",
                            ))
        except (FileNotFoundError, PermissionError):
            pass

        # Check for users with no password in /etc/shadow
        try:
            with open("/etc/shadow", "r") as f:
                for line_num, line in enumerate(f, 1):
                    parts = line.strip().split(':')
                    if len(parts) >= 2:
                        username = parts[0]
                        password_hash = parts[1]
                        # Empty password field or single '!' means no password set
                        if password_hash in ('', '!', '*'):
                            continue  # Locked or system accounts are fine
                        if password_hash == '!!':
                            # Password never set but account not locked
                            if username not in ('nobody', 'nfsnobody'):
                                findings.append(Finding(
                                    scan_id=scan_id,
                                    scanner=self.name,
                                    scan_type=self.scan_type,
                                    severity=Severity.MEDIUM,
                                    title=f"User '{username}' has no password set",
                                    description=f"User '{username}' in /etc/shadow has no password set (!!). This account should be locked or have a password.",
                                    file_path="/etc/shadow",
                                    line_start=line_num,
                                    rule_id="BASELINE-USER-002",
                                    remediation=f"Lock the account: sudo passwd -l {username}, or set a password: sudo passwd {username}",
                                ))
        except (FileNotFoundError, PermissionError):
            pass

        return findings

    async def _check_listening_ports(self, scan_id: str) -> list[Finding]:
        """Detect unexpected listening services using ss or netstat."""
        findings: list[Finding] = []

        output = ""
        for cmd in [["ss", "-tlnp"], ["netstat", "-tlnp"]]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode()
                break
            except (FileNotFoundError, asyncio.TimeoutError, Exception):
                continue

        if not output:
            return findings

        # Known safe ports
        known_ports = {'22', '80', '443', '8080', '8443', '53'}
        lines = output.strip().split('\n')[1:]  # Skip header
        for line in lines:
            parts = line.split()
            if len(parts) < 4:
                continue
            local_addr = parts[3] if 'ss' in output[:20] else parts[3]
            # Extract port from address like *:8000 or 0.0.0.0:8000 or :::8000
            port = local_addr.rsplit(':', 1)[-1] if ':' in local_addr else ""
            if port and port not in known_ports:
                # Check if listening on all interfaces (0.0.0.0 or *)
                addr_part = local_addr.rsplit(':', 1)[0] if ':' in local_addr else ""
                if addr_part in ('0.0.0.0', '*', '::'):
                    findings.append(Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.LOW,
                        title=f"Service listening on all interfaces port {port}",
                        description=f"A service is listening on {local_addr} (all interfaces). Review if this service should be exposed. Full line: {line.strip()}",
                        rule_id="BASELINE-PORT-001",
                        remediation=f"If this service should not be publicly accessible, bind it to 127.0.0.1 or restrict access with a firewall.",
                    ))

        return findings

    async def _check_package_updates(self, scan_id: str) -> list[Finding]:
        """Check if there are security updates available."""
        findings: list[Finding] = []

        # Try apt (Debian/Ubuntu)
        try:
            proc = await asyncio.create_subprocess_exec(
                "apt", "list", "--upgradable",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode()
            lines = [l for l in output.strip().split('\n') if l and 'Listing...' not in l]
            security_updates = [l for l in lines if 'security' in l.lower()]
            if security_updates:
                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.MEDIUM,
                    title=f"{len(security_updates)} security update(s) available",
                    description=f"There are {len(security_updates)} security updates available. Keeping systems patched is critical for security.",
                    rule_id="BASELINE-PKG-001",
                    remediation="Run: sudo apt update && sudo apt upgrade to install available security updates.",
                ))
            elif lines:
                findings.append(Finding(
                    scan_id=scan_id,
                    scanner=self.name,
                    scan_type=self.scan_type,
                    severity=Severity.LOW,
                    title=f"{len(lines)} package update(s) available",
                    description=f"There are {len(lines)} package updates available.",
                    rule_id="BASELINE-PKG-002",
                    remediation="Run: sudo apt update && sudo apt upgrade to install available updates.",
                ))
        except (FileNotFoundError, asyncio.TimeoutError, Exception):
            pass

        return findings

    async def _check_world_writable_files(self, scan_id: str) -> list[Finding]:
        """Check common directories for world-writable files."""
        findings: list[Finding] = []
        check_dirs = ["/etc", "/usr", "/var"]

        for check_dir in check_dirs:
            if not os.path.isdir(check_dir):
                continue
            try:
                proc = await asyncio.create_subprocess_exec(
                    "find", check_dir, "-maxdepth", "3", "-type", "f",
                    "-perm", "-o+w", "-not", "-path", "*/proc/*",
                    "-not", "-path", "*/sys/*",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
                writable_files = [f for f in stdout.decode().strip().split('\n') if f]

                if writable_files:
                    # Limit to first 10 files to avoid noise
                    sample = writable_files[:10]
                    remaining = len(writable_files) - len(sample)
                    desc = f"Found {len(writable_files)} world-writable file(s) under {check_dir}: {', '.join(sample)}"
                    if remaining > 0:
                        desc += f" (and {remaining} more)"
                    findings.append(Finding(
                        scan_id=scan_id,
                        scanner=self.name,
                        scan_type=self.scan_type,
                        severity=Severity.MEDIUM,
                        title=f"World-writable files in {check_dir}",
                        description=desc,
                        rule_id="BASELINE-WWRITE-001",
                        remediation=f"Review and fix permissions: find {check_dir} -type f -perm -o+w -exec chmod o-w {{}} \\;",
                    ))
            except (FileNotFoundError, asyncio.TimeoutError, Exception):
                continue

        return findings
