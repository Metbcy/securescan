from .semgrep import SemgrepScanner
from .bandit import BanditScanner
from .trivy import TrivyScanner
from .checkov import CheckovScanner
from .baseline import BaselineScanner
from .secrets import SecretsScanner
from .safety import SafetyScanner
from .license_checker import LicenseScanner
from .dockerfile import DockerfileScanner
from .npm_audit import NpmAuditScanner
from .gitleaks import GitHygieneScanner
from .dast_builtin import BuiltinDastScanner
from .zap_scanner import ZapScanner
from .nmap_scanner import NmapScanner

ALL_SCANNERS = [
    SemgrepScanner(),
    BanditScanner(),
    TrivyScanner(),
    CheckovScanner(),
    BaselineScanner(),
    SecretsScanner(),
    SafetyScanner(),
    LicenseScanner(),
    DockerfileScanner(),
    NpmAuditScanner(),
    GitHygieneScanner(),
    BuiltinDastScanner(),
    ZapScanner(),
    NmapScanner(),
]


def get_scanners_for_types(scan_types):
    """Return scanner instances matching the requested scan types."""
    return [s for s in ALL_SCANNERS if s.scan_type in scan_types]