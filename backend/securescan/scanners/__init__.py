from .bandit import BanditScanner
from .baseline import BaselineScanner
from .checkov import CheckovScanner
from .dast_builtin import BuiltinDastScanner
from .dockerfile import DockerfileScanner
from .gitleaks import GitHygieneScanner
from .license_checker import LicenseScanner
from .nmap_scanner import NmapScanner
from .npm_audit import NpmAuditScanner
from .safety import SafetyScanner
from .secrets import SecretsScanner
from .semgrep import SemgrepScanner
from .trivy import TrivyScanner
from .zap_scanner import ZapScanner

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
