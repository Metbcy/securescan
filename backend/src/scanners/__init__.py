from .semgrep import SemgrepScanner
from .bandit import BanditScanner
from .trivy import TrivyScanner
from .checkov import CheckovScanner
from .baseline import BaselineScanner

ALL_SCANNERS = [
    SemgrepScanner(),
    BanditScanner(),
    TrivyScanner(),
    CheckovScanner(),
    BaselineScanner(),
]


def get_scanners_for_types(scan_types):
    """Return scanner instances matching the requested scan types."""
    return [s for s in ALL_SCANNERS if s.scan_type in scan_types]