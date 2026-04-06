from abc import ABC, abstractmethod

from ..models import Finding, ScanType


class BaseScanner(ABC):
    name: str
    scan_type: ScanType
    description: str = ""
    checks: list[str] = []

    @abstractmethod
    async def scan(self, target_path: str, scan_id: str, **kwargs) -> list[Finding]:
        """Run the scanner and return findings."""
        pass

    @abstractmethod
    async def is_available(self) -> bool:
        """Check if the scanner tool is installed."""
        pass

    async def check_or_warn(self) -> tuple[bool, str]:
        """Check availability and return status message."""
        available = await self.is_available()
        if available:
            return True, f"{self.name} is available"
        return False, f"{self.name} is not installed. Install with: {self.install_hint}"

    @property
    def install_hint(self) -> str:
        return f"See {self.name} documentation"
