"""Tests for scanner availability and base functionality."""
import pytest
import asyncio
from src.scanners import ALL_SCANNERS, get_scanners_for_types
from src.scanners.base import BaseScanner
from src.scanners.baseline import BaselineScanner
from src.scanners.dockerfile import DockerfileScanner
from src.scanners.gitleaks import GitHygieneScanner
from src.models import ScanType


def test_all_scanners_registered():
    assert len(ALL_SCANNERS) == 11
    names = [s.name for s in ALL_SCANNERS]
    assert "semgrep" in names
    assert "bandit" in names
    assert "trivy" in names
    assert "checkov" in names
    assert "baseline" in names
    assert "safety" in names
    assert "licenses" in names
    assert "dockerfile" in names
    assert "npm-audit" in names
    assert "git-hygiene" in names


def test_get_scanners_for_code():
    scanners = get_scanners_for_types([ScanType.CODE])
    names = [s.name for s in scanners]
    assert "semgrep" in names
    assert "bandit" in names
    assert "git-hygiene" in names
    assert "trivy" not in names


def test_get_scanners_for_dependency():
    scanners = get_scanners_for_types([ScanType.DEPENDENCY])
    names = [s.name for s in scanners]
    assert "trivy" in names
    assert "safety" in names
    assert "licenses" in names
    assert "npm-audit" in names
    assert len(scanners) == 4


def test_get_scanners_for_iac():
    scanners = get_scanners_for_types([ScanType.IAC])
    names = [s.name for s in scanners]
    assert "checkov" in names
    assert "dockerfile" in names


def test_get_scanners_for_baseline():
    scanners = get_scanners_for_types([ScanType.BASELINE])
    names = [s.name for s in scanners]
    assert "baseline" in names
    assert len(scanners) == 1


def test_baseline_always_available():
    scanner = BaselineScanner()
    assert asyncio.run(scanner.is_available()) is True


def test_dockerfile_always_available():
    scanner = DockerfileScanner()
    assert asyncio.run(scanner.is_available()) is True


def test_git_hygiene_always_available():
    scanner = GitHygieneScanner()
    assert asyncio.run(scanner.is_available()) is True


def test_scanner_has_required_attributes():
    for scanner in ALL_SCANNERS:
        assert hasattr(scanner, "name")
        assert hasattr(scanner, "scan_type")
        assert hasattr(scanner, "scan")
        assert hasattr(scanner, "is_available")
