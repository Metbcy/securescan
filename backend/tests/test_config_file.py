"""Tests for the typed ``.securescan.yml`` schema and walk-up loader."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from securescan.config_file import (
    CONFIG_FILENAMES,
    ConfigError,
    SecureScanConfig,
    load_config,
    parse_config,
)
from securescan.models import ScanType, Severity


def _make_isolated_root(tmp_path: Path) -> Path:
    """Create a directory with a `.git` marker so the walk stops here.

    Without this, tests that rely on "no config anywhere up the tree"
    are at the mercy of whatever lives above ``tmp_path`` on the host
    machine. The walker treats a ``.git`` directory as a hard boundary,
    so a faked one is the cleanest way to isolate the test.
    """

    (tmp_path / ".git").mkdir()
    return tmp_path


def test_default_config_when_no_file_present(tmp_path, monkeypatch):
    root = _make_isolated_root(tmp_path)
    monkeypatch.chdir(root)

    config, found = load_config()

    assert found is None
    assert config == SecureScanConfig()
    assert config.scan_types == []
    assert config.severity_overrides == {}
    assert config.ignored_rules == []
    assert config.semgrep_rules == []
    assert config.fail_on_severity is None
    assert config.ai is None


def test_load_config_finds_securescan_yml(tmp_path):
    root = _make_isolated_root(tmp_path)
    (root / ".securescan.yml").write_text("ignored_rules:\n  - SEMGREP-XYZ\n")

    config, found = load_config(root)

    assert found == root / ".securescan.yml"
    assert config.ignored_rules == ["SEMGREP-XYZ"]


def test_load_config_priority_order(tmp_path):
    root = _make_isolated_root(tmp_path)
    (root / ".securescan.yml").write_text("ignored_rules: [DOTTED]\n")
    (root / "securescan.yml").write_text("ignored_rules: [PLAIN]\n")

    config, found = load_config(root)

    assert found == root / ".securescan.yml"
    assert config.ignored_rules == ["DOTTED"]


def test_load_config_walks_up_from_subdir(tmp_path):
    root = _make_isolated_root(tmp_path)
    (root / ".securescan.yml").write_text("ignored_rules: [FROM-ROOT]\n")
    nested = root / "pkg" / "sub"
    nested.mkdir(parents=True)

    config, found = load_config(nested)

    assert found == root / ".securescan.yml"
    assert config.ignored_rules == ["FROM-ROOT"]


def test_load_config_stops_at_git_boundary(tmp_path):
    parent = tmp_path / "outer"
    parent.mkdir()
    (parent / ".securescan.yml").write_text("ignored_rules: [SHOULD-NOT-APPLY]\n")

    inner = parent / "inner"
    inner.mkdir()
    (inner / ".git").mkdir()  # boundary: walker must not escape past inner/
    sub = inner / "src"
    sub.mkdir()

    config, found = load_config(sub)

    assert found is None
    assert config == SecureScanConfig()


def test_parse_config_typed_severity_override():
    config = parse_config("severity_overrides:\n  SEMGREP-XYZ: high\n")

    assert config.severity_overrides == {"SEMGREP-XYZ": Severity.HIGH}
    assert config.severity_overrides["SEMGREP-XYZ"] is Severity.HIGH


def test_parse_config_invalid_severity_raises():
    with pytest.raises(ValidationError) as exc_info:
        parse_config("severity_overrides:\n  RULE: ultra-critical\n")

    rendered = str(exc_info.value)
    assert "ultra-critical" in rendered


def test_parse_config_unknown_top_level_key_raises():
    with pytest.raises(ValidationError) as exc_info:
        parse_config("unknown_key: foo\n")

    rendered = str(exc_info.value)
    assert "unknown_key" in rendered


def test_parse_config_extra_keys_in_severity_overrides_allowed():
    text = (
        "severity_overrides:\n"
        "  SEMGREP-A: low\n"
        "  CUSTOM_RULE_42: medium\n"
        "  some.dotted.id: critical\n"
    )

    config = parse_config(text)

    assert config.severity_overrides == {
        "SEMGREP-A": Severity.LOW,
        "CUSTOM_RULE_42": Severity.MEDIUM,
        "some.dotted.id": Severity.CRITICAL,
    }


def test_resolve_paths_makes_semgrep_rules_absolute(tmp_path):
    abs_path = tmp_path / "abs" / "rule.yml"
    abs_path.parent.mkdir(parents=True)
    abs_path.touch()

    config = parse_config(
        f"semgrep_rules:\n"
        f"  - rules/local.yml\n"
        f"  - {abs_path}\n"
    )

    resolved = config.resolve_paths(tmp_path)

    assert resolved.semgrep_rules[0] == (tmp_path / "rules" / "local.yml").resolve()
    assert resolved.semgrep_rules[1] == abs_path
    # Original config is untouched (model_copy semantics).
    assert config.semgrep_rules[0] == Path("rules/local.yml")


def test_malformed_yaml_raises_clear_error(tmp_path):
    bad = tmp_path / ".securescan.yml"
    bad.write_text("not: yaml: : :\n")

    with pytest.raises(ConfigError) as exc_info:
        parse_config(bad.read_text(), source_path=bad)

    assert exc_info.value.path == bad
    assert "malformed YAML" in exc_info.value.message
    assert str(bad) in str(exc_info.value)


def test_empty_yaml_file_returns_default_config(tmp_path):
    root = _make_isolated_root(tmp_path)
    (root / ".securescan.yml").write_text("")

    config, found = load_config(root)

    assert found == root / ".securescan.yml"
    assert config == SecureScanConfig()


def test_ai_explicit_false_in_config():
    config = parse_config("ai: false\n")

    assert config.ai is False
    assert config.ai is not None


def test_load_config_idempotent(tmp_path):
    root = _make_isolated_root(tmp_path)
    (root / ".securescan.yml").write_text(
        "scan_types: [code]\n"
        "ignored_rules: [SEMGREP-XYZ]\n"
        "fail_on_severity: high\n"
    )

    first, first_path = load_config(root)
    second, second_path = load_config(root)

    assert first == second
    assert first_path == second_path
    assert first.scan_types == [ScanType.CODE]
    assert first.fail_on_severity is Severity.HIGH


def test_config_filenames_priority_documented():
    # Sanity: the documented priority is the one the loader uses.
    assert CONFIG_FILENAMES == (
        ".securescan.yml",
        ".securescan.yaml",
        "securescan.yml",
    )
