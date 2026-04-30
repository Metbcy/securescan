"""Tests for the ``securescan init`` wizard.

Covers stack detection (per-language and multi-language combos),
idempotency (refuses to overwrite without ``--force``), output
validity (the generated ``.securescan.yml`` round-trips through
the actual ``parse_config`` loader; the workflow YAML is parseable
PyYAML; the baseline JSON has ``version == 1``), and the CLI flag
surface (``--no-prompt`` / ``--no-workflow`` / ``--no-baseline``
/ ``--threshold`` / ``--scan-types``).

The wizard is deliberately filesystem-only (no network, no scanner
processes), so these tests don't need to monkey-patch anything --
``tmp_path`` is enough.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from securescan.cli import app
from securescan.config_file import parse_config

# --- helpers -----------------------------------------------------------


def _runner() -> CliRunner:
    return CliRunner()


def _read_config_yaml(project: Path) -> Path:
    p = project / ".securescan.yml"
    assert p.exists(), f"{p} should have been written"
    return p


def _scan_types_from_yaml(config_path: Path) -> list[str]:
    """Pull ``scan_types`` out of the generated config via the actual loader.

    Going through ``parse_config`` (rather than ``yaml.safe_load`` plus
    a manual key lookup) doubles as a validation check: if the wizard
    ever emits an unknown key, ``extra="forbid"`` will raise here and
    every test that touches the config will fail loud.
    """
    cfg = parse_config(config_path.read_text())
    return [t.value for t in cfg.scan_types]


# --- stack detection ---------------------------------------------------


def test_detects_python_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    assert types == ["code", "dependency", "baseline"]


def test_detects_python_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    assert types == ["code", "dependency", "baseline"]


def test_detects_python_pipfile(tmp_path):
    (tmp_path / "Pipfile").write_text("[packages]\nrequests = '*'\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    assert "code" in types and "dependency" in types and "baseline" in types


def test_detects_node_package_json(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "x", "version": "0.0.0"}\n')
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    assert types == ["code", "dependency", "baseline"]


def test_detects_rust_cargo_toml(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[package]\nname = "x"\n')
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    assert types == ["code", "dependency", "baseline"]


def test_detects_go_mod(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/x\n\ngo 1.22\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    assert types == ["code", "dependency", "baseline"]


def test_detects_container_dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.19\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    # Container detection means IaC scanning is on; baseline is always
    # present. There's no language marker so no `code`/`dependency`.
    assert "iac" in types
    assert "baseline" in types
    assert "code" not in types


def test_detects_iac_tf_files(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" { bucket = "x" }\n')
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    assert "iac" in types and "baseline" in types


def test_detects_iac_helm_chart(tmp_path):
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: x\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    assert "iac" in types


def test_detects_multi_language_combines(tmp_path):
    """Monorepo with both pyproject.toml *and* package.json is the
    common shape for a Python backend + Node frontend. The wizard
    should pick up both languages and merge their scan_types
    (de-duped, baseline appended)."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    (tmp_path / "package.json").write_text('{"name": "x"}\n')
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")

    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    # `code` and `dependency` only appear once even though two languages
    # contributed them; `iac` from Dockerfile; `baseline` always last.
    assert types == ["code", "dependency", "iac", "baseline"]


def test_unknown_stack_falls_back_to_baseline(tmp_path):
    (tmp_path / "README.md").write_text("# just a readme\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    types = _scan_types_from_yaml(_read_config_yaml(tmp_path))
    assert types == ["baseline"]


# --- idempotency -------------------------------------------------------


def test_refuses_overwrite_without_force(tmp_path):
    (tmp_path / ".securescan.yml").write_text("# pre-existing\nscan_types: [code]\n")

    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    # Non-zero exit + clear message, and the original file untouched.
    assert res.exit_code != 0
    assert "refusing to overwrite" in (res.output + (res.stderr or "")) or (
        "refusing to overwrite" in res.output
    )
    assert (tmp_path / ".securescan.yml").read_text().startswith("# pre-existing")


def test_refuses_overwrite_lists_offending_files(tmp_path):
    (tmp_path / ".securescan.yml").write_text("scan_types: [code]\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code != 0
    combined = res.output + (res.stderr or "")
    assert ".securescan.yml" in combined


def test_force_overwrites(tmp_path):
    (tmp_path / ".securescan.yml").write_text("# old\n")
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")

    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt", "--force"])
    assert res.exit_code == 0, res.output

    body = (tmp_path / ".securescan.yml").read_text()
    assert "# old" not in body
    assert "scan_types" in body


# --- output validity ---------------------------------------------------


def test_generated_yml_parses_as_securescan_config(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    cfg = parse_config((tmp_path / ".securescan.yml").read_text())
    assert [t.value for t in cfg.scan_types] == ["code", "dependency", "baseline"]
    assert cfg.fail_on_severity is not None
    assert cfg.fail_on_severity.value == "high"
    assert cfg.ignored_rules == []


def test_generated_workflow_yml_parses(tmp_path):
    (tmp_path / "go.mod").write_text("module x\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    wf_path = tmp_path / ".github" / "workflows" / "securescan.yml"
    assert wf_path.exists()
    parsed = yaml.safe_load(wf_path.read_text())
    assert parsed["name"] == "SecureScan"
    assert "jobs" in parsed and "scan" in parsed["jobs"]
    step = parsed["jobs"]["scan"]["steps"][1]
    assert step["uses"].startswith("Metbcy/securescan@")
    inputs = step["with"]
    assert inputs["scan-path"] == "."
    assert "code" in inputs["scan-types"] and "dependency" in inputs["scan-types"]
    assert inputs["fail-on-severity"] == "high"


def test_generated_baseline_parses(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output

    bl = json.loads((tmp_path / ".securescan" / "baseline.json").read_text())
    assert bl["version"] == 1
    assert bl["findings"] == []
    assert "scan_types" in bl
    assert bl["target_path"] == "."


# --- flags -------------------------------------------------------------


def test_no_prompt_skips_interactive(tmp_path):
    """With --no-prompt and no stdin, the wizard must not block waiting
    for input. CliRunner.invoke() with no ``input=`` would hang on the
    first ``typer.prompt`` if --no-prompt didn't short-circuit them."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")

    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt"])
    assert res.exit_code == 0, res.output
    assert (tmp_path / ".securescan.yml").exists()


def test_no_workflow_skips_workflow_file(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt", "--no-workflow"])
    assert res.exit_code == 0, res.output
    assert (tmp_path / ".securescan.yml").exists()
    assert not (tmp_path / ".github" / "workflows" / "securescan.yml").exists()
    # Baseline is still written.
    assert (tmp_path / ".securescan" / "baseline.json").exists()


def test_no_baseline_skips_baseline_file(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    res = _runner().invoke(app, ["init", str(tmp_path), "--no-prompt", "--no-baseline"])
    assert res.exit_code == 0, res.output
    assert (tmp_path / ".securescan.yml").exists()
    assert (tmp_path / ".github" / "workflows" / "securescan.yml").exists()
    assert not (tmp_path / ".securescan" / "baseline.json").exists()


def test_threshold_flag_overrides_default(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    res = _runner().invoke(
        app,
        ["init", str(tmp_path), "--no-prompt", "--threshold", "critical"],
    )
    assert res.exit_code == 0, res.output

    cfg = parse_config((tmp_path / ".securescan.yml").read_text())
    assert cfg.fail_on_severity is not None
    assert cfg.fail_on_severity.value == "critical"

    wf = yaml.safe_load((tmp_path / ".github" / "workflows" / "securescan.yml").read_text())
    assert wf["jobs"]["scan"]["steps"][1]["with"]["fail-on-severity"] == "critical"


def test_invalid_threshold_rejected(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    res = _runner().invoke(
        app,
        ["init", str(tmp_path), "--no-prompt", "--threshold", "bogus"],
    )
    assert res.exit_code != 0
    combined = res.output + (res.stderr or "")
    assert "threshold" in combined.lower()


def test_scan_types_flag_overrides_detection(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    res = _runner().invoke(
        app,
        [
            "init",
            str(tmp_path),
            "--no-prompt",
            "--scan-types",
            "code,iac",
        ],
    )
    assert res.exit_code == 0, res.output

    cfg = parse_config((tmp_path / ".securescan.yml").read_text())
    assert [t.value for t in cfg.scan_types] == ["code", "iac"]


def test_scan_types_flag_rejects_unknown(tmp_path):
    res = _runner().invoke(
        app,
        ["init", str(tmp_path), "--no-prompt", "--scan-types", "bogus"],
    )
    assert res.exit_code != 0
    combined = res.output + (res.stderr or "")
    assert "bogus" in combined or "unknown" in combined.lower()


def test_init_command_registered():
    """Verify ``init`` is on the root Typer app with the expected flags."""
    import click
    from typer.main import get_command

    cli = get_command(app)
    init_cmd = cli.commands["init"]  # type: ignore[union-attr]
    assert "Initialize SecureScan" in (init_cmd.help or "")

    opts: set[str] = set()
    for param in init_cmd.params:
        if isinstance(param, click.Option):
            opts.update(param.opts)
    for expected in (
        "--force",
        "--no-prompt",
        "--threshold",
        "--scan-types",
        "--no-workflow",
        "--no-baseline",
    ):
        assert expected in opts, f"missing flag: {expected}"


def test_interactive_prompt_accepts_defaults(tmp_path):
    """Without --no-prompt, the wizard reads stdin; sending blank
    lines accepts every default. This is the smoke test that the
    interactive path doesn't crash on the trivial happy case."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n")
    # Four prompts: project name, "use detected types?", threshold,
    # "write workflow?". Empty responses accept defaults; "y" /
    # "n" works for the confirms too.
    res = _runner().invoke(
        app,
        ["init", str(tmp_path)],
        input="\n\n\n\n",
    )
    assert res.exit_code == 0, res.output
    assert (tmp_path / ".securescan.yml").exists()
    assert (tmp_path / ".github" / "workflows" / "securescan.yml").exists()


def test_path_must_be_directory(tmp_path):
    file_path = tmp_path / "not-a-dir"
    file_path.write_text("hi\n")
    res = _runner().invoke(app, ["init", str(file_path), "--no-prompt"])
    assert res.exit_code != 0
