"""Tests for the SBOM generator."""

import json
import pytest
from pathlib import Path

from securescan.sbom import SBOMGenerator
from securescan.models import SBOMDocument


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project with package.json and requirements.txt."""
    package_json = {
        "name": "my-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "~4.17.21",
        },
        "devDependencies": {
            "jest": ">=29.0.0",
        },
        "peerDependencies": {
            "react": "18.0.0",
        },
    }
    (tmp_path / "package.json").write_text(json.dumps(package_json))

    requirements = """\
# This is a comment
-r base.txt
requests==2.31.0
flask>=2.3.0
numpy==1.24.3  # inline comment
"""
    (tmp_path / "requirements.txt").write_text(requirements)
    return tmp_path


# ------------------------------------------------------------------
# Parser unit tests
# ------------------------------------------------------------------

def test_parse_package_json(tmp_project: Path):
    gen = SBOMGenerator(str(tmp_project))
    components = gen._parse_package_json(tmp_project / "package.json", "sbom-test-id")

    names = {c.name for c in components}
    assert "express" in names
    assert "lodash" in names
    assert "jest" in names
    assert "react" in names

    # Semver operators should be stripped
    express = next(c for c in components if c.name == "express")
    assert express.version == "4.18.2"
    assert express.purl == "pkg:npm/express@4.18.2"

    lodash = next(c for c in components if c.name == "lodash")
    assert lodash.version == "4.17.21"

    jest = next(c for c in components if c.name == "jest")
    assert jest.version == "29.0.0"

    react = next(c for c in components if c.name == "react")
    assert react.version == "18.0.0"


def test_parse_requirements_txt(tmp_project: Path):
    gen = SBOMGenerator(str(tmp_project))
    components = gen._parse_requirements_txt(tmp_project / "requirements.txt", "sbom-test-id")

    names = {c.name for c in components}
    # Comments and flags should be skipped
    assert "requests" in names
    assert "flask" in names
    assert "numpy" in names
    # The -r flag line should not produce a component
    assert "base" not in names

    requests_comp = next(c for c in components if c.name == "requests")
    assert requests_comp.version == "2.31.0"
    assert requests_comp.purl == "pkg:pypi/requests@2.31.0"

    numpy_comp = next(c for c in components if c.name == "numpy")
    assert numpy_comp.version == "1.24.3"


def test_parse_requirements_txt_skips_comments(tmp_project: Path):
    """Comments and flag lines must not appear as components."""
    gen = SBOMGenerator(str(tmp_project))
    components = gen._parse_requirements_txt(tmp_project / "requirements.txt", "sbom-test-id")
    purls = [c.purl for c in components]
    # None of the purls should contain "This" (from the comment line)
    assert not any("This" in (p or "") for p in purls)
    assert len(components) == 3  # requests, flask, numpy


# ------------------------------------------------------------------
# generate() integration test
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_generate_returns_sbom_document(tmp_project: Path, monkeypatch):
    """generate() should return an SBOMDocument with components from both manifests."""
    # Ensure Syft is not used in this test
    monkeypatch.setattr("shutil.which", lambda _: None)

    gen = SBOMGenerator(str(tmp_project))
    doc = await gen.generate()

    assert isinstance(doc, SBOMDocument)
    assert doc.target_path == str(tmp_project)
    assert len(doc.components) > 0

    # Should have npm and pypi components
    purls = [c.purl or "" for c in doc.components]
    npm_purls = [p for p in purls if p.startswith("pkg:npm/")]
    pypi_purls = [p for p in purls if p.startswith("pkg:pypi/")]

    assert len(npm_purls) >= 4, f"Expected at least 4 npm purls, got: {npm_purls}"
    assert len(pypi_purls) >= 3, f"Expected at least 3 pypi purls, got: {pypi_purls}"


@pytest.mark.asyncio
async def test_generate_deduplicates(tmp_path: Path, monkeypatch):
    """Duplicate purls across manifest files should be deduplicated."""
    monkeypatch.setattr("shutil.which", lambda _: None)

    # Create two requirements.txt at different levels — same dep
    reqs = "requests==2.31.0\n"
    (tmp_path / "requirements.txt").write_text(reqs)
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "requirements.txt").write_text(reqs)

    gen = SBOMGenerator(str(tmp_path))
    doc = await gen.generate()

    request_comps = [c for c in doc.components if c.name == "requests"]
    assert len(request_comps) == 1, "Duplicate purl should be deduplicated"


# ------------------------------------------------------------------
# Export tests
# ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_export_cyclonedx(tmp_project: Path, monkeypatch):
    """export_cyclonedx() must produce valid CycloneDX 1.5 JSON."""
    monkeypatch.setattr("shutil.which", lambda _: None)

    gen = SBOMGenerator(str(tmp_project))
    doc = await gen.generate()
    exported = gen.export_cyclonedx(doc)

    assert exported["bomFormat"] == "CycloneDX"
    assert exported["specVersion"] == "1.5"
    assert "components" in exported
    assert isinstance(exported["components"], list)
    assert len(exported["components"]) == len(doc.components)

    # Each component has required fields
    for comp in exported["components"]:
        assert "name" in comp
        assert "version" in comp
        assert "type" in comp


@pytest.mark.asyncio
async def test_export_spdx(tmp_project: Path, monkeypatch):
    """export_spdx() must produce valid SPDX 2.3 JSON."""
    monkeypatch.setattr("shutil.which", lambda _: None)

    gen = SBOMGenerator(str(tmp_project))
    doc = await gen.generate()
    exported = gen.export_spdx(doc)

    assert exported["spdxVersion"] == "SPDX-2.3"
    assert "packages" in exported
    assert isinstance(exported["packages"], list)
    assert len(exported["packages"]) == len(doc.components)
    assert "creationInfo" in exported

    # Each package has required SPDX fields
    for pkg in exported["packages"]:
        assert "SPDXID" in pkg
        assert "name" in pkg
        assert "versionInfo" in pkg
        assert "licenseConcluded" in pkg
        assert "licenseDeclared" in pkg


# ------------------------------------------------------------------
# Additional parser tests
# ------------------------------------------------------------------

def test_parse_go_mod(tmp_path: Path):
    go_mod = """\
module example.com/myapp

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4
)

require github.com/rs/zerolog v1.30.0
"""
    (tmp_path / "go.mod").write_text(go_mod)
    gen = SBOMGenerator(str(tmp_path))
    components = gen._parse_go_mod(tmp_path / "go.mod", "sbom-id")

    names = {c.name for c in components}
    assert "github.com/gin-gonic/gin" in names
    assert "github.com/stretchr/testify" in names
    assert "github.com/rs/zerolog" in names

    gin = next(c for c in components if c.name == "github.com/gin-gonic/gin")
    assert gin.version == "v1.9.1"
    assert gin.purl == "pkg:golang/github.com/gin-gonic/gin@v1.9.1"


def test_parse_cargo_toml(tmp_path: Path):
    cargo_toml = """\
[package]
name = "my-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
tokio = {version = "1.28", features = ["full"]}

[dev-dependencies]
mockall = "0.11"
"""
    (tmp_path / "Cargo.toml").write_text(cargo_toml)
    gen = SBOMGenerator(str(tmp_path))
    components = gen._parse_cargo_toml(tmp_path / "Cargo.toml", "sbom-id")

    names = {c.name for c in components}
    assert "serde" in names
    assert "tokio" in names
    assert "mockall" in names

    serde = next(c for c in components if c.name == "serde")
    assert serde.version == "1.0"
    assert serde.purl == "pkg:cargo/serde@1.0"

    tokio = next(c for c in components if c.name == "tokio")
    assert tokio.version == "1.28"


def test_parse_gemfile_lock(tmp_path: Path):
    gemfile_lock = """\
GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.5)
      actioncable (= 7.0.5)
    rake (13.0.6)

PLATFORMS
  ruby
"""
    (tmp_path / "Gemfile.lock").write_text(gemfile_lock)
    gen = SBOMGenerator(str(tmp_path))
    components = gen._parse_gemfile_lock(tmp_path / "Gemfile.lock", "sbom-id")

    names = {c.name for c in components}
    assert "rails" in names
    assert "rake" in names

    rails = next(c for c in components if c.name == "rails")
    assert rails.version == "7.0.5"
    assert rails.purl == "pkg:gem/rails@7.0.5"
