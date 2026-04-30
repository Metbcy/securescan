"""Typed schema and walk-up loader for ``.securescan.yml``.

This module is the foundation for the v0.3.0 trust-and-signal-quality
features: severity overrides, globally-ignored rules, custom Semgrep
rule packs, fail-on-severity thresholds, and the AI toggle all flow
through :class:`SecureScanConfig`.

Design choices worth flagging
-----------------------------
* **PyYAML over ruamel.yaml.** We never round-trip user files, so the
  smaller, more ubiquitous library is the better dependency.
* **``extra="forbid"`` at the top level.** A typo'd key (``ingored_rules``)
  silently no-op'ing is a foot-gun the v0.3.0 plan explicitly calls out.
  We fail loudly instead.
* **Pure loader, separate path resolution.** :func:`load_config` returns
  the un-resolved config plus the discovered path. Callers invoke
  :meth:`SecureScanConfig.resolve_paths` when they actually need
  absolute paths. This keeps the loader trivially testable and lets
  consumers decide whether portability matters for their use case.
* **Walk-up sanity bound (25 levels).** Protects against pathological
  symlink loops; in practice nobody nests projects 25 deep.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict

from securescan.models import ScanType, Severity

CONFIG_FILENAMES: tuple[str, ...] = (
    ".securescan.yml",
    ".securescan.yaml",
    "securescan.yml",
)

_MAX_WALK_UP_LEVELS = 25


class ConfigError(Exception):
    """Raised when a ``.securescan.yml`` file is present but unreadable.

    Carries the offending ``path`` so the CLI can render a helpful
    message pointing at the exact file.
    """

    def __init__(self, message: str, path: Path) -> None:
        super().__init__(message)
        self.path = path
        self.message = message

    def __str__(self) -> str:
        return f"{self.message} (in {self.path})"


class SecureScanConfig(BaseModel):
    """Typed schema for ``.securescan.yml``.

    Unknown top-level keys raise a ``ValidationError`` (see the module
    docstring for rationale).
    """

    model_config = ConfigDict(extra="forbid")

    scan_types: list[ScanType] = []
    severity_overrides: dict[str, Severity] = {}
    ignored_rules: list[str] = []
    semgrep_rules: list[Path] = []
    fail_on_severity: Severity | None = None
    ai: bool | None = None

    def resolve_paths(self, base: Path) -> SecureScanConfig:
        """Return a copy with ``semgrep_rules`` resolved against ``base``.

        Absolute paths are kept verbatim. Relative paths are joined onto
        ``base`` (typically the directory containing the config file) so
        checked-in rule packs are portable across machines.
        """

        resolved: list[Path] = []
        for raw in self.semgrep_rules:
            p = Path(raw)
            resolved.append(p if p.is_absolute() else (base / p).resolve())
        return self.model_copy(update={"semgrep_rules": resolved})


def parse_config(text: str, *, source_path: Path | None = None) -> SecureScanConfig:
    """Parse YAML ``text`` into a :class:`SecureScanConfig`.

    An empty document (or a document of only whitespace / comments) is
    treated as ``{}`` so an empty marker file is a valid "all defaults"
    declaration.

    Raises :class:`ConfigError` for malformed YAML (so callers can
    surface the originating file path); pydantic
    :class:`~pydantic.ValidationError` propagates unchanged for schema
    violations because callers benefit from pydantic's structured error
    locations (``loc=('severity_overrides', 'RULE')``) when surfacing
    typo'd keys / unknown enum values to the user.
    """

    path = source_path if source_path is not None else Path("<string>")

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"malformed YAML: {exc}", path) from exc

    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ConfigError(
            f"top-level YAML must be a mapping, got {type(data).__name__}",
            path,
        )

    return SecureScanConfig.model_validate(data)


def _candidate_paths(directory: Path) -> list[Path]:
    return [directory / name for name in CONFIG_FILENAMES]


def _find_config_file(start_dir: Path) -> Path | None:
    """Walk up from ``start_dir`` looking for any known config filename.

    Stops at the filesystem root, when a ``.git`` directory is found in
    the current candidate directory, or after :data:`_MAX_WALK_UP_LEVELS`
    iterations (sanity bound against pathological symlink loops).

    Within a single directory the priority order is
    :data:`CONFIG_FILENAMES`: ``.securescan.yml`` beats ``.securescan.yaml``
    beats ``securescan.yml``.
    """

    current = start_dir.resolve()

    for _ in range(_MAX_WALK_UP_LEVELS):
        for candidate in _candidate_paths(current):
            if candidate.is_file():
                return candidate

        if (current / ".git").exists():
            return None

        parent = current.parent
        if parent == current:
            return None
        current = parent

    return None


def load_config(
    start_dir: Path | None = None,
) -> tuple[SecureScanConfig, Path | None]:
    """Walk up from ``start_dir`` (default :func:`Path.cwd`) and load config.

    Returns ``(config, found_path)``. When no file is found, returns the
    default :class:`SecureScanConfig` and ``None``.

    The returned config is **not** path-resolved; callers that need
    absolute ``semgrep_rules`` paths should call
    :meth:`SecureScanConfig.resolve_paths` with ``found_path.parent``.
    """

    base = (start_dir if start_dir is not None else Path.cwd()).resolve()
    found = _find_config_file(base)

    if found is None:
        return SecureScanConfig(), None

    try:
        text = found.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"could not read config file: {exc}", found) from exc

    return parse_config(text, source_path=found), found
