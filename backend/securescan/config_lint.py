"""Lint .securescan.yml: detect issues that the typed loader can't catch.

The pydantic schema rejects unknown top-level keys, bad severity values,
and bad type shapes. This linter goes further: it checks that
``semgrep_rules:`` paths actually exist on disk, warns about likely
misspelled rule IDs in ``severity_overrides:`` and ``ignored_rules:``,
and surfaces ignore-vs-override collisions that the typed schema can't
see (a rule that's both ignored and has a severity override is almost
certainly a config-author mistake -- the override never fires).

The split between schema and linter is deliberate. The schema rejects
bad *shapes* eagerly because a bad shape means we can't build a typed
config at all. The linter handles bad *semantics* -- things that are
valid YAML and a valid schema but wrong relative to how the config
will be used. Keeping the two layers separate means the loader stays
trivially fast for the hot path (every scan reads the config) while
the more expensive checks live behind the explicit ``securescan config
validate`` invocation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import ValidationError

from securescan.config_file import ConfigError, parse_config

Severity = Literal["error", "warning", "info"]

# Heuristic only -- registries vary across scanner versions, and matching
# against a hard-coded list would generate false positives the moment a
# new rule lands upstream. We just check for obvious typos: whitespace,
# control characters, empty strings.
_RULE_ID_VALID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-/]*$")


@dataclass(frozen=True)
class LintIssue:
    """A single finding from the config linter.

    ``location`` is a dotted path into the YAML document (e.g.
    ``severity_overrides.RULE-ID`` or ``semgrep_rules[2]``) so the user
    can jump straight to the offending key. ``None`` for issues that
    don't have a meaningful location (whole-file errors).
    """

    severity: Severity
    message: str
    location: str | None = None


@dataclass(frozen=True)
class LintReport:
    """Aggregate result of linting a config file.

    Issues are kept in insertion order (schema errors first, then
    semantic checks) so output is stable across runs.
    """

    issues: list[LintIssue] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        return any(issue.severity == "error" for issue in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(issue.severity == "warning" for issue in self.issues)

    def errors(self) -> list[LintIssue]:
        return [i for i in self.issues if i.severity == "error"]

    def warnings(self) -> list[LintIssue]:
        return [i for i in self.issues if i.severity == "warning"]

    def info(self) -> list[LintIssue]:
        return [i for i in self.issues if i.severity == "info"]


def _format_location(loc: tuple[object, ...]) -> str:
    """Render a pydantic ``loc`` tuple as a dotted path.

    Integers become ``[i]`` so ``("semgrep_rules", 2)`` reads as
    ``semgrep_rules[2]`` -- matches what users see in IDEs and what
    the type-checker would show.
    """

    if not loc:
        return ""
    parts: list[str] = []
    for item in loc:
        if isinstance(item, int):
            if parts:
                parts[-1] = f"{parts[-1]}[{item}]"
            else:
                parts.append(f"[{item}]")
        else:
            parts.append(str(item))
    return ".".join(parts)


def _looks_like_valid_rule_id(rule_id: str) -> bool:
    """Heuristic: does ``rule_id`` look like a real rule identifier?

    Catches typos (whitespace, empty string, control characters)
    without false-positives on legit dotted-name styles like
    ``python.lang.security.audit.x`` or short codes like ``B305``.
    """

    if not rule_id or rule_id != rule_id.strip():
        return False
    return bool(_RULE_ID_VALID_RE.fullmatch(rule_id))


def lint_config(config_path: Path) -> LintReport:
    """Run the linter on ``config_path``.

    Does not raise on lint findings; only on programmer errors. File
    IO and YAML parse failures become a single ``error`` issue so the
    CLI surface is uniform: one code path, one shape of report.
    """

    issues: list[LintIssue] = []

    if not config_path.exists():
        issues.append(
            LintIssue(
                severity="error",
                message=f"config file not found: {config_path}",
            )
        )
        return LintReport(issues=issues)

    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        issues.append(
            LintIssue(
                severity="error",
                message=f"could not read config file: {exc}",
            )
        )
        return LintReport(issues=issues)

    # Parse raw YAML once for the empty-file check; ``parse_config``
    # collapses ``None`` -> ``{}`` so by the time pydantic sees the
    # data we'd already have lost the "this file was blank" signal.
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        issues.append(
            LintIssue(
                severity="error",
                message=f"malformed YAML: {exc}",
            )
        )
        return LintReport(issues=issues)

    if raw is None or raw == {}:
        issues.append(
            LintIssue(
                severity="info",
                message=(
                    "config file is empty; no overrides will apply (this is a valid starter state)"
                ),
            )
        )
        # Fall through: an empty file is also a valid config, so we
        # still want to run the rest of the (no-op) checks. They'll
        # add nothing, but the code path stays uniform.

    try:
        config = parse_config(text, source_path=config_path)
    except ConfigError as exc:
        issues.append(
            LintIssue(
                severity="error",
                message=str(exc.message),
            )
        )
        return LintReport(issues=issues)
    except ValidationError as exc:
        for err in exc.errors():
            loc = _format_location(err.get("loc", ()))
            msg = err.get("msg", "validation error")
            issues.append(
                LintIssue(
                    severity="error",
                    message=msg,
                    location=loc or None,
                )
            )
        return LintReport(issues=issues)

    base_dir = config_path.parent
    resolved = config.resolve_paths(base_dir)
    for index, path in enumerate(resolved.semgrep_rules):
        if not path.exists():
            issues.append(
                LintIssue(
                    severity="error",
                    message=f"semgrep_rules path does not exist: {path}",
                    location=f"semgrep_rules[{index}]",
                )
            )

    for rule_id in config.severity_overrides.keys():
        if not _looks_like_valid_rule_id(rule_id):
            issues.append(
                LintIssue(
                    severity="warning",
                    message=(
                        f"rule ID {rule_id!r} does not look like a valid "
                        "identifier (expected non-empty, no whitespace, "
                        "alphanumeric / dot / dash / slash / underscore)"
                    ),
                    location=f"severity_overrides.{rule_id}",
                )
            )

    for index, rule_id in enumerate(config.ignored_rules):
        if not _looks_like_valid_rule_id(rule_id):
            issues.append(
                LintIssue(
                    severity="warning",
                    message=(
                        f"rule ID {rule_id!r} does not look like a valid "
                        "identifier (expected non-empty, no whitespace, "
                        "alphanumeric / dot / dash / slash / underscore)"
                    ),
                    location=f"ignored_rules[{index}]",
                )
            )

    ignored_set = set(config.ignored_rules)
    for rule_id in config.severity_overrides.keys():
        if rule_id in ignored_set:
            issues.append(
                LintIssue(
                    severity="warning",
                    message=(
                        f"rule {rule_id!r} appears in both ignored_rules "
                        "and severity_overrides; the override will never "
                        "fire because the rule is suppressed first"
                    ),
                    location=f"severity_overrides.{rule_id}",
                )
            )

    return LintReport(issues=issues)
