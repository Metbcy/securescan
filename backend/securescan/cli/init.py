"""``securescan init`` -- one-shot project bootstrap wizard.

Adopting SecureScan on an existing repo without ``init`` means hand-
authoring three files (``.securescan.yml``,
``.github/workflows/securescan.yml``, ``.securescan/baseline.json``).
Three steps, three artifacts, three opportunities to give up.

This wizard collapses that to one command:

* Detects the user's stack (Python, Node, Rust, Go, Dockerfile, Terraform, ...)
  by globbing well-known marker files.
* Picks a sensible default set of :class:`ScanType` values from what
  it found (``baseline`` is always included so re-running stays cheap).
* Asks the user a couple of confirmation questions (skippable with
  ``--no-prompt`` for CI / scripted setup).
* Writes all three files atomically. Refuses to overwrite existing
  files unless ``--force`` is passed -- ``init`` is meant to be safe
  to re-run on a project that's already partially configured.

The generated ``.securescan.yml`` is written against the actual
:class:`SecureScanConfig` schema (``scan_types``, ``fail_on_severity``,
``ignored_rules``) -- ``extra="forbid"`` on the loader means we can't
sneak made-up keys in. The ``project name`` the user picks lives in a
YAML comment header instead of as a config key.

The generated ``.securescan/baseline.json`` matches the envelope shape
:func:`securescan.baseline_writer.serialize_baseline` produces (an empty
``findings`` list is the "no suppressions yet" state). The first scan
will surface every finding in the repo; once the user has triaged
those, ``securescan baseline .`` regenerates the file with real
fingerprints.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

from ..baseline_writer import BASELINE_VERSION
from ..models import ScanType
from . import _shared

# --- Stack detection ---------------------------------------------------

# Order matters only for the "Detected stack:" message: we render the
# first detected language first. Each entry maps a human label to the
# marker filenames (top-level globs) and the scan types that label
# implies. ``baseline`` is added unconditionally further down so the
# first ``securescan scan`` doesn't drown the user in known findings.
_STACK_DETECTORS: tuple[tuple[str, tuple[str, ...], tuple[ScanType, ...]], ...] = (
    (
        "Python",
        ("pyproject.toml", "requirements.txt", "Pipfile", "setup.py", "setup.cfg"),
        (ScanType.CODE, ScanType.DEPENDENCY),
    ),
    (
        "JavaScript/TypeScript",
        ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
        (ScanType.CODE, ScanType.DEPENDENCY),
    ),
    (
        "Rust",
        ("Cargo.toml", "Cargo.lock"),
        (ScanType.CODE, ScanType.DEPENDENCY),
    ),
    (
        "Go",
        ("go.mod", "go.sum"),
        (ScanType.CODE, ScanType.DEPENDENCY),
    ),
)

# Container / IaC detectors are pattern-based (Dockerfile lives at the
# repo root by convention but Terraform/k8s manifests live anywhere) so
# they get their own helper rather than a glob list.


def _detect_container(root: Path) -> bool:
    for name in ("Dockerfile", "Containerfile"):
        if (root / name).is_file():
            return True
    # Multi-stage builds with custom names: ``Dockerfile.api``,
    # ``api.Dockerfile`` etc. are common enough to honor.
    for entry in root.iterdir() if root.is_dir() else ():
        if not entry.is_file():
            continue
        nm = entry.name
        if nm.startswith("Dockerfile.") or nm.endswith(".Dockerfile"):
            return True
    return False


def _detect_iac(root: Path) -> bool:
    if not root.is_dir():
        return False
    # Terraform: any *.tf at the repo root or under a `terraform/`,
    # `infra/`, `infrastructure/` directory.
    if any(root.glob("*.tf")):
        return True
    for sub in ("terraform", "infra", "infrastructure"):
        d = root / sub
        if d.is_dir() and any(d.rglob("*.tf")):
            return True
    # Kubernetes / Helm: a `k8s/` or `kubernetes/` dir of manifests,
    # or a `Chart.yaml` (Helm chart).
    for sub in ("k8s", "kubernetes", "manifests"):
        d = root / sub
        if d.is_dir() and (any(d.rglob("*.yaml")) or any(d.rglob("*.yml"))):
            return True
    if (root / "Chart.yaml").is_file():
        return True
    # Charts nested one level deep: charts/<name>/Chart.yaml.
    charts = root / "charts"
    if charts.is_dir() and any(charts.rglob("Chart.yaml")):
        return True
    return False


def detect_stack(root: Path) -> tuple[list[str], list[ScanType]]:
    """Return ``(detected_labels, scan_types)`` for the project at ``root``.

    ``baseline`` is always appended to the scan-type list so re-running
    a scan against an unchanged tree stays cheap. If nothing matches we
    fall back to ``[baseline]`` only -- a deliberate "we don't know
    what this is, but we can still diff it against itself" default.
    """

    labels: list[str] = []
    types: list[ScanType] = []

    for label, markers, implied in _STACK_DETECTORS:
        if any((root / m).is_file() for m in markers):
            labels.append(label)
            for t in implied:
                if t not in types:
                    types.append(t)

    if _detect_container(root):
        labels.append("Container")
        if ScanType.IAC not in types:
            types.append(ScanType.IAC)

    if _detect_iac(root):
        labels.append("IaC")
        if ScanType.IAC not in types:
            types.append(ScanType.IAC)

    if ScanType.BASELINE not in types:
        types.append(ScanType.BASELINE)

    return labels, types


# --- File templates ----------------------------------------------------

_VALID_THRESHOLDS: tuple[str, ...] = ("critical", "high", "medium", "low")


def _render_config_yaml(
    *,
    project_name: str,
    scan_types: list[ScanType],
    threshold: str,
) -> str:
    """Render ``.securescan.yml`` text.

    The schema (:class:`SecureScanConfig`) is ``extra="forbid"``, so we
    can only emit keys it knows about: ``scan_types``,
    ``fail_on_severity``, ``ignored_rules``, ``semgrep_rules``. The
    project name lives in a comment header.
    """

    types_list = ", ".join(t.value for t in scan_types)
    return (
        f"# SecureScan configuration for {project_name}.\n"
        "# See https://metbcy.github.io/securescan/scanning/suppression.html\n"
        "# for the full schema.\n"
        "#\n"
        "# Inline `securescan: ignore <rule-id>` comments, the\n"
        "# `ignored_rules` list below, and the baseline file at\n"
        "# .securescan/baseline.json all suppress findings. Inline\n"
        "# comments take precedence.\n"
        "\n"
        f"scan_types: [{types_list}]\n"
        f"fail_on_severity: {threshold}\n"
        "\n"
        "# Per-rule suppressions. Add the rule_id of any finding you've\n"
        "# decided to permanently accept across the whole repo here.\n"
        "ignored_rules: []\n"
        "\n"
        "# Custom Semgrep rule packs (paths or registry refs). Optional.\n"
        "# semgrep_rules:\n"
        "#   - p/ci\n"
    )


def _render_workflow_yaml(
    *,
    scan_types: list[ScanType],
    threshold: str,
) -> str:
    """Render ``.github/workflows/securescan.yml`` text."""
    types_csv = ",".join(t.value for t in scan_types)
    return (
        "name: SecureScan\n"
        "\n"
        "on:\n"
        "  pull_request:\n"
        "  push:\n"
        "    branches: [main]\n"
        "\n"
        "permissions:\n"
        "  contents: read\n"
        "  pull-requests: write\n"
        "  security-events: write\n"
        "\n"
        "jobs:\n"
        "  scan:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          fetch-depth: 0   # diff-aware mode needs full history\n"
        "\n"
        "      - uses: Metbcy/securescan@v1\n"
        "        with:\n"
        "          scan-path: .\n"
        f"          scan-types: '{types_csv}'\n"
        f"          fail-on-severity: {threshold}\n"
        "          pr-mode: summary    # or 'inline' for review comments\n"
        "          upload-sarif: true\n"
    )


def _render_baseline_json(
    *,
    scan_types: list[ScanType],
) -> str:
    """Render an empty ``.securescan/baseline.json`` body.

    Mirrors the envelope shape :func:`baseline_writer.serialize_baseline`
    produces so ``securescan compare`` and ``securescan diff --baseline``
    accept the file as-is. ``findings`` is empty so the first real scan
    surfaces every finding in the tree -- after triage, the user runs
    ``securescan baseline .`` to populate fingerprints.
    """
    envelope = {
        "version": BASELINE_VERSION,
        "generated_by": "securescan init",
        "target_path": ".",
        "scan_types": sorted(t.value for t in scan_types),
        "findings": [],
    }
    return json.dumps(envelope, indent=2, sort_keys=True) + "\n"


# --- Atomic write helper ----------------------------------------------


def _write_file(path: Path, body: str, *, force: bool) -> bool:
    """Write ``body`` to ``path`` unless it already exists.

    Returns ``True`` if the file was written, ``False`` if skipped due
    to a pre-existing file with ``force=False``. The caller is
    responsible for surfacing the skip to the user; we don't print
    here so the wizard can decide whether to abort or just continue.
    """
    if path.exists() and not force:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return True


# --- Command -----------------------------------------------------------


def init(
    project_path: Path = typer.Argument(
        Path("."),
        help="Project directory to initialize.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing files instead of refusing.",
    ),
    no_prompt: bool = typer.Option(
        False,
        "--no-prompt",
        help="Use detected defaults; don't ask the user anything. "
        "Useful in CI / scripted setup.",
    ),
    threshold: str = typer.Option(
        "high",
        "--threshold",
        help="Default fail-on-severity (critical|high|medium|low).",
    ),
    scan_types: str | None = typer.Option(
        None,
        "--scan-types",
        help="Comma-separated list of scan types. Default: auto-detect.",
    ),
    no_workflow: bool = typer.Option(
        False,
        "--no-workflow",
        help="Skip writing the GitHub Action workflow file.",
    ),
    no_baseline: bool = typer.Option(
        False,
        "--no-baseline",
        help="Skip writing the empty baseline file.",
    ),
):
    """Initialize SecureScan for a project.

    Creates ``.securescan.yml``, ``.github/workflows/securescan.yml``,
    and ``.securescan/baseline.json`` so a fresh clone is one command
    away from a working scan setup. Idempotent: refuses to overwrite
    existing files unless ``--force`` is passed.
    """

    root = Path(project_path).resolve()
    if not root.is_dir():
        print(f"error: {project_path} is not a directory", file=sys.stderr)
        raise typer.Exit(code=2)

    # --- 1. Pick scan types ------------------------------------------
    detected_labels, detected_types = detect_stack(root)

    if scan_types is not None:
        # User-specified list takes precedence over detection. Validate
        # each entry against ScanType so we fail loudly on typos rather
        # than silently dropping the bad ones into a forbid'd config.
        chosen_types: list[ScanType] = []
        for raw in scan_types.split(","):
            name = raw.strip()
            if not name:
                continue
            try:
                chosen_types.append(ScanType(name))
            except ValueError:
                valid = ", ".join(t.value for t in ScanType)
                print(
                    f"error: unknown scan type {name!r}. Valid: {valid}",
                    file=sys.stderr,
                )
                raise typer.Exit(code=2) from None
        if not chosen_types:
            print("error: --scan-types must list at least one type", file=sys.stderr)
            raise typer.Exit(code=2)
    else:
        chosen_types = detected_types

    # --- 2. Validate threshold ---------------------------------------
    threshold_norm = threshold.strip().lower()
    if threshold_norm not in _VALID_THRESHOLDS:
        valid = "|".join(_VALID_THRESHOLDS)
        print(
            f"error: invalid --threshold {threshold!r}. Valid: {valid}",
            file=sys.stderr,
        )
        raise typer.Exit(code=2)

    # --- 3. Interactive prompts --------------------------------------
    project_name = root.name or "project"
    write_workflow = not no_workflow

    if not no_prompt:
        project_name = typer.prompt("Project name?", default=project_name)

        if scan_types is None:
            stack_label = ", ".join(detected_labels) if detected_labels else "unknown"
            types_label = ", ".join(t.value for t in chosen_types)
            keep = typer.confirm(
                f"Detected stack: {stack_label}. Use scan types [{types_label}]?",
                default=True,
            )
            if not keep:
                # Let the user override interactively. We don't validate
                # here -- typer.prompt would loop forever on a typo;
                # easier to let the user abort and re-run with
                # --scan-types.
                raw = typer.prompt(
                    "Enter comma-separated scan types",
                    default=types_label,
                )
                overridden: list[ScanType] = []
                for piece in raw.split(","):
                    nm = piece.strip()
                    if not nm:
                        continue
                    try:
                        overridden.append(ScanType(nm))
                    except ValueError:
                        valid = ", ".join(t.value for t in ScanType)
                        print(
                            f"error: unknown scan type {nm!r}. Valid: {valid}",
                            file=sys.stderr,
                        )
                        raise typer.Exit(code=2) from None
                if overridden:
                    chosen_types = overridden

        threshold_norm = typer.prompt(
            f"Fail-on-severity threshold? ({'|'.join(_VALID_THRESHOLDS)})",
            default=threshold_norm,
        ).strip().lower()
        if threshold_norm not in _VALID_THRESHOLDS:
            valid = "|".join(_VALID_THRESHOLDS)
            print(
                f"error: invalid threshold {threshold_norm!r}. Valid: {valid}",
                file=sys.stderr,
            )
            raise typer.Exit(code=2)

        if not no_workflow:
            write_workflow = typer.confirm(
                "Write GitHub Action workflow?",
                default=True,
            )

    # --- 4. Plan the writes ------------------------------------------
    config_path = root / ".securescan.yml"
    workflow_path = root / ".github" / "workflows" / "securescan.yml"
    baseline_path = root / ".securescan" / "baseline.json"

    targets: list[tuple[Path, str]] = [
        (config_path, _render_config_yaml(
            project_name=project_name,
            scan_types=chosen_types,
            threshold=threshold_norm,
        )),
    ]
    if write_workflow:
        targets.append((
            workflow_path,
            _render_workflow_yaml(scan_types=chosen_types, threshold=threshold_norm),
        ))
    if not no_baseline:
        targets.append((
            baseline_path,
            _render_baseline_json(scan_types=chosen_types),
        ))

    # Pre-flight idempotency check: if any target exists and --force
    # wasn't passed, refuse the whole run rather than write a partial
    # state. A clear error message + exit 1 is way friendlier than
    # writing two of three files and leaving the user wondering.
    if not force:
        existing = [str(p) for p, _ in targets if p.exists()]
        if existing:
            print(
                "error: refusing to overwrite existing files (pass --force):",
                file=sys.stderr,
            )
            for p in existing:
                print(f"  - {p}", file=sys.stderr)
            raise typer.Exit(code=1)

    # --- 5. Execute --------------------------------------------------
    written: list[Path] = []
    for path, body in targets:
        if _write_file(path, body, force=force):
            written.append(path)

    _shared.console.print(
        f"[bold green]✓ SecureScan initialized for {project_name}[/bold green]"
    )
    for p in written:
        try:
            rel = p.relative_to(root)
        except ValueError:
            rel = p
        _shared.console.print(f"  wrote [cyan]{rel}[/cyan]")
    _shared.console.print(
        "\nNext: run [bold]securescan scan .[/bold] to see your first findings."
    )

    raise typer.Exit(code=0)
