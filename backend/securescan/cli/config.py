"""``securescan config`` sub-app — config-file management commands.

Currently exposes ``securescan config validate``. The sub-app instance
``config_app`` is registered on the root Typer app by
:mod:`securescan.cli.__init__` via ``app.add_typer(config_app,
name="config")``.
"""

import sys
from pathlib import Path

import typer

from ..config_file import load_config
from ..config_lint import LintReport, lint_config

config_app = typer.Typer(
    help="Manage .securescan.yml configuration.",
    no_args_is_help=True,
)


_SEVERITY_RANK_FOR_LINT: dict[str, int] = {
    "error": 0,
    "warning": 1,
    "info": 2,
}


def _print_lint_report(report: LintReport) -> None:
    """Render lint issues to stderr, grouped by severity.

    Errors first, then warnings, then info -- mirrors how compilers
    surface diagnostics. The summary line is the last thing on stderr
    so a reader skimming the tail still sees the totals.
    """

    grouped = sorted(
        report.issues,
        key=lambda issue: _SEVERITY_RANK_FOR_LINT.get(issue.severity, 99),
    )
    for issue in grouped:
        location = issue.location if issue.location else "-"
        print(f"{issue.severity}: {location}: {issue.message}", file=sys.stderr)

    n_errors = len(report.errors())
    n_warnings = len(report.warnings())
    n_info = len(report.info())

    def _plural(n: int, singular: str, plural: str) -> str:
        return f"{n} {singular if n == 1 else plural}"

    summary_label = "Config invalid" if report.has_errors else "Config valid"
    summary = (
        f"{summary_label}: "
        f"{_plural(n_errors, 'error', 'errors')}, "
        f"{_plural(n_warnings, 'warning', 'warnings')}, "
        f"{_plural(n_info, 'info issue', 'info issues')}."
    )
    print(summary, file=sys.stderr)


@config_app.command("validate")
def config_validate(
    config_path: Path | None = typer.Argument(
        None,
        help=("Path to the config file. Defaults to walking up from the current directory."),
    ),
):
    """Lint the .securescan.yml configuration file.

    Catches typos in severity_overrides keys, missing semgrep_rules
    paths, ignore-vs-override collisions, and other semantic mistakes
    that the typed loader can't see. Warnings and info issues do not
    fail the exit code; only errors do.
    """

    if config_path is None:
        _, found_path = load_config()
        if found_path is None:
            print(
                "no .securescan.yml in this directory tree",
                file=sys.stderr,
            )
            raise typer.Exit(code=2)
        target = found_path
    else:
        target = config_path

    report = lint_config(target)
    _print_lint_report(report)

    if report.has_errors:
        raise typer.Exit(code=1)
