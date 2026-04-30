"""SecureScan CLI package.

The original ``securescan/cli.py`` module was split into per-command
submodules in v0.10.3. This package preserves the pre-split entry point
``securescan.cli:app`` (referenced from ``pyproject.toml``'s
``[project.scripts]``) and re-exports the helper / function names that
existing tests and downstream consumers imported from the flat module.

Layout:

* :mod:`._shared` -- helpers shared by 2+ command modules
  (``_run_scan_for_diff``, severity dicts, github-review validators,
  output-format defaults, etc.)
* :mod:`.scan`, :mod:`.diff`, :mod:`.compare`, :mod:`.baseline`,
  :mod:`.serve`, :mod:`.status`, :mod:`.history` -- one file per
  top-level Typer command
* :mod:`.config` -- the ``securescan config`` sub-Typer plus its
  ``validate`` subcommand

Behavior is byte-identical to the pre-split ``cli.py``: same flags,
same defaults, same help text, same exit codes.
"""

import typer

# Import the shared module first so submodules can `from . import _shared`
# without an import loop.
from . import _shared
from . import scan as _scan_module

# Re-export public + commonly-imported helpers so that pre-split
# imports (``from securescan.cli import should_run_ai`` etc.) keep
# resolving. Tests in particular reach into a handful of private
# helpers; we re-export those too to keep the migration cost zero
# for tests that didn't touch the call sites.
from ._shared import (
    _REVIEW_EVENTS,
    _SEVERITY_THRESHOLD_MAP,
    SEVERITY_COLORS,
    SEVERITY_RANK,
    AIEnricher,
    _default_show_suppressed,
    _load_resolved_config,
    _render_compare_text,
    _render_diff_sarif,
    _render_diff_text,
    _require_github_review_inputs,
    _resolve_default_output,
    _run_scan_for_diff,
    _validate_review_event,
    console,
    diff_should_run_ai,
    should_run_ai,
)
from .baseline import baseline
from .compare import compare
from .config import config_app
from .diff import diff
from .history import history
from .scan import _print_findings, _print_summary, _run_scan_async
from .serve import serve
from .status import status

# Build the root Typer app and register each top-level command on it
# directly. We deliberately do NOT use ``app.add_typer(sub_app,
# name="scan")`` here -- that would change the invocation grammar
# from ``securescan scan <args>`` to ``securescan scan scan <args>``
# because Typer's ``add_typer`` treats the sub-app as a command group.
# Re-applying ``app.command()`` to each function preserves the
# pre-split CLI surface byte-for-byte.
#
# We import ``scan`` via ``from . import scan as _scan_module`` (rather
# than ``from .scan import scan``) so that ``securescan.cli.scan``
# attribute access keeps resolving to the *submodule* -- some tests
# do ``import securescan.cli.scan as _cli_scan`` and need a module to
# monkey-patch ``_run_scan_async`` on.
app = typer.Typer(name="securescan", help="AI-powered security scanning CLI")
app.command()(_scan_module.scan)
app.command()(diff)
app.command()(status)
app.command()(serve)
app.command()(history)
app.command()(compare)
app.command()(baseline)
app.add_typer(config_app, name="config")


__all__ = [
    "AIEnricher",
    "SEVERITY_COLORS",
    "SEVERITY_RANK",
    "_default_show_suppressed",
    "_load_resolved_config",
    "_print_findings",
    "_print_summary",
    "_render_compare_text",
    "_render_diff_sarif",
    "_render_diff_text",
    "_require_github_review_inputs",
    "_resolve_default_output",
    "_REVIEW_EVENTS",
    "_run_scan_async",
    "_run_scan_for_diff",
    "_SEVERITY_THRESHOLD_MAP",
    "_validate_review_event",
    "app",
    "baseline",
    "compare",
    "config_app",
    "console",
    "diff",
    "diff_should_run_ai",
    "history",
    "serve",
    "should_run_ai",
    "status",
]


if __name__ == "__main__":
    app()
