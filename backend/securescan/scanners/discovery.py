"""Tool discovery helpers.

`shutil.which()` only searches the PATH environment variable. When
SecureScan's backend runs out of a Python virtualenv (e.g.
``./venv/bin/python -m uvicorn ...``), the venv's ``bin/`` is NOT
added to PATH for the running process — so tools like ``semgrep``,
``bandit``, ``safety``, and ``checkov`` installed via ``pip install``
into that venv are invisible to ``shutil.which()`` despite being
fully usable.

``find_tool(name)`` is the authoritative way to resolve a binary
across both system PATH and the running Python's ``bin/``. Every
scanner that previously called ``shutil.which(name)`` directly
(both in ``is_available()`` and in ``create_subprocess_exec``)
should switch to this helper.

For Python tools that ship as importable modules (bandit, safety,
semgrep, checkov), we additionally fall back to ``python -m <tool>``
via :func:`tool_command_or_module` so the scanner can still execute
even when only the module is available (no console script).
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path
from typing import Optional


def _venv_bin_dir() -> Path:
    """Return the directory containing the running Python's executables.

    On Unix this is ``<prefix>/bin``; on Windows it's ``<prefix>/Scripts``.
    For a venv-launched process this is the venv's bin/.

    NOTE: we deliberately do NOT call ``.resolve()`` on ``sys.executable``.
    Venvs are typically constructed by symlinking ``python`` → ``python3``
    → ``/usr/bin/python3``; resolving would walk the symlink chain to the
    system interpreter and miss the venv's own ``bin/`` directory where
    pip-installed scripts actually live.
    """
    return Path(sys.executable).parent


def find_tool(name: str) -> Optional[str]:
    """Return the absolute path to ``name`` if installed, else ``None``.

    Search order:
      1. PATH (system-wide installs).
      2. The running Python's bin/ directory (venv-installed tools).

    The fallback to step 2 is what fixes the bug where
    ``shutil.which("bandit")`` returns None for a backend running
    out of a venv that has ``bandit`` installed via pip.
    """
    via_path = shutil.which(name)
    if via_path is not None:
        return via_path

    candidate = _venv_bin_dir() / name
    if candidate.is_file():
        return str(candidate)

    return None


def tool_command_or_module(name: str, module: Optional[str] = None) -> Optional[list[str]]:
    """Return the command-line prefix needed to invoke ``name``.

    Examples:
      - ``bandit`` resolves to ``["/usr/bin/bandit"]`` (system) or
        ``["/path/to/venv/bin/bandit"]`` (venv).
      - If neither exists but the Python module ``module`` is
        importable, returns ``["<sys.executable>", "-m", module]``.
      - Returns ``None`` if the tool can't be found at all.

    ``module`` defaults to ``name`` (most Python security tools
    follow this convention).
    """
    binary = find_tool(name)
    if binary is not None:
        return [binary]

    module_name = module if module is not None else name
    try:
        import importlib.util
        spec = importlib.util.find_spec(module_name)
        if spec is not None:
            return [sys.executable, "-m", module_name]
    except (ImportError, ValueError):
        pass

    return None
