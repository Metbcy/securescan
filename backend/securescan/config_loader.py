"""User-scoped env loader.

Loads a `.env` file from the user's config directory before
:class:`securescan.config.Settings` is instantiated, so persistent
credentials (e.g. ``SECURESCAN_ZAP_API_KEY``) survive reboots without
re-exporting them in every shell.

Resolution order (first hit wins):

1. ``$XDG_CONFIG_HOME/securescan/.env`` when ``XDG_CONFIG_HOME`` is set
   and non-empty (per the XDG Base Directory spec).
2. ``~/.config/securescan/.env``.

Real shell env vars always win over file values
(``load_dotenv(..., override=False)``), and a missing file is a silent
no-op — Docker images that don't ship a config dir are unaffected.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

_REL_PATH = Path("securescan") / ".env"


def _candidate_paths() -> list[Path]:
    paths: list[Path] = []
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        paths.append(Path(xdg) / _REL_PATH)
    paths.append(Path.home() / ".config" / _REL_PATH)
    return paths


def load_user_env() -> Optional[Path]:
    """Load the first existing user env file. Return its path, or ``None``."""
    for candidate in _candidate_paths():
        if candidate.is_file():
            load_dotenv(candidate, override=False)
            return candidate
    return None
