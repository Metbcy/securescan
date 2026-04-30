"""Pytest session-wide config.

We force `SECURESCAN_TESTING=1` so the structured logger falls back to
text output - keeping pytest's capsys/caplog working as the existing
suite expects, regardless of whatever SECURESCAN_LOG_FORMAT or
SECURESCAN_IN_CONTAINER might be set in the environment.

We also pin a sane terminal width via ``COLUMNS`` BEFORE any test
imports. Several CLI tests assert against the rendered help text
(e.g. ``"--no-ai" in result.output``); without a TTY (CI runners
have no pty) Rich/Click read ``COLUMNS`` to size the help table,
and an unset ``COLUMNS`` collapses the body to nothing — every
flag-recognition test fails as a result. Setting ``COLUMNS=200``
guarantees the help table renders the full option list inline
regardless of the runner's tty state. Local dev with a real terminal
overrides this, so interactive ``securescan --help`` keeps using the
caller's actual width.
"""

from __future__ import annotations

import os

os.environ.setdefault("SECURESCAN_TESTING", "1")
# `setdefault` won't overwrite an existing value; CI explicitly sets
# COLUMNS=0 (no TTY), which is exactly the value that breaks help
# rendering. Force-overwrite when the inherited value is missing or
# nonsense (0 / "" / not an int / < 80).
_existing_columns = os.environ.get("COLUMNS", "")
try:
    _columns_ok = int(_existing_columns) >= 80
except (ValueError, TypeError):
    _columns_ok = False
if not _columns_ok:
    os.environ["COLUMNS"] = "200"
