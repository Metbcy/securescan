"""Pytest session-wide config.

We force `SECURESCAN_TESTING=1` so the structured logger falls back to
text output - keeping pytest's capsys/caplog working as the existing
suite expects, regardless of whatever SECURESCAN_LOG_FORMAT or
SECURESCAN_IN_CONTAINER might be set in the environment.
"""
from __future__ import annotations

import os


os.environ.setdefault("SECURESCAN_TESTING", "1")
