"""``pre-commit-securescan``: thin wrapper that invokes ``scan --staged``.

pre-commit invokes the configured ``entry:`` directly (not via Typer's
multi-command app), so we expose a flat console-script that maps to
the equivalent of ``securescan scan --staged .`` (target_path defaults
to the current working directory, which pre-commit sets to the repo
root before invoking the hook).
"""

from __future__ import annotations

import sys


def main() -> None:
    # pre-commit may pass extra positional file arguments via
    # ``pass_filenames: true``; we set ``pass_filenames: false`` in
    # ``.pre-commit-hooks.yaml`` so we won't see those, but be
    # defensive: drop anything pre-commit hands us. ``--staged``
    # discovers the staged set itself via ``git diff --cached``.
    sys.argv = ["securescan", "scan", "--staged", "."]
    from . import app

    app(prog_name="securescan", standalone_mode=True)
