"""Tests for ``backend/securescan/`` package shape after the SS9 rename.

These checks guard against regressing back to the legacy ``src/`` layout,
which would silently turn ``pip install securescan`` into a top-level
``src`` package collision with anyone else who has a ``src/`` directory.
"""

import sys


def test_securescan_package_is_importable():
    import securescan  # noqa: F401  (import-only smoke check)
    from securescan import cli, diff, fingerprint, models  # noqa: F401


def test_package_does_not_expose_src_namespace():
    # The old ``src`` namespace should not be importable as a top-level
    # package (it is only a relative-import target now). If something has
    # imported ``src`` it must not look like the SecureScan package
    # (i.e. must not expose ``cli``).
    assert "src" not in sys.modules or not hasattr(sys.modules.get("src"), "cli")
