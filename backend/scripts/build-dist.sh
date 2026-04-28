#!/usr/bin/env bash
# Build wheel + sdist for PyPI publish. Run from anywhere; cd's into backend/.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -rf dist build *.egg-info
python -m pip install -q -U build twine
python -m build
python -m twine check dist/*
ls -lh dist/
