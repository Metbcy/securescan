#!/usr/bin/env bash
# Local diff: scan two branches outside CI, classify, render to terminal.
set -euo pipefail
BASE="${1:-main}"
HEAD="${2:-HEAD}"

# Snapshot the base branch
git checkout "$BASE"
securescan scan . --type code --output json --output-file before.json --no-ai

# Snapshot the head branch
git checkout "$HEAD"
securescan scan . --type code --output json --output-file after.json --no-ai

# Diff
securescan diff . --base-snapshot before.json --head-snapshot after.json --output text

# Restore
git checkout -
