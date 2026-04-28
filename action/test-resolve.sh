#!/usr/bin/env bash
# Self-test for entrypoint-resolve.sh.
#
# Not a pytest -- pure shell self-test. Exercises the three resolution
# paths: pull_request event with empty inputs, explicit inputs win over
# event payload, non-PR event errors out without explicit head input.
#
# Run directly:  bash action/test-resolve.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESOLVE="$HERE/entrypoint-resolve.sh"

if [[ ! -x "$RESOLVE" ]]; then
  echo "FAIL: $RESOLVE is not executable"
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Case 1: pull_request event, no explicit inputs -> reads sha from payload.
# ---------------------------------------------------------------------------
cat > "$WORK/event1.json" <<'EOF'
{"pull_request": {"base": {"sha": "abc123"}, "head": {"sha": "def456"}, "number": 42}}
EOF
out1="$WORK/output1"
: > "$out1"
GITHUB_EVENT_NAME=pull_request \
GITHUB_EVENT_PATH="$WORK/event1.json" \
GITHUB_OUTPUT="$out1" \
INPUT_BASE_REF= INPUT_HEAD_REF= \
  bash "$RESOLVE" >/dev/null

grep -q '^base_ref=abc123$' "$out1" || { echo "FAIL case 1: base_ref"; cat "$out1"; exit 1; }
grep -q '^head_ref=def456$' "$out1" || { echo "FAIL case 1: head_ref"; cat "$out1"; exit 1; }
echo "PASS case 1: pull_request event reads sha from payload"

# ---------------------------------------------------------------------------
# Case 2: explicit inputs override event payload.
# ---------------------------------------------------------------------------
out2="$WORK/output2"
: > "$out2"
GITHUB_EVENT_NAME=pull_request \
GITHUB_EVENT_PATH="$WORK/event1.json" \
GITHUB_OUTPUT="$out2" \
INPUT_BASE_REF=main INPUT_HEAD_REF=feature \
  bash "$RESOLVE" >/dev/null

grep -q '^base_ref=main$' "$out2" || { echo "FAIL case 2: base_ref"; cat "$out2"; exit 1; }
grep -q '^head_ref=feature$' "$out2" || { echo "FAIL case 2: head_ref"; cat "$out2"; exit 1; }
echo "PASS case 2: explicit inputs override event payload"

# ---------------------------------------------------------------------------
# Case 3: push event with no explicit base_ref -> error exit 2.
# ---------------------------------------------------------------------------
out3="$WORK/output3"
: > "$out3"
set +e
GITHUB_EVENT_NAME=push \
GITHUB_EVENT_PATH= \
GITHUB_SHA=cafebabe \
GITHUB_OUTPUT="$out3" \
INPUT_BASE_REF= INPUT_HEAD_REF= \
  bash "$RESOLVE" >/dev/null 2>&1
rc=$?
set -e
if [[ "$rc" -ne 2 ]]; then
  echo "FAIL case 3: expected exit 2, got $rc"
  exit 1
fi
echo "PASS case 3: push event without base errors with exit 2"

# ---------------------------------------------------------------------------
# Case 4: push event with explicit base_ref -> uses GITHUB_SHA for head.
# ---------------------------------------------------------------------------
out4="$WORK/output4"
: > "$out4"
GITHUB_EVENT_NAME=push \
GITHUB_EVENT_PATH= \
GITHUB_SHA=cafebabe \
GITHUB_OUTPUT="$out4" \
INPUT_BASE_REF=main INPUT_HEAD_REF= \
  bash "$RESOLVE" >/dev/null

grep -q '^base_ref=main$' "$out4" || { echo "FAIL case 4: base_ref"; cat "$out4"; exit 1; }
grep -q '^head_ref=cafebabe$' "$out4" || { echo "FAIL case 4: head_ref"; cat "$out4"; exit 1; }
echo "PASS case 4: push event uses GITHUB_SHA for head"

echo "All entrypoint-resolve.sh self-tests passed."
