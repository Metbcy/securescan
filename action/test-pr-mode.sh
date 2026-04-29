#!/usr/bin/env bash
# Self-test for entrypoint.sh's pr-mode dispatch logic.
#
# Not a pytest -- pure shell self-test. Mocks securescan (via a fake
# docker on PATH and INPUT_PREFER_IMAGE=true to skip the wheel install
# branch), post-pr-comment.sh, and post-review.sh by writing tiny
# replacements to a sandbox GITHUB_ACTION_PATH, then runs entrypoint.sh
# under each pr-mode value and asserts which mocks got invoked.
#
# Run directly:  bash action/test-pr-mode.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENTRYPOINT="$HERE/entrypoint.sh"

if [[ ! -f "$ENTRYPOINT" ]]; then
  echo "FAIL: $ENTRYPOINT not found"
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAILS=0

# ---------------------------------------------------------------------------
# Sandbox: a copy of entrypoint.sh plus mock post-* scripts. Each mock
# appends its name to $TRACKER so we can assert which paths fired.
# ---------------------------------------------------------------------------
SANDBOX="$WORK/action"
mkdir -p "$SANDBOX"
cp "$ENTRYPOINT" "$SANDBOX/entrypoint.sh"
chmod +x "$SANDBOX/entrypoint.sh"

cat > "$SANDBOX/post-pr-comment.sh" <<'EOF'
#!/usr/bin/env bash
echo "post-pr-comment" >> "${TRACKER:-/dev/null}"
EOF
chmod +x "$SANDBOX/post-pr-comment.sh"

cat > "$SANDBOX/post-review.sh" <<'EOF'
#!/usr/bin/env bash
echo "post-review" >> "${TRACKER:-/dev/null}"
EOF
chmod +x "$SANDBOX/post-review.sh"

# Fake docker on PATH: paired with INPUT_PREFER_IMAGE=true this stands in
# for the securescan container. No-op exit 0 is enough -- entrypoint.sh
# writes its own output files into the workspace via --output-file but
# the post-* mocks don't read them, so an empty exec is sufficient.
SHIMS="$WORK/shims"
mkdir -p "$SHIMS"
cat > "$SHIMS/docker" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$SHIMS/docker"

# Synthetic pull_request event payload (matches entrypoint-resolve.sh's
# expected schema -- the action's resolve step already ran upstream so
# entrypoint.sh just consumes INPUT_BASE_REF / INPUT_HEAD_REF directly).
PR_EVENT="$WORK/pr_event.json"
cat > "$PR_EVENT" <<'EOF'
{"pull_request": {"base": {"sha": "base000"}, "head": {"sha": "head111"}, "number": 7}}
EOF

# ---------------------------------------------------------------------------
# Helper: run entrypoint.sh with a given pr-mode + event_name. Captures
# stdout/stderr per case so we can assert on warnings as well as on
# tracker contents.
# ---------------------------------------------------------------------------
run_case() {
  local case_name="$1" pr_mode="$2" event_name="$3" event_path="$4"
  local action_dir="${5:-$SANDBOX}"
  local case_dir="$WORK/case-${case_name}"
  mkdir -p "$case_dir/tmp"
  : > "$case_dir/tracker"

  PATH="$SHIMS:$PATH" \
  GITHUB_ACTION_PATH="$action_dir" \
  GITHUB_WORKSPACE="$case_dir" \
  GITHUB_EVENT_NAME="$event_name" \
  GITHUB_EVENT_PATH="$event_path" \
  GITHUB_REPOSITORY="example/repo" \
  GITHUB_SHA="head111" \
  TRACKER="$case_dir/tracker" \
  RUNNER_TEMP="$case_dir/tmp" \
  INPUT_BASE_REF="base000" \
  INPUT_HEAD_REF="head111" \
  INPUT_SCAN_TYPES="code" \
  INPUT_FAIL_ON_SEVERITY="none" \
  INPUT_COMMENT_ON_PR="true" \
  INPUT_UPLOAD_SARIF="true" \
  INPUT_IMAGE_TAG="latest" \
  INPUT_PREFER_IMAGE="true" \
  INPUT_BASELINE="" \
  INPUT_GITHUB_TOKEN="dummy" \
  INPUT_PR_MODE="$pr_mode" \
  INPUT_REVIEW_EVENT="COMMENT" \
  INPUT_INLINE_SUGGESTIONS="true" \
    bash "$action_dir/entrypoint.sh" >"$case_dir/stdout" 2>"$case_dir/stderr" || true
}

assert_tracker_has() {
  local case_dir="$1" needle="$2" label="$3"
  if grep -qx "$needle" "$case_dir/tracker"; then
    echo "PASS $label"
  else
    echo "FAIL $label: tracker missing '$needle'"
    echo "  tracker:"; sed 's/^/    /' "$case_dir/tracker"
    echo "  stdout:"; sed 's/^/    /' "$case_dir/stdout"
    echo "  stderr:"; sed 's/^/    /' "$case_dir/stderr"
    FAILS=$((FAILS + 1))
  fi
}

assert_tracker_lacks() {
  local case_dir="$1" needle="$2" label="$3"
  if grep -qx "$needle" "$case_dir/tracker"; then
    echo "FAIL $label: tracker unexpectedly contains '$needle'"
    echo "  tracker:"; sed 's/^/    /' "$case_dir/tracker"
    FAILS=$((FAILS + 1))
  else
    echo "PASS $label"
  fi
}

assert_log_contains() {
  local case_dir="$1" needle="$2" label="$3"
  if grep -qF "$needle" "$case_dir/stdout" "$case_dir/stderr"; then
    echo "PASS $label"
  else
    echo "FAIL $label: log missing '$needle'"
    echo "  stdout:"; sed 's/^/    /' "$case_dir/stdout"
    echo "  stderr:"; sed 's/^/    /' "$case_dir/stderr"
    FAILS=$((FAILS + 1))
  fi
}

# ---------------------------------------------------------------------------
# Case 1: pr-mode=summary on pull_request -> only post-pr-comment.sh fires.
# ---------------------------------------------------------------------------
run_case 1 summary pull_request "$PR_EVENT"
assert_tracker_has   "$WORK/case-1" "post-pr-comment" "case 1: summary -> post-pr-comment called"
assert_tracker_lacks "$WORK/case-1" "post-review"     "case 1: summary -> post-review NOT called"

# ---------------------------------------------------------------------------
# Case 2: pr-mode=inline on pull_request -> only post-review.sh fires.
# ---------------------------------------------------------------------------
run_case 2 inline pull_request "$PR_EVENT"
assert_tracker_has   "$WORK/case-2" "post-review"     "case 2: inline -> post-review called"
assert_tracker_lacks "$WORK/case-2" "post-pr-comment" "case 2: inline -> post-pr-comment NOT called"

# ---------------------------------------------------------------------------
# Case 3: pr-mode=both on pull_request -> both fire.
# ---------------------------------------------------------------------------
run_case 3 both pull_request "$PR_EVENT"
assert_tracker_has "$WORK/case-3" "post-pr-comment" "case 3: both -> post-pr-comment called"
assert_tracker_has "$WORK/case-3" "post-review"     "case 3: both -> post-review called"

# ---------------------------------------------------------------------------
# Case 4: pr-mode=summary on push -> nothing fires (summary path is gated
# on pull_request to preserve v0.2.0 semantics; review path was never on).
# ---------------------------------------------------------------------------
run_case 4 summary push ""
assert_tracker_lacks "$WORK/case-4" "post-pr-comment" "case 4: summary+push -> post-pr-comment NOT called"
assert_tracker_lacks "$WORK/case-4" "post-review"     "case 4: summary+push -> post-review NOT called"

# ---------------------------------------------------------------------------
# Case 5: pr-mode=inline on push -> warn + skip; no inline call.
# ---------------------------------------------------------------------------
run_case 5 inline push ""
assert_tracker_lacks "$WORK/case-5" "post-review"     "case 5: inline+push -> post-review NOT called"
assert_tracker_lacks "$WORK/case-5" "post-pr-comment" "case 5: inline+push -> post-pr-comment NOT called"
assert_log_contains  "$WORK/case-5" "requires a pull_request event" "case 5: inline+push -> warning logged"

# ---------------------------------------------------------------------------
# Case 6: defensive missing post-review.sh (IR7 not landed yet) -> warn +
# skip; the action does NOT fail. Built by copying the sandbox without
# post-review.sh.
# ---------------------------------------------------------------------------
NO_REVIEW_DIR="$WORK/no-review"
mkdir -p "$NO_REVIEW_DIR"
cp "$ENTRYPOINT" "$NO_REVIEW_DIR/entrypoint.sh"
chmod +x "$NO_REVIEW_DIR/entrypoint.sh"
cp "$SANDBOX/post-pr-comment.sh" "$NO_REVIEW_DIR/post-pr-comment.sh"
run_case 6 inline pull_request "$PR_EVENT" "$NO_REVIEW_DIR"
assert_tracker_lacks "$WORK/case-6" "post-review"   "case 6: missing post-review.sh -> not invoked"
assert_log_contains  "$WORK/case-6" "post-review.sh not found" "case 6: missing post-review.sh -> warning logged"

# ---------------------------------------------------------------------------
# Case 7: pr-mode=BOTH (uppercase) -> normalised to 'both' (case-insensitive
# input handling avoids surprising users who type the docs example verbatim).
# ---------------------------------------------------------------------------
run_case 7 BOTH pull_request "$PR_EVENT"
assert_tracker_has "$WORK/case-7" "post-pr-comment" "case 7: BOTH -> post-pr-comment called"
assert_tracker_has "$WORK/case-7" "post-review"     "case 7: BOTH -> post-review called"

# ---------------------------------------------------------------------------
# Case 8: unknown pr-mode -> warn + fall back to 'summary' (don't fail the
# action just because someone typoed an input value).
# ---------------------------------------------------------------------------
run_case 8 banana pull_request "$PR_EVENT"
assert_tracker_has   "$WORK/case-8" "post-pr-comment" "case 8: unknown pr-mode -> falls back to summary"
assert_tracker_lacks "$WORK/case-8" "post-review"     "case 8: unknown pr-mode -> no inline call"
assert_log_contains  "$WORK/case-8" "unknown pr-mode" "case 8: unknown pr-mode -> warning logged"

if [[ "$FAILS" -ne 0 ]]; then
  echo "FAIL: $FAILS pr-mode self-test cases failed"
  exit 1
fi

echo "All entrypoint.sh pr-mode self-tests passed."
