#!/usr/bin/env bash
# Main runner for the SecureScan composite action.
#
# Strategy:
#   1. Try the wheel install path first (pip install securescan into a venv,
#      then `securescan status`). If that succeeds we run the wheel.
#   2. Otherwise fall back to the container image
#      ghcr.io/metbcy/securescan:<image-tag>.
#   3. Run `securescan diff` twice -- once for the PR-comment Markdown
#      output, once for SARIF -- so a `--fail-on-severity` exit on the
#      first run does not skip the SARIF upload. We capture the exit
#      code from the Markdown run and re-raise it at the end.
#   4. Upsert the PR comment by marker (delegated to post-pr-comment.sh).
set -euo pipefail

WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"
RUNNER_TMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
OUT_DIR="$WORKSPACE/.securescan"
PR_COMMENT_OUT="$OUT_DIR/diff.md"
SARIF_OUT="$OUT_DIR/diff.sarif"
mkdir -p "$OUT_DIR"

ACTION_DIR="${GITHUB_ACTION_PATH:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
IMAGE_REF="ghcr.io/metbcy/securescan:${INPUT_IMAGE_TAG:-latest}"

# ---------------------------------------------------------------------------
# 1. Decide wheel vs image.
# ---------------------------------------------------------------------------
USE_IMAGE=false
SECURESCAN_BIN=""

if [[ "${INPUT_PREFER_IMAGE:-false}" == "true" ]]; then
  USE_IMAGE=true
  echo "prefer-image=true; skipping wheel install path"
else
  VENV_DIR="$RUNNER_TMP/securescan-venv"
  if python3 -m venv "$VENV_DIR" 2>/dev/null \
      && "$VENV_DIR/bin/pip" install --quiet --upgrade pip >/dev/null 2>&1 \
      && "$VENV_DIR/bin/pip" install --quiet securescan; then
    SECURESCAN_BIN="$VENV_DIR/bin/securescan"
    if "$SECURESCAN_BIN" --help >/dev/null 2>&1; then
      echo "Using wheel install path: $SECURESCAN_BIN"
    else
      echo "wheel installed but binary not callable; falling back to image"
      USE_IMAGE=true
    fi
  else
    echo "wheel install failed; falling back to image $IMAGE_REF"
    USE_IMAGE=true
  fi
fi

# ---------------------------------------------------------------------------
# 2. Build the diff arg arrays. We keep `args_for` building two arrays --
#    one for the github-pr-comment render (writes diff.md) and one for the
#    sarif render (writes diff.sarif). Path values differ between the wheel
#    path (host-absolute paths) and the image path (rewritten to /workspace
#    and /output mounts), so we build the arrays per-context below.
# ---------------------------------------------------------------------------
SCAN_TYPE_ARGS=()
IFS=',' read -ra _types <<< "${INPUT_SCAN_TYPES:-code}"
for t in "${_types[@]}"; do
  t_trim="${t// /}"
  if [[ -n "$t_trim" ]]; then
    SCAN_TYPE_ARGS+=(--type "$t_trim")
  fi
done

FAIL_ARGS=()
fail_lower="$(echo "${INPUT_FAIL_ON_SEVERITY:-none}" | tr '[:upper:]' '[:lower:]')"
if [[ -n "$fail_lower" && "$fail_lower" != "none" ]]; then
  FAIL_ARGS+=(--fail-on-severity "$fail_lower")
fi

# ---------------------------------------------------------------------------
# 2b. Resolve pr-mode dispatch flags. Default `summary` keeps the v0.2.0
#     single-comment behaviour. `inline` and `both` are opt-in and require
#     a pull_request event payload (so we can read base.sha for the diff
#     position translation that the github-review renderer feeds off).
# ---------------------------------------------------------------------------
pr_mode_lower="$(echo "${INPUT_PR_MODE:-summary}" | tr '[:upper:]' '[:lower:]')"
case "$pr_mode_lower" in
  summary|inline|both) ;;
  *)
    echo "::warning::unknown pr-mode '${INPUT_PR_MODE:-}'; falling back to 'summary'"
    pr_mode_lower="summary"
    ;;
esac

WANT_SUMMARY=false
WANT_INLINE=false
case "$pr_mode_lower" in
  summary) WANT_SUMMARY=true ;;
  inline)  WANT_INLINE=true ;;
  both)    WANT_SUMMARY=true; WANT_INLINE=true ;;
esac

if [[ "$WANT_INLINE" == "true" && "${GITHUB_EVENT_NAME:-}" != "pull_request" ]]; then
  echo "::warning::pr-mode='${pr_mode_lower}' requires a pull_request event (got '${GITHUB_EVENT_NAME:-}'); skipping inline review submission"
  WANT_INLINE=false
fi

REVIEW_OUT="$OUT_DIR/review.json"

# ---------------------------------------------------------------------------
# 3. Run the diff. Capture exit code so SARIF upload + PR comment still happen
#    when --fail-on-severity returns non-zero.
# ---------------------------------------------------------------------------
DIFF_EXIT=0

# ---------------------------------------------------------------------------
# 3a. Build the optional github-review args. Only used when WANT_INLINE=true.
#     The renderer is gated on --repo / --sha / --base-sha by the CLI; we
#     populate them from GITHUB_REPOSITORY / GITHUB_SHA / INPUT_BASE_REF.
#     Suggestion blocks default on; --no-suggestions is appended when the
#     action input is explicitly false.
# ---------------------------------------------------------------------------
review_event_upper="$(echo "${INPUT_REVIEW_EVENT:-COMMENT}" | tr '[:lower:]' '[:upper:]')"
inline_sugg_lower="$(echo "${INPUT_INLINE_SUGGESTIONS:-true}" | tr '[:upper:]' '[:lower:]')"

REVIEW_ARGS=(
  --output github-review
  --repo "${GITHUB_REPOSITORY:-}"
  --sha "${GITHUB_SHA:-$INPUT_HEAD_REF}"
  --base-sha "${INPUT_BASE_REF}"
  --review-event "$review_event_upper"
)
if [[ "$inline_sugg_lower" != "true" ]]; then
  REVIEW_ARGS+=(--no-suggestions)
fi

if [[ "$USE_IMAGE" == "true" ]]; then
  echo "Using container $IMAGE_REF"

  baseline_args_img=()
  if [[ -n "${INPUT_BASELINE:-}" ]]; then
    baseline_args_img+=(--baseline "/workspace/$INPUT_BASELINE")
  fi

  docker_common=(
    docker run --rm
    -v "$WORKSPACE:/workspace"
    -v "$OUT_DIR:/output"
    -e GITHUB_REPOSITORY -e GITHUB_SHA -e CI=true
    "$IMAGE_REF"
    diff /workspace
    --base-ref "$INPUT_BASE_REF"
    --head-ref "$INPUT_HEAD_REF"
    "${SCAN_TYPE_ARGS[@]}"
    "${baseline_args_img[@]}"
    "${FAIL_ARGS[@]}"
  )

  set +e
  "${docker_common[@]}" --output github-pr-comment --output-file /output/diff.md
  DIFF_EXIT=$?
  set -e

  set +e
  "${docker_common[@]}" --output sarif --output-file /output/diff.sarif
  sarif_exit=$?
  set -e
  if [[ "$sarif_exit" -ne 0 && "$DIFF_EXIT" -eq 0 ]]; then
    DIFF_EXIT="$sarif_exit"
  fi

  if [[ "$WANT_INLINE" == "true" ]]; then
    set +e
    "${docker_common[@]}" "${REVIEW_ARGS[@]}" --output-file /output/review.json
    review_exit=$?
    set -e
    if [[ "$review_exit" -ne 0 && "$DIFF_EXIT" -eq 0 ]]; then
      DIFF_EXIT="$review_exit"
    fi
  fi
else
  baseline_args_host=()
  if [[ -n "${INPUT_BASELINE:-}" ]]; then
    baseline_args_host+=(--baseline "$WORKSPACE/$INPUT_BASELINE")
  fi

  bin_common=(
    "$SECURESCAN_BIN"
    diff "$WORKSPACE"
    --base-ref "$INPUT_BASE_REF"
    --head-ref "$INPUT_HEAD_REF"
    "${SCAN_TYPE_ARGS[@]}"
    "${baseline_args_host[@]}"
    "${FAIL_ARGS[@]}"
  )

  set +e
  "${bin_common[@]}" --output github-pr-comment --output-file "$PR_COMMENT_OUT"
  DIFF_EXIT=$?
  set -e

  set +e
  "${bin_common[@]}" --output sarif --output-file "$SARIF_OUT"
  sarif_exit=$?
  set -e
  if [[ "$sarif_exit" -ne 0 && "$DIFF_EXIT" -eq 0 ]]; then
    DIFF_EXIT="$sarif_exit"
  fi

  if [[ "$WANT_INLINE" == "true" ]]; then
    set +e
    "${bin_common[@]}" "${REVIEW_ARGS[@]}" --output-file "$REVIEW_OUT"
    review_exit=$?
    set -e
    if [[ "$review_exit" -ne 0 && "$DIFF_EXIT" -eq 0 ]]; then
      DIFF_EXIT="$review_exit"
    fi
  fi
fi

# ---------------------------------------------------------------------------
# 4. Post the PR feedback. `summary` (default) upserts the marker comment via
#    post-pr-comment.sh; `inline` submits a GitHub Review via post-review.sh
#    (added by IR7); `both` runs both in sequence. Each call is independently
#    guarded so a missing/failed handler never blocks the other path or the
#    SARIF upload that runs as a separate composite step.
# ---------------------------------------------------------------------------
if [[ "$WANT_SUMMARY" == "true" \
      && "${INPUT_COMMENT_ON_PR:-true}" == "true" \
      && "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
  if [[ -x "$ACTION_DIR/post-pr-comment.sh" ]]; then
    "$ACTION_DIR/post-pr-comment.sh" || echo "::warning::post-pr-comment.sh failed (continuing)"
  else
    echo "::warning::post-pr-comment.sh not found at $ACTION_DIR (skipping comment)"
  fi
fi

if [[ "$WANT_INLINE" == "true" ]]; then
  if [[ -x "$ACTION_DIR/post-review.sh" ]]; then
    "$ACTION_DIR/post-review.sh" || echo "::warning::post-review.sh failed (continuing)"
  else
    echo "::warning::post-review.sh not found at $ACTION_DIR (inline review submission requires IR7; skipping)"
  fi
fi

exit "$DIFF_EXIT"
