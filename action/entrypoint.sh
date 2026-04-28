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
# 3. Run the diff. Capture exit code so SARIF upload + PR comment still happen
#    when --fail-on-severity returns non-zero.
# ---------------------------------------------------------------------------
DIFF_EXIT=0

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
fi

# ---------------------------------------------------------------------------
# 4. Upsert the PR comment (marker-based) regardless of fail-on-severity exit.
# ---------------------------------------------------------------------------
if [[ "${INPUT_COMMENT_ON_PR:-true}" == "true" && "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
  if [[ -x "$ACTION_DIR/post-pr-comment.sh" ]]; then
    "$ACTION_DIR/post-pr-comment.sh" || echo "::warning::post-pr-comment.sh failed (continuing)"
  else
    echo "::warning::post-pr-comment.sh not found at $ACTION_DIR (skipping comment)"
  fi
fi

exit "$DIFF_EXIT"
