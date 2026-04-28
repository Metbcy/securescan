#!/usr/bin/env bash
# Resolve base-ref / head-ref defaults from the GitHub event payload.
#
# When the action is used on a `pull_request` event without explicit inputs
# we fill base from `pull_request.base.sha` and head from
# `pull_request.head.sha` (immutable shas, not symbolic refs). On a push
# we fall back to GITHUB_SHA for head and require the caller to supply
# base explicitly. On any other event without explicit inputs we error
# out cleanly with `::error::` so the workflow log shows the cause.
#
# Outputs (written to $GITHUB_OUTPUT):
#   base_ref=<sha>
#   head_ref=<sha>
set -euo pipefail

base_ref="${INPUT_BASE_REF:-}"
head_ref="${INPUT_HEAD_REF:-}"

event_name="${GITHUB_EVENT_NAME:-}"
event_path="${GITHUB_EVENT_PATH:-}"

if [[ -z "$base_ref" && "$event_name" == "pull_request" && -n "$event_path" && -f "$event_path" ]]; then
  base_ref="$(jq -r '.pull_request.base.sha // empty' "$event_path")"
fi

if [[ -z "$head_ref" ]]; then
  if [[ "$event_name" == "pull_request" && -n "$event_path" && -f "$event_path" ]]; then
    head_ref="$(jq -r '.pull_request.head.sha // empty' "$event_path")"
  else
    head_ref="${GITHUB_SHA:-HEAD}"
  fi
fi

if [[ -z "$base_ref" || -z "$head_ref" ]]; then
  echo "::error::base-ref and head-ref could not be resolved (provide them explicitly when not running on pull_request)"
  exit 2
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "base_ref=$base_ref"
    echo "head_ref=$head_ref"
  } >> "$GITHUB_OUTPUT"
fi

echo "Resolved base=$base_ref head=$head_ref"
