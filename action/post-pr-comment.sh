#!/usr/bin/env bash
# Upsert a single PR comment, identified by the SS7 marker
# `<!-- securescan:diff -->`. Uses raw curl against the GitHub REST API
# rather than `gh` CLI so the action works on minimal self-hosted runners
# that do not have `gh` installed (ubuntu-latest does, but we can't
# assume it everywhere).
#
# Behaviour:
#   - look up existing comments on the PR
#   - if any starts with the marker, PATCH it
#   - otherwise POST a new one
#   - silent no-op (warning) if the comment body is missing/empty,
#     the token is missing, or the PR number can't be resolved
set -euo pipefail

MARKER="<!-- securescan:diff -->"
EVENT_PATH="${GITHUB_EVENT_PATH:-}"
WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"
BODY_PATH="$WORKSPACE/.securescan/diff.md"

if [[ -z "$EVENT_PATH" || ! -f "$EVENT_PATH" ]]; then
  echo "::warning::no GITHUB_EVENT_PATH; skipping PR comment"
  exit 0
fi

pr_number="$(jq -r '.pull_request.number // .number // empty' "$EVENT_PATH")"
if [[ -z "$pr_number" || "$pr_number" == "null" ]]; then
  echo "::warning::could not resolve PR number; skipping comment"
  exit 0
fi

token="${INPUT_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
if [[ -z "$token" ]]; then
  echo "::warning::no GITHUB_TOKEN available; skipping PR comment"
  exit 0
fi

if [[ ! -s "$BODY_PATH" ]]; then
  echo "::warning::no diff body to post at $BODY_PATH"
  exit 0
fi
body="$(cat "$BODY_PATH")"

api_root="${GITHUB_API_URL:-https://api.github.com}"
repo="${GITHUB_REPOSITORY:-}"
if [[ -z "$repo" ]]; then
  echo "::warning::GITHUB_REPOSITORY not set; skipping PR comment"
  exit 0
fi

comments_url="${api_root}/repos/${repo}/issues/${pr_number}/comments"

existing_id="$(curl -fsSL \
  -H "Authorization: Bearer ${token}" \
  -H 'Accept: application/vnd.github+json' \
  -H 'X-GitHub-Api-Version: 2022-11-28' \
  "${comments_url}?per_page=100" \
  | jq -r --arg m "$MARKER" '[.[] | select(.body | startswith($m))] | first | .id // empty')"

payload="$(jq -nc --arg b "$body" '{body: $b}')"

if [[ -n "$existing_id" && "$existing_id" != "null" ]]; then
  curl -fsSL -X PATCH \
    -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    "${api_root}/repos/${repo}/issues/comments/${existing_id}" > /dev/null
  echo "Updated PR comment ${existing_id}"
else
  curl -fsSL -X POST \
    -H "Authorization: Bearer ${token}" \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    -H 'Content-Type: application/json' \
    -d "$payload" \
    "${comments_url}" > /dev/null
  echo "Created new PR comment on #${pr_number}"
fi
