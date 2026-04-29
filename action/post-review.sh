#!/usr/bin/env bash
# Submit/update inline review comments on a PR via the GitHub Reviews API.
#
# v0.4.0 wedge: per-file/per-line review comments. The IR2 fingerprint
# marker (`<!-- securescan:fp:<12-hex> -->`) embedded by the IR4 renderer
# in each comment body is the upsert key. On each re-run we look up the
# PR's existing review comments, then partition the latest review.json
# comments into:
#   - PATCH (fingerprint already present -- preserves reviewer threads)
#   - POST  (new fingerprint, posted as part of the new review)
# Existing comments whose fingerprint has DISAPPEARED from the latest
# payload get a PATCH that PREPENDS "Resolved in <sha>" + a strikethrough
# of the original body. We deliberately do NOT call the GraphQL
# `resolveReviewThread` mutation: that is a thread-level state reviewers
# expect to control manually.
#
# Defensive contract: every error path is `::warning::` + exit 0. The
# action SHALL NOT fail because comment posting hit a snag; that would
# block CI on a non-essential side-effect.
#
# No `gh` CLI: raw curl + jq so the action runs on minimal self-hosted
# runners. Pagination capped at 5 pages * 100 = 500 comments. Beyond
# that the action degrades to "new comments only" -- a tolerable outcome
# for the rare PR with that many existing review comments.
set -euo pipefail

MARKER_FP_PREFIX="<!-- securescan:fp:"
MARKER_RESOLVED_PREFIX="**Resolved in "

EVENT_PATH="${GITHUB_EVENT_PATH:-}"
WORKSPACE="${GITHUB_WORKSPACE:-$PWD}"
REVIEW_FILE="${INPUT_REVIEW_FILE:-${WORKSPACE}/.securescan/review.json}"
api_root="${GITHUB_API_URL:-https://api.github.com}"
repo="${GITHUB_REPOSITORY:-}"
token="${INPUT_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"

# ---- defensive guards -----------------------------------------------------

if [[ -z "$EVENT_PATH" || ! -f "$EVENT_PATH" ]]; then
  echo "::warning::no GITHUB_EVENT_PATH; skipping inline review submission"
  exit 0
fi

pr_number="$(jq -r '.pull_request.number // .number // empty' "$EVENT_PATH" 2>/dev/null || true)"
if [[ -z "$pr_number" || "$pr_number" == "null" ]]; then
  echo "::warning::could not resolve PR number; skipping inline review submission"
  exit 0
fi

if [[ -z "$token" ]]; then
  echo "::warning::no GITHUB_TOKEN available; skipping inline review submission"
  exit 0
fi

if [[ -z "$repo" ]]; then
  echo "::warning::GITHUB_REPOSITORY not set; skipping inline review submission"
  exit 0
fi

if [[ ! -s "$REVIEW_FILE" ]]; then
  echo "::warning::no review payload at $REVIEW_FILE; skipping inline review submission"
  exit 0
fi

if ! jq -e . "$REVIEW_FILE" > /dev/null 2>&1; then
  echo "::warning::review payload at $REVIEW_FILE is not valid JSON; skipping"
  exit 0
fi

commit_id="$(jq -r '.commit_id // empty' "$REVIEW_FILE")"
if [[ -z "$commit_id" ]]; then
  echo "::warning::review payload missing commit_id; skipping inline review submission"
  exit 0
fi

short_sha="${commit_id:0:7}"
review_event="$(jq -r '.event // "COMMENT"' "$REVIEW_FILE")"
review_body="$(jq -r '.body // ""' "$REVIEW_FILE")"

curl_common=(
  -fsSL
  --retry 3 --retry-delay 2
  -H "Authorization: Bearer ${token}"
  -H 'Accept: application/vnd.github+json'
  -H 'X-GitHub-Api-Version: 2022-11-28'
)

# ---- 1. list existing review comments (paginated, cap 5 * 100) -----------

echo "::group::SecureScan: list existing review comments"
existing_all="[]"
for page in 1 2 3 4 5; do
  resp="$(curl "${curl_common[@]}" \
    "${api_root}/repos/${repo}/pulls/${pr_number}/comments?per_page=100&page=${page}" \
    2>/dev/null || echo '[]')"
  if ! echo "$resp" | jq -e 'type == "array"' > /dev/null 2>&1; then
    echo "::warning::list comments page ${page} returned non-array; stopping pagination"
    break
  fi
  count="$(echo "$resp" | jq 'length')"
  existing_all="$(jq -nc --argjson a "$existing_all" --argjson b "$resp" '$a + $b')"
  echo "page ${page}: ${count} comments"
  if [[ "$count" -lt 100 ]]; then
    break
  fi
done
echo "::endgroup::"

# Filter to securescan-marked comments and extract fingerprints.
existing_marked="$(echo "$existing_all" | jq -c '
  [ .[]
    | select((.body // "") | test("<!-- securescan:fp:[0-9a-fA-F]+ -->"; "i"))
    | { fp: ((.body // "")
            | capture("<!-- securescan:fp:(?<fp>[0-9a-fA-F]+) -->"; "i").fp
            | ascii_downcase),
        id: .id,
        body: (.body // "") } ]
')"
existing_fp_count="$(echo "$existing_marked" | jq 'length')"
echo "existing securescan-marked comments: ${existing_fp_count}"

# ---- 2. partition review.json comments into PATCH and POST buckets -------

new_comments_input="$(jq -c '.comments // []' "$REVIEW_FILE")"

# Map fp -> {id, body} for existing.
existing_fp_map="$(echo "$existing_marked" | jq -c '
  reduce .[] as $i ({}; .[$i.fp] = { id: $i.id, body: $i.body })
')"

# Set of fingerprints present in current review payload comments.
current_fp_set="$(echo "$new_comments_input" | jq -c '
  [ .[]
    | (.body // "")
    | select(test("<!-- securescan:fp:[0-9a-fA-F]+ -->"; "i"))
    | capture("<!-- securescan:fp:(?<fp>[0-9a-fA-F]+) -->"; "i").fp
    | ascii_downcase ]
')"

# PATCH list: comments in new payload whose fp already has an existing comment.
patch_list="$(jq -nc \
  --argjson comments "$new_comments_input" \
  --argjson map "$existing_fp_map" '
  [ $comments[]
    | . as $c
    | (.body // "") as $b
    | select($b | test("<!-- securescan:fp:[0-9a-fA-F]+ -->"; "i"))
    | ($b | capture("<!-- securescan:fp:(?<fp>[0-9a-fA-F]+) -->"; "i").fp | ascii_downcase) as $fp
    | $map[$fp] as $existing
    | select($existing != null)
    | { id: $existing.id, body: $c.body } ]
')"

# POST list: comments in new payload whose fp is NOT in existing map (or no fp at all).
new_post_list="$(jq -nc \
  --argjson comments "$new_comments_input" \
  --argjson map "$existing_fp_map" '
  [ $comments[]
    | . as $c
    | (.body // "") as $b
    | (if ($b | test("<!-- securescan:fp:[0-9a-fA-F]+ -->"; "i"))
       then ($b | capture("<!-- securescan:fp:(?<fp>[0-9a-fA-F]+) -->"; "i").fp | ascii_downcase)
       else null end) as $fp
    | if $fp == null then $c
      elif ($map[$fp] // null) != null then empty
      else $c end ]
')"

# RESOLVE list: existing securescan-marked comments whose fp is no longer in the payload.
resolve_list="$(jq -nc \
  --argjson existing "$existing_marked" \
  --argjson current "$current_fp_set" '
  ($current | map(. as $f | {key: $f, value: true}) | from_entries) as $cur
  | [ $existing[] | select($cur[.fp] == null) ]
')"

patch_count="$(echo "$patch_list" | jq 'length')"
post_count="$(echo "$new_post_list" | jq 'length')"
resolve_count="$(echo "$resolve_list" | jq 'length')"

# ---- 3. PATCH existing-still-present comments ----------------------------

echo "::group::SecureScan: PATCH still-present comments (${patch_count})"
patched=0
i=0
while [[ "$i" -lt "$patch_count" ]]; do
  cid="$(echo "$patch_list" | jq -r ".[$i].id")"
  body="$(echo "$patch_list" | jq -r ".[$i].body")"
  payload="$(jq -nc --arg b "$body" '{body: $b}')"
  if curl "${curl_common[@]}" -X PATCH \
      -H 'Content-Type: application/json' \
      -d "$payload" \
      "${api_root}/repos/${repo}/pulls/comments/${cid}" > /dev/null 2>&1; then
    patched=$((patched + 1))
  else
    echo "::warning::failed to PATCH comment ${cid}"
  fi
  i=$((i + 1))
done
echo "patched ${patched}/${patch_count}"
echo "::endgroup::"

# ---- 4. mark resolved findings (prepend header + strikethrough body) -----

echo "::group::SecureScan: mark resolved findings (${resolve_count})"
resolved=0
i=0
while [[ "$i" -lt "$resolve_count" ]]; do
  cid="$(echo "$resolve_list" | jq -r ".[$i].id")"
  orig="$(echo "$resolve_list" | jq -r ".[$i].body")"
  if [[ "$orig" == "${MARKER_RESOLVED_PREFIX}"* ]]; then
    echo "comment ${cid} already marked resolved; skipping"
    i=$((i + 1))
    continue
  fi
  new_body="$(printf '%s' "$orig" | jq -Rsr --arg sha "$short_sha" '
    "**Resolved in " + $sha + "** \u2014 finding no longer present in current scan.\n\n" +
    (split("\n") | map(
      if test("^\\s*$") then .
      elif test("^<!-- securescan:") then .
      else "~~" + . + "~~"
      end
    ) | join("\n"))
  ')"
  payload="$(jq -nc --arg b "$new_body" '{body: $b}')"
  if curl "${curl_common[@]}" -X PATCH \
      -H 'Content-Type: application/json' \
      -d "$payload" \
      "${api_root}/repos/${repo}/pulls/comments/${cid}" > /dev/null 2>&1; then
    resolved=$((resolved + 1))
  else
    echo "::warning::failed to PATCH (resolve) comment ${cid}"
  fi
  i=$((i + 1))
done
echo "marked-resolved ${resolved}/${resolve_count}"
echo "::endgroup::"

# ---- 5. submit review with new inline comments ---------------------------

echo "::group::SecureScan: submit review (${post_count} new inline comment(s))"

if [[ "$post_count" -eq 0 && -z "$review_body" ]]; then
  echo "no new inline comments and empty review body; skipping review submission"
  echo "::endgroup::"
  echo "summary: created=0 patched=${patched} marked-resolved=${resolved}"
  exit 0
fi

review_payload="$(jq -nc \
  --arg cid "$commit_id" \
  --arg ev "$review_event" \
  --arg body "$review_body" \
  --argjson comments "$new_post_list" '
  { commit_id: $cid, event: $ev, body: $body, comments: $comments }
')"

created=0
if curl "${curl_common[@]}" -X POST \
    -H 'Content-Type: application/json' \
    -d "$review_payload" \
    "${api_root}/repos/${repo}/pulls/${pr_number}/reviews" > /dev/null 2>&1; then
  created="$post_count"
  echo "submitted review with ${post_count} new inline comment(s)"
else
  echo "::warning::failed to submit review"
fi
echo "::endgroup::"

echo "summary: created=${created} patched=${patched} marked-resolved=${resolved}"
