#!/usr/bin/env bash
# Self-test for post-review.sh.
#
# Stands up a tiny Python http.server that records every request to a
# log file and returns canned responses. Then runs post-review.sh
# against fixture event payloads and review.json files, asserting on
# the recorded request log. No real GitHub API call is made: keeps the
# suite fast, deterministic, and runnable in CI.
#
# Run directly:  bash action/test-post-review.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/post-review.sh"

if [[ ! -x "$SCRIPT" ]]; then
  echo "FAIL: $SCRIPT is not executable"
  exit 1
fi

if ! command -v jq > /dev/null 2>&1; then
  echo "FAIL: jq required for self-test"
  exit 1
fi

if ! command -v python3 > /dev/null 2>&1; then
  echo "FAIL: python3 required for self-test"
  exit 1
fi

WORK="$(mktemp -d)"
PID_FILE="$WORK/server.pid"
PORT_FILE="$WORK/server.port"

cleanup() {
  if [[ -s "$PID_FILE" ]]; then
    local pid
    pid="$(cat "$PID_FILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

PASS_COUNT=0
FAIL_COUNT=0

pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "PASS $*"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "FAIL $*"
}

# ---------------------------------------------------------------------------
# Mock GitHub API server (Python http.server).
# Reads its state from argv[1] (a JSON file with key "existing_comments").
# Logs every request to argv[2] as one JSON object per line:
#   {method, path, body}.
# Binds to an ephemeral port and prints the bound port to stdout.
# Written once to a temp .py file so start_mock can re-launch it cheaply.
# ---------------------------------------------------------------------------
SERVER_PY="$WORK/mock_server.py"
cat > "$SERVER_PY" <<'PY'
import http.server
import json
import sys
from urllib.parse import urlparse, parse_qs

state = json.loads(open(sys.argv[1]).read())
log_path = sys.argv[2]


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        return

    def _read_body(self):
        n = int(self.headers.get("Content-Length", "0") or "0")
        if n <= 0:
            return ""
        return self.rfile.read(n).decode("utf-8", errors="replace")

    def _record(self, body):
        with open(log_path, "a") as f:
            f.write(json.dumps({
                "method": self.command,
                "path": self.path,
                "body": body,
            }) + "\n")

    def _resp(self, status, payload):
        out = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def do_GET(self):
        body = self._read_body()
        self._record(body)
        u = urlparse(self.path)
        if "/pulls/" in u.path and u.path.endswith("/comments"):
            page = int(parse_qs(u.query).get("page", ["1"])[0])
            data = state.get("existing_comments", [])
            per_page = 100
            chunk = data[(page - 1) * per_page:page * per_page]
            self._resp(200, chunk)
        else:
            self._resp(404, {})

    def do_POST(self):
        body = self._read_body()
        self._record(body)
        if self.path.endswith("/reviews"):
            self._resp(201, {"id": 999})
        else:
            self._resp(404, {})

    def do_PATCH(self):
        body = self._read_body()
        self._record(body)
        if "/comments/" in self.path:
            try:
                cid = int(self.path.rsplit("/", 1)[-1])
            except ValueError:
                cid = 0
            self._resp(200, {"id": cid})
        else:
            self._resp(404, {})


srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
print(srv.server_address[1], flush=True)
srv.serve_forever()
PY

start_mock() {
  local state_file="$1"
  local log_file="$2"
  : > "$log_file"
  : > "$PORT_FILE"
  python3 "$SERVER_PY" "$state_file" "$log_file" > "$PORT_FILE" 2>/dev/null &
  echo $! > "$PID_FILE"
  # Wait up to ~3s for the server to bind and write its port.
  for _ in $(seq 1 60); do
    if [[ -s "$PORT_FILE" ]]; then
      break
    fi
    sleep 0.05
  done
  if [[ ! -s "$PORT_FILE" ]]; then
    echo "FATAL: mock server failed to start"
    return 1
  fi
}

stop_mock() {
  if [[ -s "$PID_FILE" ]]; then
    local pid
    pid="$(cat "$PID_FILE")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
    : > "$PID_FILE"
  fi
}

# ---------------------------------------------------------------------------
# Helpers for assertions on the request log.
# ---------------------------------------------------------------------------
log_count_method() {
  # log_count_method <log> <method>
  local log="$1" method="$2"
  if [[ ! -s "$log" ]]; then echo 0; return; fi
  jq -s --arg m "$method" 'map(select(.method == $m)) | length' "$log"
}

log_count_path_method() {
  # log_count_path_method <log> <method> <substring-of-path>
  local log="$1" method="$2" pat="$3"
  if [[ ! -s "$log" ]]; then echo 0; return; fi
  jq -s --arg m "$method" --arg p "$pat" '
    map(select(.method == $m and (.path | contains($p)))) | length
  ' "$log"
}

log_post_review_comments_length() {
  # Length of the comments[] array on the first POST /reviews call.
  local log="$1"
  jq -s '
    map(select(.method == "POST" and (.path | contains("/reviews"))))
    | first | (.body | fromjson) | (.comments | length)
  ' "$log"
}

log_first_patch_body() {
  # Decoded body of the first PATCH /comments/{id} call.
  local log="$1"
  jq -rs '
    map(select(.method == "PATCH" and (.path | contains("/comments/"))))
    | first | (.body | fromjson) | .body
  ' "$log"
}

# ---------------------------------------------------------------------------
# Fixture builder. Writes:
#   $1/event.json    (GH event payload with PR #42)
#   $1/.securescan/review.json
# Caller passes review.json contents as $2 (raw JSON string).
# ---------------------------------------------------------------------------
make_fixture() {
  local dir="$1"
  local review_json="$2"
  mkdir -p "$dir/.securescan"
  cat > "$dir/event.json" <<'EOF'
{"pull_request": {"number": 42, "head": {"sha": "deadbeefcafef00d1234567890abcdef00000000"}, "base": {"sha": "0000000000000000000000000000000000000000"}}}
EOF
  printf '%s' "$review_json" > "$dir/.securescan/review.json"
}

run_script() {
  # run_script <work-dir> <port> [--no-token] [--no-review] [--no-event]
  local dir="$1"
  local port="${2:-}"
  shift 2 || true
  local token="testtoken"
  local event_path="$dir/event.json"
  local review_file="$dir/.securescan/review.json"
  for flag in "$@"; do
    case "$flag" in
      --no-token) token="" ;;
      --no-review) review_file="$dir/.securescan/does-not-exist.json" ;;
      --no-event) event_path="$dir/missing-event.json" ;;
    esac
  done
  local api_url="http://127.0.0.1:${port}"
  GITHUB_REPOSITORY="acme/widgets" \
  GITHUB_EVENT_PATH="$event_path" \
  GITHUB_API_URL="$api_url" \
  GITHUB_TOKEN="$token" \
  GITHUB_WORKSPACE="$dir" \
  INPUT_REVIEW_FILE="$review_file" \
    bash "$SCRIPT"
}

# ---------------------------------------------------------------------------
# Common payloads. Note: the marker MUST appear in each comment body so
# the script can extract a fingerprint. Use 12 hex chars (matches IR2).
# ---------------------------------------------------------------------------
FP_A="aaaa11112222"
FP_B="bbbb33334444"
FP_C="cccc55556666"

REVIEW_TWO_NEW=$(jq -nc \
  --arg fpA "$FP_A" --arg fpB "$FP_B" '
{
  commit_id: "deadbeefcafef00d1234567890abcdef00000000",
  event: "COMMENT",
  body: "SecureScan diff review\n\n<!-- securescan:diff-review -->",
  comments: [
    {path: "src/a.py", position: 5, body: ("**HIGH** finding A\n\n<!-- securescan:fp:" + $fpA + " -->")},
    {path: "src/b.py", position: 3, body: ("**LOW** finding B\n\n<!-- securescan:fp:" + $fpB + " -->")}
  ]
}')

# ---------------------------------------------------------------------------
# Test 1: all-new comments. existing_comments empty -> POST with both;
# zero PATCH calls.
# ---------------------------------------------------------------------------
T1="$WORK/t1"
mkdir -p "$T1"
make_fixture "$T1" "$REVIEW_TWO_NEW"
T1_STATE="$T1/state.json"
T1_LOG="$T1/log.ndjson"
echo '{"existing_comments": []}' > "$T1_STATE"
start_mock "$T1_STATE" "$T1_LOG"
PORT="$(cat "$PORT_FILE")"
run_script "$T1" "$PORT" > "$T1/stdout" 2>&1 || true
stop_mock

post_reviews="$(log_count_path_method "$T1_LOG" POST /reviews)"
patches="$(log_count_path_method "$T1_LOG" PATCH /comments/)"
inline_count="$(log_post_review_comments_length "$T1_LOG")"
if [[ "$post_reviews" == "1" && "$patches" == "0" && "$inline_count" == "2" ]]; then
  pass "case 1: all-new -> 1 POST /reviews with 2 inline comments, 0 PATCH"
else
  fail "case 1: post=$post_reviews patches=$patches inline=$inline_count"
  cat "$T1/stdout"
  cat "$T1_LOG"
fi

# ---------------------------------------------------------------------------
# Test 2: idempotent re-run. Existing comments cover both fingerprints ->
# 2 PATCH calls; POST /reviews still posts a review with empty comments
# array because review body is non-empty.
# ---------------------------------------------------------------------------
T2="$WORK/t2"
mkdir -p "$T2"
make_fixture "$T2" "$REVIEW_TWO_NEW"
T2_STATE="$T2/state.json"
T2_LOG="$T2/log.ndjson"
jq -nc --arg fpA "$FP_A" --arg fpB "$FP_B" '
{
  existing_comments: [
    {id: 1001, body: ("OLD finding A\n\n<!-- securescan:fp:" + $fpA + " -->")},
    {id: 1002, body: ("OLD finding B\n\n<!-- securescan:fp:" + $fpB + " -->")}
  ]
}' > "$T2_STATE"
start_mock "$T2_STATE" "$T2_LOG"
PORT="$(cat "$PORT_FILE")"
run_script "$T2" "$PORT" > "$T2/stdout" 2>&1 || true
stop_mock

post_reviews="$(log_count_path_method "$T2_LOG" POST /reviews)"
patches="$(log_count_path_method "$T2_LOG" PATCH /comments/)"
inline_count="$(log_post_review_comments_length "$T2_LOG")"
if [[ "$post_reviews" == "1" && "$patches" == "2" && "$inline_count" == "0" ]]; then
  pass "case 2: idempotent -> 2 PATCH, POST /reviews with empty comments[]"
else
  fail "case 2: post=$post_reviews patches=$patches inline=$inline_count"
  cat "$T2/stdout"
  cat "$T2_LOG"
fi

# ---------------------------------------------------------------------------
# Test 3: mixed new + existing. Existing has only fpA; review.json has
# fpA + fpB -> 1 PATCH (fpA), POST /reviews with 1 inline (fpB).
# ---------------------------------------------------------------------------
T3="$WORK/t3"
mkdir -p "$T3"
make_fixture "$T3" "$REVIEW_TWO_NEW"
T3_STATE="$T3/state.json"
T3_LOG="$T3/log.ndjson"
jq -nc --arg fpA "$FP_A" '
{
  existing_comments: [
    {id: 2001, body: ("OLD finding A\n\n<!-- securescan:fp:" + $fpA + " -->")}
  ]
}' > "$T3_STATE"
start_mock "$T3_STATE" "$T3_LOG"
PORT="$(cat "$PORT_FILE")"
run_script "$T3" "$PORT" > "$T3/stdout" 2>&1 || true
stop_mock

post_reviews="$(log_count_path_method "$T3_LOG" POST /reviews)"
patches="$(log_count_path_method "$T3_LOG" PATCH /comments/)"
inline_count="$(log_post_review_comments_length "$T3_LOG")"
if [[ "$post_reviews" == "1" && "$patches" == "1" && "$inline_count" == "1" ]]; then
  pass "case 3: mixed -> 1 PATCH (fpA), POST with 1 inline (fpB)"
else
  fail "case 3: post=$post_reviews patches=$patches inline=$inline_count"
  cat "$T3/stdout"
  cat "$T3_LOG"
fi

# ---------------------------------------------------------------------------
# Test 4: resolved finding. Existing has fpC (NOT in review.json which
# carries fpA+fpB). The fpC comment must be PATCHed with the
# "**Resolved in <sha>**" prefix.
# ---------------------------------------------------------------------------
T4="$WORK/t4"
mkdir -p "$T4"
make_fixture "$T4" "$REVIEW_TWO_NEW"
T4_STATE="$T4/state.json"
T4_LOG="$T4/log.ndjson"
jq -nc --arg fpA "$FP_A" --arg fpB "$FP_B" --arg fpC "$FP_C" '
{
  existing_comments: [
    {id: 3001, body: ("OLD finding A\n\n<!-- securescan:fp:" + $fpA + " -->")},
    {id: 3002, body: ("OLD finding B\n\n<!-- securescan:fp:" + $fpB + " -->")},
    {id: 3003, body: ("OLD finding C\n\n<!-- securescan:fp:" + $fpC + " -->")}
  ]
}' > "$T4_STATE"
start_mock "$T4_STATE" "$T4_LOG"
PORT="$(cat "$PORT_FILE")"
run_script "$T4" "$PORT" > "$T4/stdout" 2>&1 || true
stop_mock

# Expect 3 PATCH calls: 2 for upsert (A,B) + 1 for resolve (C).
patches="$(log_count_path_method "$T4_LOG" PATCH /comments/)"
# Find PATCH bodies, count those starting with the resolved marker.
resolved_patches="$(jq -s '
  map(select(.method == "PATCH" and (.path | contains("/comments/"))))
  | map(.body | fromjson | .body)
  | map(select(startswith("**Resolved in ")))
  | length
' "$T4_LOG")"
# Verify the PATCH for /comments/3003 has the resolved prefix and includes the short SHA.
resolve_body="$(jq -rs '
  map(select(.method == "PATCH" and (.path | endswith("/comments/3003"))))
  | first | (.body | fromjson) | .body
' "$T4_LOG")"
if [[ "$patches" == "3" && "$resolved_patches" == "1" \
      && "$resolve_body" == "**Resolved in deadbee**"* \
      && "$resolve_body" == *"~~OLD finding C~~"* ]]; then
  pass "case 4: resolved -> PATCH 3003 with Resolved-prefix and strikethrough"
else
  fail "case 4: patches=$patches resolved_patches=$resolved_patches"
  echo "resolve_body: $resolve_body"
  cat "$T4/stdout"
  cat "$T4_LOG"
fi

# ---------------------------------------------------------------------------
# Test 5: missing event payload -> warn, exit 0, no API calls.
# ---------------------------------------------------------------------------
T5="$WORK/t5"
mkdir -p "$T5"
make_fixture "$T5" "$REVIEW_TWO_NEW"
T5_STATE="$T5/state.json"
T5_LOG="$T5/log.ndjson"
echo '{"existing_comments": []}' > "$T5_STATE"
start_mock "$T5_STATE" "$T5_LOG"
PORT="$(cat "$PORT_FILE")"
set +e
run_script "$T5" "$PORT" --no-event > "$T5/stdout" 2>&1
rc=$?
set -e
stop_mock
total_calls="$(jq -s 'length' "$T5_LOG" 2>/dev/null || echo 0)"
if [[ "$rc" -eq 0 && "$total_calls" == "0" ]] && grep -q '::warning::' "$T5/stdout"; then
  pass "case 5: missing event -> warn + exit 0, no API calls"
else
  fail "case 5: rc=$rc calls=$total_calls"
  cat "$T5/stdout"
fi

# ---------------------------------------------------------------------------
# Test 6: missing review.json -> warn, exit 0, no API calls.
# ---------------------------------------------------------------------------
T6="$WORK/t6"
mkdir -p "$T6"
make_fixture "$T6" "$REVIEW_TWO_NEW"
T6_STATE="$T6/state.json"
T6_LOG="$T6/log.ndjson"
echo '{"existing_comments": []}' > "$T6_STATE"
start_mock "$T6_STATE" "$T6_LOG"
PORT="$(cat "$PORT_FILE")"
set +e
run_script "$T6" "$PORT" --no-review > "$T6/stdout" 2>&1
rc=$?
set -e
stop_mock
total_calls="$(jq -s 'length' "$T6_LOG" 2>/dev/null || echo 0)"
if [[ "$rc" -eq 0 && "$total_calls" == "0" ]] && grep -q '::warning::' "$T6/stdout"; then
  pass "case 6: missing review.json -> warn + exit 0, no API calls"
else
  fail "case 6: rc=$rc calls=$total_calls"
  cat "$T6/stdout"
fi

# ---------------------------------------------------------------------------
# Test 7: missing token -> warn, exit 0, no API calls.
# ---------------------------------------------------------------------------
T7="$WORK/t7"
mkdir -p "$T7"
make_fixture "$T7" "$REVIEW_TWO_NEW"
T7_STATE="$T7/state.json"
T7_LOG="$T7/log.ndjson"
echo '{"existing_comments": []}' > "$T7_STATE"
start_mock "$T7_STATE" "$T7_LOG"
PORT="$(cat "$PORT_FILE")"
set +e
run_script "$T7" "$PORT" --no-token > "$T7/stdout" 2>&1
rc=$?
set -e
stop_mock
total_calls="$(jq -s 'length' "$T7_LOG" 2>/dev/null || echo 0)"
if [[ "$rc" -eq 0 && "$total_calls" == "0" ]] && grep -q '::warning::' "$T7/stdout"; then
  pass "case 7: missing token -> warn + exit 0, no API calls"
else
  fail "case 7: rc=$rc calls=$total_calls"
  cat "$T7/stdout"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "post-review.sh self-test: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
exit 0
