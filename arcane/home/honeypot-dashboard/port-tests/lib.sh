#!/bin/bash
# Shared harness for the modernization-port smoke suite (#1608/#1610).
# Every script sources this. Requirements:
#   - an Elasticsearch tunnel or endpoint (default http://127.0.0.1:19200;
#     on the devbox: ssh -N -L 19200:172.16.1.12:9200 xore@$HOMESERVER_HOST)
#   - rust toolchain (cargo) and node 22+ / npm
# Overridables: ES_URL, BE_PORT, FE_PORT.
set -u

PORT_TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD_DIR="$(dirname "$PORT_TESTS_DIR")"
BACKEND_DIR="$DASHBOARD_DIR/backend-service"
FRONTEND_DIR="$DASHBOARD_DIR/frontend-next"

ES_URL="${ES_URL:-http://127.0.0.1:19200}"
BE_PORT="${BE_PORT:-18081}"
FE_PORT="${FE_PORT:-14173}"
BE_URL="http://127.0.0.1:$BE_PORT"
FE_URL="http://127.0.0.1:$FE_PORT"

export PATH="$HOME/.cargo/bin:$PATH"

_BE_PID=""
_FE_PID=""

require_es() {
  curl -sf --max-time 5 "$ES_URL" >/dev/null || {
    echo "FATAL: Elasticsearch not reachable at $ES_URL (start the tunnel?)" >&2
    exit 1
  }
}

start_backend() {
  ensure_ports_free
  # Extra env for worker-loop tests can be passed as arguments (VAR=val).
  # Defaults first, caller args last so they can override.
  # APIARY_ALLOW_UNAUTH_DEV=1 (#2183): this harness is exactly the sanctioned
  # dev case — a tokenless local boot that is meant to serve anything on
  # loopback. Without it the tier refuses to start with [E-SERVICE-TOKEN].
  (cd "$BACKEND_DIR" && env \
    ELASTICSEARCH_URL="$ES_URL" LISTEN_ADDR="127.0.0.1:$BE_PORT" \
    APIARY_ALLOW_UNAUTH_DEV=1 "$@" \
    cargo run -q >"${TMPDIR:-/tmp}/port-tests-backend.log" 2>&1) &
  _BE_PID=$!
  for _ in $(seq 1 60); do
    curl -sf "$BE_URL/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "FATAL: backend did not become healthy; log tail:" >&2
  tail -5 "${TMPDIR:-/tmp}/port-tests-backend.log" >&2
  exit 1
}

# Builds the frontend unless SKIP_FE_BUILD=1 (reuse the last .output).
start_frontend() {
  if [ "${SKIP_FE_BUILD:-0}" != "1" ]; then
    (cd "$FRONTEND_DIR" && npm run build >"${TMPDIR:-/tmp}/port-tests-febuild.log" 2>&1) || {
      echo "FATAL: frontend build failed; log tail:" >&2
      tail -20 "${TMPDIR:-/tmp}/port-tests-febuild.log" >&2
      exit 1
    }
  fi
  # Defaults first, caller args last so they can override (auth-flow.sh
  # passes OIDC_DISABLED=0).
  (cd "$FRONTEND_DIR" && env \
    OIDC_DISABLED=1 BACKEND_URL="$BE_URL" PORT="$FE_PORT" \
    APIARY_ALLOW_UNAUTH_DEV=1 "$@" \
    node .output/server/index.mjs >"${TMPDIR:-/tmp}/port-tests-frontend.log" 2>&1) &
  _FE_PID=$!
  for _ in $(seq 1 30); do
    curl -sf "$FE_URL/static/theme.css" >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "FATAL: frontend did not come up; log tail:" >&2
  tail -5 "${TMPDIR:-/tmp}/port-tests-frontend.log" >&2
  exit 1
}

stop_all() {
  # The subshell PID isn't enough — cargo/node spawn children of their
  # own, and a survivor on the port makes the NEXT script silently test
  # a stale server. Kill by listening port, which is unambiguous.
  [ -n "$_BE_PID" ] && kill "$_BE_PID" 2>/dev/null
  [ -n "$_FE_PID" ] && kill "$_FE_PID" 2>/dev/null
  fuser -k -TERM "$BE_PORT/tcp" "$FE_PORT/tcp" 2>/dev/null
  wait 2>/dev/null
  sleep 1
}
trap stop_all EXIT

# Refuse to start over a survivor from a previous run.
ensure_ports_free() {
  if curl -sf --max-time 2 "$BE_URL/healthz" >/dev/null 2>&1 || \
     curl -sf --max-time 2 "$FE_URL/static/theme.css" >/dev/null 2>&1; then
    echo "stale test server found on $BE_PORT/$FE_PORT — killing it" >&2
    fuser -k -TERM "$BE_PORT/tcp" "$FE_PORT/tcp" 2>/dev/null
    sleep 2
  fi
}

PASS=0
FAIL=0

check() { # check <label> <command...>
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "PASS  $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $label" >&2
    FAIL=$((FAIL + 1))
  fi
}

check_http() { # check_http <label> <expected-code> <url>
  local label="$1" expected="$2" url="$3"
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 90 "$url")
  if [ "$code" = "$expected" ]; then
    echo "PASS  $label ($code)"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $label (got $code, want $expected)" >&2
    FAIL=$((FAIL + 1))
  fi
}

check_json() { # check_json <label> <url> <python-expr over parsed d>
  local label="$1" url="$2" expr="$3"
  if curl -s --max-time 90 "$url" | python3 -c "import sys,json; d=json.load(sys.stdin); assert ($expr), 'assertion failed'" 2>/dev/null; then
    echo "PASS  $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL  $label ($expr)" >&2
    FAIL=$((FAIL + 1))
  fi
}

summary() {
  echo "----"
  echo "passed=$PASS failed=$FAIL"
  [ "$FAIL" -eq 0 ]
}
