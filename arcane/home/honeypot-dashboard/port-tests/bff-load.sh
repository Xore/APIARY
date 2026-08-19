#!/bin/bash
# #1616 load-test gate: cluster mode actually forks workers, and the BFF
# sheds load under contention (SSE fan-out + burst navigation) instead of
# hanging, 500ing, or crashing. Slower and noisier than the smoke suite,
# so it's not in port-tests' default sweep — run it explicitly:
#   bash port-tests/bff-load.sh
# SKIP_FE_BUILD=1 reuses the last vite build.
source "$(dirname "$0")/lib.sh"
require_es
start_backend

# --- 1. cluster mode: WEB_CONCURRENCY workers actually come up and serve
# behind the shared port. ---
CLUSTER_PORT=$((FE_PORT + 1))
if [ "${SKIP_FE_BUILD:-0}" != "1" ]; then
  (cd "$FRONTEND_DIR" && npm run build >"${TMPDIR:-/tmp}/port-tests-febuild.log" 2>&1) || {
    echo "FATAL: frontend build failed" >&2
    exit 1
  }
fi
# setsid, not a plain `&`: this script runs non-interactively, so it has
# no job control, and a plain background job stays in *this script's own*
# process group rather than getting a fresh one — a `kill -PGID` cleanup
# below would then take out the script itself along with the cluster
# processes (lib.sh's stop_all sidesteps this differently, by killing a
# specific tracked PID/port rather than a group; that doesn't reach
# cluster.fork()'s workers here, which is the whole reason for the group
# kill in the first place). setsid gives the primary — and everything it
# forks, since children inherit their parent's group — its own session,
# so it can be killed as a unit without collateral damage.
(cd "$FRONTEND_DIR" && setsid env OIDC_DISABLED=1 BACKEND_URL="$BE_URL" PORT="$CLUSTER_PORT" WEB_CONCURRENCY=3 \
  node server/cluster.mjs >"${TMPDIR:-/tmp}/port-tests-cluster.log" 2>&1) &
for _ in $(seq 1 30); do
  curl -sf --max-time 2 "http://127.0.0.1:$CLUSTER_PORT/static/theme.css" >/dev/null 2>&1 && break
  sleep 1
done
check_http "cluster mode: serves behind shared port" 200 "http://127.0.0.1:$CLUSTER_PORT/static/theme.css"
check "cluster mode: 3 workers forked" bash -c \
  "[ \$(grep -c '^\[cluster\] primary .* starting 3 workers' '${TMPDIR:-/tmp}/port-tests-cluster.log') = 1 ]"
# Found via the port (exclusively this test's own listener, never another
# job's process on this shared box), then resolved to its setsid-issued
# PGID so the signal reaches the primary and all 3 workers in one shot.
cluster_pgid() {
  local pid
  pid=$(fuser "$CLUSTER_PORT/tcp" 2>/dev/null | awk '{print $1}')
  [ -n "$pid" ] && ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' '
}
pgid=$(cluster_pgid)
[ -n "$pgid" ] && kill -TERM "-$pgid" 2>/dev/null
sleep 6
pgid=$(cluster_pgid)
[ -n "$pgid" ] && kill -KILL "-$pgid" 2>/dev/null
sleep 1

# --- 2. backpressure under contention: tight per-route/backend caps so
# the burst below is guaranteed to exceed them, then SSE fan-out + burst
# navigation run concurrently. ---
start_frontend BACKEND_MAX_INFLIGHT=6 BACKEND_MAX_QUEUE=6 LIVE_MAX_STREAMS=8

LOAD_DIR="${TMPDIR:-/tmp}/bff-load-$$"
mkdir -p "$LOAD_DIR"
rm -f "$LOAD_DIR"/sse-* "$LOAD_DIR"/nav-*

# Collected so the `wait` below can name them explicitly — a bare `wait`
# would also block on start_backend/start_frontend's own background jobs
# (the servers themselves, tracked as _BE_PID/_FE_PID in this same shell),
# which run for the rest of the script and would never exit on their own.
PIDS=()

# 12 concurrent SSE opens against an 8-stream cap: most of the first 8
# must stream real bytes, the rest must shed with 503 (not hang, not
# 500). --max-time is generous (this is a real ES-backed event stream —
# under concurrent load with the nav burst below, first-byte latency
# isn't the thing being tested here, admission is) and the "most" below
# tolerates a couple of admitted streams losing that first-byte race
# without treating it as a shedding failure.
for i in $(seq 1 12); do
  (curl -s -o "$LOAD_DIR/sse-$i.body" -w '%{http_code}\n' --max-time 12 -N "$FE_URL/api/live" >"$LOAD_DIR/sse-$i.code") &
  PIDS+=("$!")
done

# Burst navigation concurrently with the SSE fan-out above: real
# operator load doesn't wait for a quiet moment. Timed so a starved event
# loop (or a leaked limiter slot) shows up as latency, not just a status
# code.
ROUTES=(/ /events /ips /campaigns /api/chart/os-distribution /api/chart/ml-backlog /api/chart/netflow-bytes /api/chart/anomaly-trend)
for i in $(seq 1 40); do
  route="${ROUTES[$((i % ${#ROUTES[@]}))]}"
  (
    t0=$(date +%s%N)
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$FE_URL$route")
    t1=$(date +%s%N)
    echo "$code $(((t1 - t0) / 1000000))" >"$LOAD_DIR/nav-$i.result"
  ) &
  PIDS+=("$!")
done
wait "${PIDS[@]}"

check "sse fan-out: most of the 8-stream cap admitted and streamed bytes" bash -c \
  "n=0; for f in '$LOAD_DIR'/sse-*.body; do [ -s \"\$f\" ] && n=\$((n + 1)); done; [ \"\$n\" -ge 6 ]"
check "sse fan-out: excess streams shed with 503, not a hang/500" bash -c \
  "grep -l 503 '$LOAD_DIR'/sse-*.code >/dev/null 2>&1"

python3 - "$LOAD_DIR" <<'PYEOF'
import glob
import sys

load_dir = sys.argv[1]
codes = []
latencies = []
for path in glob.glob(f"{load_dir}/nav-*.result"):
    with open(path) as f:
        code, ms = f.read().split()
        codes.append(code)
        latencies.append(int(ms))

# 503 is this tier's own admission control shedding a request outright;
# 502 is a chart proxy correctly reporting "the Rust tier didn't answer"
# once BACKEND_MAX_INFLIGHT=6 lets a request through but the tight cap
# leaves the (single dev-mode, real-ES-over-a-tunnel) backend genuinely
# unable to keep up — graceful degradation either way. Only an unhandled
# 500 (a crash bubbling out, not a deliberate error response) fails this.
bad = [c for c in codes if not (c.startswith("2") or c in ("502", "503", "504"))]
latencies.sort()
p50 = latencies[len(latencies) // 2] if latencies else -1
p99 = latencies[int(len(latencies) * 0.99)] if latencies else -1
print(f"nav burst: {len(codes)} requests, p50={p50}ms p99={p99}ms, unexpected codes={bad}")

ok = len(codes) == 40 and not bad and p99 < 8000
print("PASS" if ok else "FAIL", "nav burst: no 500s/hangs, p99 under 8s")
sys.exit(0 if ok else 1)
PYEOF
if [ $? -eq 0 ]; then
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
fi

check_http "server survives the burst (still healthy)" 200 "$FE_URL/static/theme.css"

rm -rf "$LOAD_DIR"
summary
