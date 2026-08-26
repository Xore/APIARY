#!/usr/bin/env bash
# test_daily_cap.sh — GITHUB_ANALYSIS_DAILY_CAP actually limits (#2081).
# Both of its breaks failed open: publishes_today() crashed under errexit
# exactly when it had its first same-day record to count (empty arithmetic
# operand read as "under cap"), and even counting correctly, the counter
# tallied live .pending records that collect-results.py deletes on every
# resolution, so each resolution handed the quota slot back. Covers
# publishes_today() directly against fixture spools (no network), then the
# armed quota_exceeded path end-to-end with stubbed siblings.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: $*"; }

[[ ! -e /etc/honeypot-github.env ]] || \
  fail "refusing to run: /etc/honeypot-github.env exists on this machine and could leak into the test"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
today=$(date -u +%F)
yesterday=$(date -u -d "yesterday" +%F)

export GITHUB_ANALYSIS_PENDING_DIR="$work/pending"
export GITHUB_ANALYSIS_RESULTS_DIR="$work/results"
results_dir="$GITHUB_ANALYSIS_RESULTS_DIR"
install -d -m 0700 "$GITHUB_ANALYSIS_PENDING_DIR" "$results_dir"

add_pending() { # add_pending <sha> <date>
  printf '{"version":1,"sha256":"%s","commit":"","requested_at":"%sT10:00:00Z","sensor":"","bucket":""}' \
    "$1" "$2" >"$GITHUB_ANALYSIS_PENDING_DIR/$1.pending"
}

add_result() { # add_result <sha> <exit_status> <completed_date>
  printf '{"version":1,"sha256":"%s","requested_at":"%sT09:00:00Z","completed_at":"%sT11:00:00Z","exit_status":"%s"}' \
    "$1" "$3" "$3" "$2" >"$results_dir/$1.json"
}

count_now() {
  # Extract publishes_today() verbatim from the script and run it under the
  # same errexit regime it lives under in production -- the entire point of
  # break 1 is that only `set -euo pipefail` exposes it.
  bash -c '
    set -euo pipefail
    today() { date -u +%F; }
    results="'"$results_dir"'"
    eval "$(sed -n "/^publishes_today()/,/^}/p" "'"$script_dir"'/process-github-requests.sh")"
    publishes_today
  '
}

check_count() { # check_count <want> <label>
  local want=$1 label=$2 got
  got=$(count_now) || fail "$label: counter exited nonzero (errexit kill?)"
  [[ $got == "$want" ]] || fail "$label: count was '$got', want '$want'"
  pass "$label"
}

# --- Empty spools count zero. ---
check_count 0 "empty spools count 0"

# --- Break 1: one same-day pending must return 1 without terminating. ---
add_pending "$(printf 'a%.0s' {1..64})" "$today"
check_count 1 "one same-day .pending counts 1 under errexit"

# --- Break 2: a resolved publication keeps consuming today's quota. ---
rm -f "$GITHUB_ANALYSIS_PENDING_DIR"/*.pending
add_result "$(printf 'b%.0s' {1..64})" ok "$today"
check_count 1 "an ok result from today counts with no pending left"

add_result "$(printf 'c%.0s' {1..64})" failed "$today"
add_result "$(printf 'd%.0s' {1..64})" timeout "$today"
check_count 3 "failed and timeout results count too -- Actions ran for them"

# --- Non-quota states never counted. ---
add_result "$(printf 'e%.0s' {1..64})" dry_run "$today"
add_result "$(printf 'f%.0s' {1..64})" quota_exceeded "$today"
add_result "$(printf 'g%.0s' {1..64})" error "$today"
check_count 3 "dry_run/quota_exceeded/error results are not counted"

# --- Other days don't count. ---
add_result "$(printf 'h%.0s' {1..64})" ok "$yesterday"
add_result "$(printf 'i%.0s' {1..64})" failed "$yesterday"
check_count 3 "yesterday's records stay out of today's count"

# --- Pending plus resolved sum. ---
add_pending "$(printf 'j%.0s' {1..64})" "$today"
check_count 4 "one unresolved publication plus three resolved = 4"

# --- Armed end-to-end: at-cap refuses with quota_exceeded and never hands
# --- off to publish-sample.sh. This fixture reproduces #2081's first break
# --- exactly: one same-day .pending exists, so the old post-increment
# --- crashed the counter and the request published right through the cap. ---
bin="$work/bin"
install -d "$bin"
cp "$script_dir/process-github-requests.sh" "$bin/"
for f in resolve-sample.sh check-denylist.sh; do
  ln -s "$script_dir/$f" "$bin/$f"
done
cat >"$bin/publish-sample.sh" <<'STUB'
#!/usr/bin/env bash
touch "$STUB_CALLED_MARKER"
exit 0
STUB
chmod +x "$bin/publish-sample.sh"
export STUB_CALLED_MARKER="$work/PUBLISH_SAMPLE_WAS_CALLED"

mkdir -p "$work/logs/cowrie"   # hermetic denylist log lookup: nothing to find
export HONEYPOT_LOGS_DIR="$work/logs"
export COWRIE_DOWNLOADS_DIR="$work/cowrie-downloads"
export GITHUB_ANALYSIS_REQUEST_DIR="$work/requests/pending"
export GITHUB_ANALYSIS_LOCK="$work/publish.lock"
export GITHUB_PUBLISH_ENABLED=1
export GITHUB_ANALYSIS_DAILY_CAP=4   # the counter already reads 4 above
install -d -m 0700 "$COWRIE_DOWNLOADS_DIR" "$GITHUB_ANALYSIS_REQUEST_DIR"

sample_content="APIARY daily-cap fixture, not a real sample"
sample_path="$COWRIE_DOWNLOADS_DIR/fixture"
printf '%s' "$sample_content" >"$sample_path"
hash=$(sha256sum "$sample_path" | cut -d' ' -f1)
mv "$sample_path" "$COWRIE_DOWNLOADS_DIR/$hash"
: >"$GITHUB_ANALYSIS_REQUEST_DIR/$hash.request"

"$bin/process-github-requests.sh"

result="$results_dir/$hash.json"
[[ -f $result ]] || fail "at-cap run wrote no result record"
status=$(jq -r '.exit_status' "$result")
[[ $status == quota_exceeded ]] || fail "exit_status was '$status', want quota_exceeded"
pass "a request arriving at the cap gets a quota_exceeded result"

[[ ! -e $STUB_CALLED_MARKER ]] || fail "publish-sample.sh ran despite the cap being reached"
pass "publish-sample.sh is never invoked once the cap is reached"

echo "OK: the daily cap counts consumed quota and blocks at the limit"
