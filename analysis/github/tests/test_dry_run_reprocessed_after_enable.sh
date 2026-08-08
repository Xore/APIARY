#!/usr/bin/env bash
# test_dry_run_reprocessed_after_enable.sh — a dry-run result must not
# permanently block a hash from being published for real once
# GITHUB_PUBLISH_ENABLED flips to 1. Regression test for the "already
# resolved" short-circuit firing on a stale dry_run result before the
# publish chain ever runs again. No network access, no real git remote,
# no GH_PAT.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: $*"; }

[[ ! -e /etc/honeypot-github.env ]] || \
  fail "refusing to run: /etc/honeypot-github.env exists on this machine and could leak into the test"

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export GITHUB_ANALYSIS_REQUEST_DIR="$work/requests/pending"
export GITHUB_ANALYSIS_RESULTS_DIR="$work/results"
export GITHUB_ANALYSIS_PENDING_DIR="$work/pending"
export GITHUB_ANALYSIS_LOCK="$work/publish.lock"
export COWRIE_DOWNLOADS_DIR="$work/cowrie-downloads"
export GITHUB_ANALYSIS_DAILY_CAP=20

install -d -m 0700 "$GITHUB_ANALYSIS_REQUEST_DIR" "$GITHUB_ANALYSIS_RESULTS_DIR" "$COWRIE_DOWNLOADS_DIR"

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

sample_content="APIARY github-analysis dry-run-then-enable fixture, not a real sample"
sample_path="$COWRIE_DOWNLOADS_DIR/fixture"
printf '%s' "$sample_content" >"$sample_path"
hash=$(sha256sum "$sample_path" | cut -d' ' -f1)
mv "$sample_path" "$COWRIE_DOWNLOADS_DIR/$hash"

# First pass: disabled, produces a dry_run result -- same as test_dry_run.sh.
unset GITHUB_PUBLISH_ENABLED
: >"$GITHUB_ANALYSIS_REQUEST_DIR/$hash.request"
"$bin/process-github-requests.sh"

result="$GITHUB_ANALYSIS_RESULTS_DIR/$hash.json"
[[ -f $result ]] || fail "no result record written after first (dry-run) pass"
status=$(jq -r '.exit_status' "$result")
[[ $status == dry_run ]] || fail "exit_status was '$status' after first pass, want dry_run"
[[ ! -e "$work/PUBLISH_SAMPLE_WAS_CALLED" ]] || fail "publish-sample.sh was invoked during the dry-run pass"
pass "first pass (disabled) produced a dry_run result"

# Operator arms publishing, then the same hash is requested again -- this is
# the case that used to be silently swallowed by the stale dry_run result.
export GITHUB_PUBLISH_ENABLED=1
: >"$GITHUB_ANALYSIS_REQUEST_DIR/$hash.request"
"$bin/process-github-requests.sh"

[[ -e "$work/PUBLISH_SAMPLE_WAS_CALLED" ]] || \
  fail "publish-sample.sh was never invoked on the second pass -- the stale dry_run result blocked reprocessing"
pass "publish-sample.sh was invoked once GITHUB_PUBLISH_ENABLED=1 on re-request"

[[ ! -e "$GITHUB_ANALYSIS_REQUEST_DIR/$hash.request" ]] || fail "second request marker was not consumed"
pass "second request marker consumed"

echo "OK: a dry-run result does not permanently block real publishing"
