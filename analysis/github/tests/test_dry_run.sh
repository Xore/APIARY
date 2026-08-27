#!/usr/bin/env bash
# test_dry_run.sh — proves the one property this whole feature depends on:
# with GITHUB_PUBLISH_ENABLED unset (or 0), a request produces a dry_run
# result and publish-sample.sh — the only thing that can commit, zip, or
# push — is never invoked. Per WORK-LEDGER.md rule 7, this must be a test,
# not a convention. No network access, no real git remote, no GH_PAT.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: $*"; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Pin the env-file path into the sandbox. The production scripts source
# ${GITHUB_ANALYSIS_ENV_FILE:-/etc/honeypot-github.env} whenever the file
# exists, and this suite's CI lane runs on the real homeserver runner
# (#2389), which legitimately has /etc/honeypot-github.env installed --
# sourcing it would override these hermetic exports with live host state
# (GH_PAT, GITHUB_REPO, real dirs). The old refuse-guard closed that leak
# by refusing to run on any host carrying the file, which made this test
# permanently red on the very runner it is routed to (#2461). Pointing the
# variable at an empty fixture inside $work closes the same leak
# deterministically instead: nothing host-owned can ever be sourced.
: >"$work/host-env"
export GITHUB_ANALYSIS_ENV_FILE="$work/host-env"

export GITHUB_ANALYSIS_REQUEST_DIR="$work/requests/pending"
export GITHUB_ANALYSIS_RESULTS_DIR="$work/results"
export GITHUB_ANALYSIS_PENDING_DIR="$work/pending"
export GITHUB_ANALYSIS_LOCK="$work/publish.lock"
export COWRIE_DOWNLOADS_DIR="$work/cowrie-downloads"
export GITHUB_ANALYSIS_DAILY_CAP=20
unset GITHUB_PUBLISH_ENABLED

install -d -m 0700 "$GITHUB_ANALYSIS_REQUEST_DIR" "$GITHUB_ANALYSIS_RESULTS_DIR" "$COWRIE_DOWNLOADS_DIR"

# A stub publish-sample.sh that would leave unmistakable evidence if the
# dry-run gate ever failed to short-circuit before reaching it. Runs from a
# copy of process-github-requests.sh alongside the stub, not the real one --
# the script resolves its sibling scripts by its own directory
# (${BASH_SOURCE[0]}), not $PATH, so this is what makes the stub take effect.
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

sample_content="APIARY github-analysis dry-run fixture, not a real sample"
sample_path="$COWRIE_DOWNLOADS_DIR/fixture"
printf '%s' "$sample_content" >"$sample_path"
hash=$(sha256sum "$sample_path" | cut -d' ' -f1)
mv "$sample_path" "$COWRIE_DOWNLOADS_DIR/$hash"

: >"$GITHUB_ANALYSIS_REQUEST_DIR/$hash.request"

"$bin/process-github-requests.sh"

[[ ! -e "$GITHUB_ANALYSIS_REQUEST_DIR/$hash.request" ]] || fail "request marker was not consumed"
pass "request marker consumed"

result="$GITHUB_ANALYSIS_RESULTS_DIR/$hash.json"
[[ -f $result ]] || fail "no result record written for $hash"
pass "result record written"

status=$(jq -r '.exit_status' "$result")
[[ $status == dry_run ]] || fail "exit_status was '$status', want dry_run"
pass "exit_status is dry_run"

[[ ! -e "$work/PUBLISH_SAMPLE_WAS_CALLED" ]] || fail "publish-sample.sh was invoked despite GITHUB_PUBLISH_ENABLED being unset"
pass "publish-sample.sh was never invoked"

shopt -s nullglob
pending_records=("$GITHUB_ANALYSIS_PENDING_DIR"/*.pending)
shopt -u nullglob
[[ ${#pending_records[@]} -eq 0 ]] || fail "a .pending record exists; only a real publish writes one"
pass "no .pending record exists"

echo "OK: dry-run default holds"
