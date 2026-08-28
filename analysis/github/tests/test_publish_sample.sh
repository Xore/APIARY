#!/usr/bin/env bash
# test_publish_sample.sh — publish-sample.sh actually succeeds end to end
# against a real (local, throwaway) git remote (#249). Before the fix, this
# failed on every single invocation regardless of the sample's content:
# mktemp creates its temp path as an existing empty file, and zip treats an
# existing destination as an archive to update rather than create, choking
# on the empty file with "zip error: Zip file structure invalid". A stub or
# mock of the zip step would not have caught this -- it has to actually run.
set -euo pipefail

fail() { echo "FAIL: $*"; exit 1; }
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
export GITHUB_CLONE="$work/clone"
export COWRIE_DOWNLOADS_DIR="$work/cowrie-downloads"
unset GITHUB_PUBLISH_ENABLED

install -d -m 0700 "$GITHUB_ANALYSIS_REQUEST_DIR" "$GITHUB_ANALYSIS_RESULTS_DIR" "$GITHUB_ANALYSIS_PENDING_DIR" "$COWRIE_DOWNLOADS_DIR"

# A local bare repo stands in for the real Xore/honeypot remote -- publish-sample.sh
# only ever does `git fetch`/`git reset --hard`/`git push` against whatever
# $GITHUB_CLONE's origin is, and git treats a local path exactly like any
# other remote.
bare="$work/remote.git"
git init --quiet --bare "$bare"

clone="$work/clone"
git clone --quiet "$bare" "$clone"
git -C "$clone" -c user.name=seed -c user.email=seed@localhost commit --quiet --allow-empty -m "seed"
git -C "$clone" push --quiet origin HEAD

sample="$work/sample"
printf 'APIARY github-analysis publish fixture, not a real sample\n' >"$sample"
mkdir -p "$work/cowrie-downloads"
sha256=$(sha256sum "$sample" | cut -d' ' -f1)
cp "$sample" "$work/cowrie-downloads/$sha256"

"$script_dir/publish-sample.sh" "$sha256" "$work/cowrie-downloads/$sha256"
pass "publish-sample.sh exited 0"

[[ -f "$GITHUB_ANALYSIS_PENDING_DIR/$sha256.pending" ]] || fail "no .pending record written"
pass ".pending record written"

# The pushed commit must actually contain a valid, extractable zip.
verify="$work/verify"
git clone --quiet "$bare" "$verify"
zip_path=$(find "$verify/samples" -type f -name "$sha256.zip" -print -quit)
[[ -n $zip_path ]] || fail "no $sha256.zip found in the pushed commit"
pass "pushed commit contains $sha256.zip"

unzip -tqP infected "$zip_path" || fail "pushed zip is not a valid, extractable archive"
pass "pushed zip is a valid archive"

echo "OK: publish-sample.sh produces a valid archive end to end"
