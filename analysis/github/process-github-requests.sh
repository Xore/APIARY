#!/usr/bin/env bash
# process-github-requests.sh — validate, gate, and dispatch dashboard requests
# to publish a captured sample to Xore/honeypot.
#
# Structurally mirrors sandbox/process-web-requests.sh: a flock guard, a
# pending/rejected split, drain-to-empty. The extra gates below (dry-run,
# denylist, daily cap) exist because this spool's worker publishes to a
# public repository and third-party scanners, not a disposable local VM --
# see docs/github-analysis-integration-roadmap.md section 3.
#
# Every request gets a disposition: rejected (malformed/unresolvable, not a
# sample the pipeline could have scored), or a result record in
# GITHUB_ANALYSIS_RESULTS_DIR (dry_run, denylist_blocked, quota_exceeded, or
# -- real mode only -- handed to publish-sample.sh, which itself writes the
# .pending record collect-results.py polls). A request is never silently
# dropped.
set -euo pipefail

env_file=${GITHUB_ANALYSIS_ENV_FILE:-/etc/honeypot-github.env}
# shellcheck disable=SC1090
[[ -f $env_file ]] && source "$env_file"

GITHUB_PUBLISH_ENABLED=${GITHUB_PUBLISH_ENABLED:-0}
GITHUB_ANALYSIS_REQUEST_DIR=${GITHUB_ANALYSIS_REQUEST_DIR:-/var/lib/honeypot-github/requests/pending}
GITHUB_ANALYSIS_RESULTS_DIR=${GITHUB_ANALYSIS_RESULTS_DIR:-/var/lib/honeypot-github/results}
GITHUB_ANALYSIS_DAILY_CAP=${GITHUB_ANALYSIS_DAILY_CAP:-20}
GITHUB_ANALYSIS_DENYLIST_STRINGS=${GITHUB_ANALYSIS_DENYLIST_STRINGS:-}
GITHUB_ANALYSIS_DENYLIST_SOURCE_CIDRS=${GITHUB_ANALYSIS_DENYLIST_SOURCE_CIDRS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8}
GITHUB_ANALYSIS_LOCK=${GITHUB_ANALYSIS_LOCK:-/run/lock/honeypot-github-publish.lock}
# Where publish-sample.sh records a real publication awaiting Actions
# results, distinct from $GITHUB_ANALYSIS_REQUEST_DIR (incoming .request
# markers) despite the similar name -- an explicit variable here on purpose,
# after a dirname-based derivation quietly computed the same path as the
# request spool itself in an earlier version of this script.
GITHUB_ANALYSIS_PENDING_DIR=${GITHUB_ANALYSIS_PENDING_DIR:-/var/lib/honeypot-github/pending}

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
pending="$GITHUB_ANALYSIS_REQUEST_DIR"
rejected="$(dirname "$pending")/rejected"
results="$GITHUB_ANALYSIS_RESULTS_DIR"
# -o/-g root only when actually root: the installed systemd unit always is,
# but a test run as an ordinary user needs to create these under a temp dir
# it owns rather than fail outright chown'ing to a user it isn't.
owner_args=()
[[ $EUID -eq 0 ]] && owner_args=(-o root -g root)
install -d -m 0700 "${owner_args[@]}" "$pending" "$rejected" "$results" "$GITHUB_ANALYSIS_PENDING_DIR"
export GITHUB_ANALYSIS_PENDING_DIR

exec 9>"$GITHUB_ANALYSIS_LOCK"
flock -n 9 || exit 0

now() { date -u +%FT%TZ; }
today() { date -u +%F; }

write_result() {
  # write_result <sha256> <exit_status> [extra JSON fields already comma-joined]
  local sha=$1 status=$2 extra=${3:-}
  local tmp="$results/.$sha.json.tmp"
  {
    printf '{"version":1,"sha256":"%s","requested_at":"%s","completed_at":"%s","exit_status":"%s"' \
      "$sha" "$requested_at" "$(now)" "$status"
    [[ -z $extra ]] || printf ',%s' "$extra"
    printf '}\n'
  } >"$tmp"
  chmod 0600 "$tmp"
  mv -f "$tmp" "$results/$sha.json"
}

# Count today's real (non-dry-run) publishes by reading the .pending records
# publish-sample.sh writes on success -- the same count collect-results.py
# will eventually resolve, so there is exactly one source of truth for "how
# many did we push today", not a separate counter that can drift from it.
publishes_today() {
  local count=0 f requested
  shopt -s nullglob
  for f in "$GITHUB_ANALYSIS_PENDING_DIR"/*.pending; do
    requested=$(jq -r '.requested_at // empty' "$f" 2>/dev/null || true)
    [[ ${requested:0:10} == "$(today)" ]] && ((count++))
  done
  shopt -u nullglob
  printf '%s\n' "$count"
}

published_this_drain=0

shopt -s nullglob
while true; do
  requests=("$pending"/*.request)
  ((${#requests[@]})) || break
  for request in "${requests[@]}"; do
    name=$(basename "$request")
    sha=${name%.request}
    requested_at=$(now)

    # 32-64 hex, matching dashboard's own hashName -- not 64-only. Dionaea's
    # binaries/ is MD5-keyed; see resolve-sample.sh's header for why.
    if [[ ! $sha =~ ^[0-9a-fA-F]{32,64}$ ]]; then
      mv -f "$request" "$rejected/$name"
      printf 'invalid hash request at %s\n' "$requested_at" >"$rejected/$name.error"
      continue
    fi
    sha=${sha,,}

    sample=$("$script_dir/resolve-sample.sh" "$sha" 2>/dev/null || true)
    if [[ -z $sample || ! -f $sample ]]; then
      mv -f "$request" "$rejected/$name"
      printf 'no captured sample resolves to %s at %s\n' "$sha" "$requested_at" >"$rejected/$name.error"
      continue
    fi

    # Everything from here on is keyed by the sample's real content SHA-256,
    # not necessarily the request hash: a Dionaea capture was just resolved
    # by its MD5 filename above, but upstream's samples/{sha256} naming and
    # iocs/hashes.csv are SHA-256, and mixing the two hash spaces in result
    # records would make later lookups ambiguous. Same migration
    # sandbox/submit-capture.sh already does for the same reason.
    sha=$(sha256sum "$sample" | cut -d' ' -f1)

    if [[ -f $results/$sha.json ]]; then
      rm -f "$request"
      logger -t honeypot-github "already resolved, skipping: $sha"
      continue
    fi

    if [[ $GITHUB_PUBLISH_ENABLED != 1 ]]; then
      write_result "$sha" "dry_run"
      rm -f "$request"
      logger -t honeypot-github "dry-run request $sha (GITHUB_PUBLISH_ENABLED != 1)"
      continue
    fi

    if ! reason=$("$script_dir/check-denylist.sh" "$sample" "$sha" \
        "$GITHUB_ANALYSIS_DENYLIST_STRINGS" "$GITHUB_ANALYSIS_DENYLIST_SOURCE_CIDRS" 2>&1); then
      write_result "$sha" "denylist_blocked" "\"reason\":$(jq -Rn --arg r "$reason" '$r')"
      rm -f "$request"
      logger -t honeypot-github "denylist blocked $sha: $reason"
      continue
    fi

    if (( $(publishes_today) >= GITHUB_ANALYSIS_DAILY_CAP )); then
      write_result "$sha" "quota_exceeded" "\"daily_cap\":$GITHUB_ANALYSIS_DAILY_CAP"
      rm -f "$request"
      logger -t honeypot-github "quota exceeded, deferring $sha (cap=$GITHUB_ANALYSIS_DAILY_CAP)"
      continue
    fi

    if output=$("$script_dir/publish-sample.sh" "$sha" "$sample" 2>&1); then
      rm -f "$request"
      published_this_drain=1
      logger -t honeypot-github "published $sha: $output"
    else
      write_result "$sha" "error" "\"error\":$(jq -Rn --arg e "$output" '$e')"
      mv -f "$request" "$rejected/$name"
      printf '%s\n' "$output" >"$rejected/$name.error"
      logger -t honeypot-github "publish failed for $sha: $output"
    fi
  done
done

# A burst can enqueue additional jobs while the path-triggered worker is
# already active; starting the collector after the handoff closes that
# systemd path-unit race, same reasoning as the sandbox worker. Only when
# something was actually published this drain: a dry-run-only pass (the
# default, and every test run) has nothing for the collector to do, and
# systemctl reaching for a dbus that may not be running (containers, tests)
# can cost several real seconds even when the unit doesn't exist to fail
# fast against.
if [[ $published_this_drain == 1 ]]; then
  systemctl start --no-block honeypot-github-collect.service 2>/dev/null || true
fi
