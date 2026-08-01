#!/usr/bin/env bash
# publish-sample.sh <sha256> <sample-path> — classify, zip, commit, and push
# one sample to Xore/honeypot. Only ever invoked by process-github-requests.sh
# after the dry-run gate, denylist check, and quota check have all passed.
#
# On success, writes <sha256>.pending (commit SHA + timing) for
# collect-results.py to poll -- this script never waits on Actions itself,
# per the roadmap: polling is not the analyst's click path.
set -euo pipefail

sha256=${1:?usage: publish-sample.sh <sha256> <sample-path>}
sample=${2:?}

env_file=/etc/honeypot-github.env
# shellcheck disable=SC1090
[[ -f $env_file ]] && source "$env_file"

GITHUB_REPO=${GITHUB_REPO:-Xore/honeypot}
GITHUB_CLONE=${GITHUB_CLONE:-/var/lib/honeypot-github/repo}
pending_dir=${GITHUB_ANALYSIS_PENDING_DIR:-/var/lib/honeypot-github/pending}
owner_args=()
[[ $EUID -eq 0 ]] && owner_args=(-o root -g root)
install -d -m 0700 "${owner_args[@]}" "$pending_dir"

[[ -d $GITHUB_CLONE/.git ]] || { echo "GITHUB_CLONE ($GITHUB_CLONE) is not a git checkout -- run install-github-publisher.sh" >&2; exit 1; }
command -v zip >/dev/null || { echo "zip is required (apt-get install zip)" >&2; exit 1; }

cd "$GITHUB_CLONE"
git fetch --quiet origin
git reset --quiet --hard "origin/$(git rev-parse --abbrev-ref HEAD)"

# Upstream only scans Added/Renamed files (--diff-filter=AR); a re-push of an
# already-known hash is wasted quota and produces no new run.
if [[ -f iocs/hashes.csv ]] && grep -qi "^$sha256," iocs/hashes.csv; then
  echo "already known upstream, skipping push: $sha256"
  # Still worth a result record so the analyst sees why nothing happened,
  # but this script's job is the push; process-github-requests.sh treats a
  # zero exit here as "handled", so hand that disposition back on stdout
  # for its log line and let a later collect-results.py pass, if the hash
  # already has an upstream run, pick the result up normally.
  exit 0
fi

# 1. Classify, matching upstream's samples/{ELF,PE,Scripts,Docs,UNKNOWN}/ layout.
description=$(file -b "$sample" 2>/dev/null || echo "")
case "$description" in
  *"ELF "*) bucket=ELF ;;
  *"PE32"*|*"MS-DOS executable"*|*"MS Windows"*) bucket=PE ;;
  *"script"*|*"ASCII text"*|*"Unicode text"*) bucket=Scripts ;;
  *"PDF document"*|*"Composite Document"*|*"Microsoft"*|*"Zip archive"*) bucket=Docs ;;
  *) bucket=UNKNOWN ;;
esac
install -d -m 0755 "samples/$bucket"

# 2. Zip with the password upstream's README documents ("infected") -- the
# same convention VX-Underground/MalwareBazaar use, so anything that clones
# Xore/honeypot does not auto-quarantine or execute the sample on checkout.
# See #74's archive-convention decision.
dest="samples/$bucket/$sha256.zip"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
# mktemp creates $tmp as an existing empty file; zip treats an existing
# destination as an archive to update rather than create, and chokes on the
# empty file with "zip error: Zip file structure invalid" (#249) -- every
# invocation fails this way, regardless of the sample. Removing the empty
# placeholder first (the trap above still cleans up the reserved name if zip
# never runs) lets zip create a fresh archive instead.
rm -f "$tmp"
zip -q -j -P infected "$tmp" "$sample"
mv -f "$tmp" "$dest"
trap - EXIT
chmod 0644 "$dest"

# 3. Commit and push. sensor/date in the message, not the sample's own
# metadata, so a bad file -b guess never ends up in git history as fact.
sensor=$(basename "$(dirname "$sample")")
git add "$dest"
git -c user.name="honeypot-github-publish" -c user.email="honeypot-github-publish@localhost" \
  commit --quiet -m "sample: $sha256 ($sensor, $(date -u +%F))"
git push --quiet origin HEAD
commit=$(git rev-parse HEAD)

# 4. Record the pending publication for collect-results.py.
tmp="$pending_dir/.$sha256.pending.tmp"
jq -n --arg sha256 "$sha256" --arg commit "$commit" \
  --arg requested_at "$(date -u +%FT%TZ)" --arg sensor "$sensor" --arg bucket "$bucket" \
  '{version:1,sha256:$sha256,commit:$commit,requested_at:$requested_at,sensor:$sensor,bucket:$bucket}' \
  >"$tmp"
chmod 0600 "$tmp"
mv -f "$tmp" "$pending_dir/$sha256.pending"

echo "pushed $sha256 as $dest ($commit)"
