#!/usr/bin/env bash
# collect.sh — DEPRECATED. Do not install this on a cron.
#
# Copies new payloads from Cowrie/Dionaea to a local clone of Xore/honeypot
# then pushes them, triggering the GitHub Actions analysis pipeline.
#
# Why deprecated: pushing a capture to Xore/honeypot publishes it to a public
# repository and to eight third-party scanner APIs. That is an irreversible
# external disclosure and must be a deliberate per-sample decision, not a timer.
# The replacement is an admin-only, confirm-gated button in the dashboard
# (backend-service github_analysis_submit.rs) backed by a root-owned host
# publisher — see docs/analysis/README.md. (The roadmap doc named here
# before was removed with #1662's stale-doc sweep.)
#
# Kept only for a one-time manual backfill, run by hand with the operator
# watching. Review what it is about to publish before running it.
#
# Prerequisites:
#   - git clone https://github.com/Xore/Honeypot /opt/honeypot-samples
#   - SSH deploy key or GH_PAT configured in git credential store

set -euo pipefail

HONEYPOT_REPO="/opt/honeypot-samples"
COWRIE_DOWNLOADS="/opt/cowrie/var/lib/cowrie/downloads"
DIONAEA_SAMPLES="/opt/dionaea/var/lib/dionaea/binaries"
LOG="/var/log/honeypot-collect.log"

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*" | tee -a "$LOG"; }

log "=== Starting payload collection ==="

cd "$HONEYPOT_REPO"
git pull --ff-only origin main

COPIED=0

copy_samples() {
    local SRC="$1"
    local DEST_TYPE="$2"   # ELF, PE, Scripts, UNKNOWN
    local DEST_DIR="$HONEYPOT_REPO/samples/$DEST_TYPE"
    mkdir -p "$DEST_DIR"

    if [[ ! -d "$SRC" ]]; then
        log "Source not found: $SRC (skipping)"
        return
    fi

    while IFS= read -r -d '' file; do
        sha=$(sha256sum "$file" | awk '{print $1}')
        # Detect file type
        magic=$(file -b "$file" 2>/dev/null || echo '')
        if echo "$magic" | grep -qi 'ELF'; then
            dest="$HONEYPOT_REPO/samples/ELF/$sha"
        elif echo "$magic" | grep -qi 'PE32\|MS-DOS'; then
            dest="$HONEYPOT_REPO/samples/PE/$sha"
        elif echo "$magic" | grep -qi 'script\|text'; then
            dest="$HONEYPOT_REPO/samples/Scripts/$sha"
        else
            dest="$HONEYPOT_REPO/samples/UNKNOWN/$sha"
        fi

        if [[ ! -f "$dest" ]]; then
            cp "$file" "$dest"
            log "Copied: $sha ($magic)"
            COPIED=$((COPIED + 1))
        fi
    done < <(find "$SRC" -type f -newer "$HONEYPOT_REPO/.last_collection" -print0 2>/dev/null || \
             find "$SRC" -type f -print0)
}

copy_samples "$COWRIE_DOWNLOADS"  "ELF"
copy_samples "$DIONAEA_SAMPLES"   "UNKNOWN"

if [[ $COPIED -gt 0 ]]; then
    log "Copied $COPIED new samples. Committing and pushing..."
    git add samples/
    git commit -m "feat: add $COPIED new samples from honeypot [$( date -u +%Y-%m-%d)]"
    git push origin main
    touch "$HONEYPOT_REPO/.last_collection"
    log "Push complete. GitHub Actions analysis pipeline triggered."
else
    log "No new samples found."
fi
