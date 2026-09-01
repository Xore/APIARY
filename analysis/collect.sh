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

    if [[ ! -d "$SRC" ]]; then
        log "Source not found: $SRC (skipping)"
        return
    fi

    # The marker's -newer filter is only a scan-time optimization; the
    # content-addressed dest check below is what actually prevents
    # duplicate copies, so a stale/missing marker just costs a wider scan,
    # never a correctness problem.
    local find_args=(-type f -print0)
    if [[ -f "$HONEYPOT_REPO/.last_collection" ]]; then
        find_args=(-type f -newer "$HONEYPOT_REPO/.last_collection" -print0)
    else
        log "No .last_collection marker; scanning $SRC in full."
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
            mkdir -p "$(dirname "$dest")"
            cp "$file" "$dest"
            log "Copied: $sha ($magic)"
            COPIED=$((COPIED + 1))
        fi
    done < <(find "$SRC" "${find_args[@]}" 2>/dev/null)
}

copy_samples "$COWRIE_DOWNLOADS"
copy_samples "$DIONAEA_SAMPLES"

# Stage whatever landed this run, then ask git the truth about what is
# actually pending rather than trusting COPIED alone. A prior run can die
# in two different places after copying files -- `git commit` (rare) or
# `git push` (auth, network: "the interesting cases for a manual backfill
# over SSH") -- and both leave state that COPIED=0 alone would misreport as
# "no new samples" on every later run, since the content-addressed dest
# already exists so copy_samples silently skips re-copying it. Checking
# both "anything staged/uncommitted" and "local ahead of upstream" covers
# either death point and makes both retryable and honestly reported.
git add samples/
UNCOMMITTED=$(git status --porcelain -- samples/ | wc -l)

if [[ $UNCOMMITTED -gt 0 ]]; then
    git commit -q -m "feat: add samples from honeypot [$(date -u +%Y-%m-%d)]"
fi

AHEAD=$(git rev-list --count '@{u}..HEAD' 2>/dev/null || echo 0)

if [[ $AHEAD -gt 0 ]]; then
    if [[ $COPIED -gt 0 ]]; then
        log "Copied $COPIED new sample(s) this run ($UNCOMMITTED newly staged). $AHEAD commit(s) ahead of origin/main, pushing..."
    elif [[ $UNCOMMITTED -gt 0 ]]; then
        log "$UNCOMMITTED sample(s) left over from a previous run were staged but never committed (no new samples copied this run). Committed and pushing..."
    else
        log "$AHEAD commit(s) with samples left over from a previous run were committed but never pushed (no new samples copied this run). Retrying push..."
    fi
    git push origin main
    touch "$HONEYPOT_REPO/.last_collection"
    log "Push complete. GitHub Actions analysis pipeline triggered."
else
    log "No new samples found."
fi
