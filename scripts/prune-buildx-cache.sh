#!/usr/bin/env bash
# prune-buildx-cache.sh -- bound the size of one image's type=local buildx
# cache directory (#2822). type=local has no eviction of any kind: every
# `cache-to` export leaves old, no-longer-referenced blobs behind in
# blobs/sha256/, and the directory grows without bound otherwise. This is
# the local-disk equivalent of the GHA-quota incident this issue exists to
# fix, just slower -- an unbounded cache on /mnt-1 eventually starves
# whatever else is on that filesystem (including /mnt-1/benchmarks).
#
# Strategy: OCI local-cache layout is content-addressed
# (blobs/sha256/<digest>), so a blob's mtime only changes when it is
# written -- BuildKit does not touch it on a cache-from read. That makes
# mtime a reasonable staleness signal: a blob nothing has exported in
# PRUNE_DAYS days is one no recent build layer references. Delete those,
# then enforce a hard per-image ceiling -- by clearing the directory
# outright rather than trimming it, for the reason spelled out at the
# ceiling pass below. The age-based pass never touches index.json /
# ingest -- those are tiny and BuildKit regenerates or rewrites them on
# every export.
#
# Usage: prune-buildx-cache.sh <cache-dir>
set -euo pipefail

dir=${1:?usage: prune-buildx-cache.sh <cache-dir>}
PRUNE_DAYS=${PRUNE_DAYS:-14}
MAX_BYTES=${MAX_BYTES:-$((2 * 1024 * 1024 * 1024))}  # 2 GiB per image

[ -d "$dir" ] || { echo "prune-buildx-cache: $dir does not exist, nothing to do"; exit 0; }
blobs="$dir/blobs/sha256"
[ -d "$blobs" ] || { echo "prune-buildx-cache: no $blobs yet, nothing to do"; exit 0; }

before=$(du -sb "$dir" 2>/dev/null | cut -f1)
echo "prune-buildx-cache: $dir before: ${before:-0} bytes"

# Age-based pass. Oldest-blob deletion is safe here only in the weak sense
# that it cannot HARD-fail a build: measured 2026-09-02, removing one blob
# a manifest references makes BuildKit emit
#   WARNING: local cache import at <dir> skipped: digest sha256:... unavailable
# and build on with EXIT=0. But note what that warning says -- it skips the
# WHOLE import, not the missing layer. So a partially-pruned directory is
# worth nothing and still occupies disk, which is why the ceiling pass below
# resets rather than nibbles.
find "$blobs" -type f -mtime "+$PRUNE_DAYS" -print0 | xargs -0 -r rm -f --

# Hard-ceiling pass: whole-directory reset, not oldest-blob-at-a-time.
#
# Two reasons this beats trimming. (1) Correctness: since one missing blob
# voids the entire import (above), trimming to just under the ceiling most
# likely leaves a directory that is simultaneously useless AND ~MAX_BYTES
# large -- the worst of both. A reset gives up the cache honestly and the
# next build re-exports a clean, complete one. (2) Cost: the previous form
# re-ran `du -sb` over the whole tree after every single `rm`, which is
# O(n^2) over a directory of thousands of small blobs.
total=$(du -sb "$dir" 2>/dev/null | cut -f1)
[ -n "$total" ] || total=0
if [ "$total" -gt "$MAX_BYTES" ]; then
  echo "prune-buildx-cache: $dir is ${total} bytes, over the ${MAX_BYTES} ceiling -- resetting"
  # Remove the cache contents, not the directory itself: the runner owns
  # what is inside but may not be able to recreate the directory under a
  # root-owned /mnt-1 (#2822's own blocker).
  find "$dir" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi

after=$(du -sb "$dir" 2>/dev/null | cut -f1)
echo "prune-buildx-cache: $dir after: ${after:-0} bytes"
