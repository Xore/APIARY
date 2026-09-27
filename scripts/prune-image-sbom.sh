#!/usr/bin/env bash
# prune-image-sbom.sh -- bound the homeserver's per-image SBOM store.
# #3321.
#
# /var/image-sbom/<image>/ accumulates one <hex-digest>.sbom.json per
# dashboard build that ran on this box, and nothing would ever remove them:
# unlike the buildx layer cache beside it (scripts/prune-buildx-cache.sh,
# #2822) there is no upstream eviction, so the directory is simply
# append-only. Each file is small -- CycloneDX JSON for a distroless-ish
# runtime image runs a few hundred KiB to a few MiB -- which is exactly why
# this is a retention policy and not a size ceiling. An operator asking
# "which of these builds is affected?" wants the recent history, not every
# build since the disk was last rebuilt.
#
# So: keep the newest KEEP records per image, delete the rest, then re-point
# latest.sbom.json at the newest survivor. The digest-named files are never
# pruned by age, only by count, because a digest-keyed inventory's whole
# value is that it names one exact image -- deleting a month-old one because
# a newer one exists would make the older image's inventory unanswerable,
# which is the gap this issue was filed to close.
#
# Re-pointing latest.sbom.json after the delete matters: a store whose latest
# pointer names a pruned digest is worse than no pointer, because it looks
# authoritative.
#
# Usage: prune-image-sbom.sh <root-dir>
#   KEEP  records to keep per image (default 10; 0 disables the age pass)
set -euo pipefail

root=${1:?usage: prune-image-sbom.sh <root-dir>}
KEEP=${KEEP:-10}

[ -d "$root" ] || { echo "prune-image-sbom: $root does not exist, nothing to do"; exit 0; }

# Sorted by mtime descending, and only the digest-named records: latest.sbom.json
# is a pointer, not a record, and is rewritten below rather than counted.
records() {
  find "$1" -maxdepth 1 -type f -name '*.sbom.json' ! -name 'latest.sbom.json' \
    -printf '%T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2-
}

total_before=0
total_after=0
for dir in "$root"/*/; do
  [ -d "$dir" ] || continue
  dir=${dir%/}
  image=${dir##*/}
  mapfile -t found < <(records "$dir")
  if [ "${#found[@]}" -eq 0 ]; then
    continue
  fi
  total_before=$((total_before + ${#found[@]}))
  if [ "$KEEP" -gt 0 ] && [ "${#found[@]}" -gt "$KEEP" ]; then
    # records() is newest-first, so everything past KEEP is the oldest tail.
    for stale in "${found[@]:KEEP}"; do
      rm -f -- "$stale"
      echo "prune-image-sbom: dropped $stale (older than the newest $KEEP)"
    done
    total_after=$((total_after + KEEP))
  else
    total_after=$((total_after + ${#found[@]}))
  fi

  # Re-point latest at whatever now exists newest-first. Falls through to the
  # rm when the store is empty, so a directory is never left claiming a
  # digest that is gone. Unconditional: the copy is a few hundred KiB, and
  # comparing against the current pointer to skip it would be a second
  # source of truth about which file is newest.
  mapfile -t kept < <(records "$dir")
  if [ "${#kept[@]}" -gt 0 ]; then
    cp -f -- "${kept[0]}" "$dir/latest.sbom.json"
  else
    rm -f -- "$dir/latest.sbom.json"
    echo "prune-image-sbom: $image has no SBOM records left; removed latest.sbom.json"
  fi

  # Same seven-runner-users problem prune-buildx-cache.sh documents for
  # /var/buildx-cache (#2822): the writer's umask collapses the inherited
  # default ACL's mask, so whichever runner did not write last could not
  # replace latest.sbom.json on the next build. Idempotent and cheap.
  chmod -R g+rwX "$dir" 2>/dev/null || true
  find "$dir" -type d -exec chmod g+s {} + 2>/dev/null || true
done

echo "prune-image-sbom: $root held $total_before record(s), now holds $total_after"
