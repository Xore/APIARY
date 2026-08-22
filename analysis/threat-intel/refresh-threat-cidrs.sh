#!/usr/bin/env bash
# refresh-threat-cidrs.sh — populate threat-cidrs.csv from free, zero-auth
# threat-intel sources (#244).
#
# backend-service's threat_intel.rs worker loop (WORKER_LOOPS=threat-intel)
# reads this file and picks up a refresh within its own reload interval
# without a restart -- ported from the old Go dashboard's geoip.go
# (loadIntelCIDRs/threatIntelReloadLoop), decoupled from the dashboard
# entirely now (#1659). threat-cidrs.csv is gitignored (generated/refreshed
# content, same reasoning as country.csv -- see .gitignore); this
# script creates it on first run, seeded from the tracked
# threat-cidrs.csv.example if present. Auto-fetched entries live inside a
# marker block; any manually-added lines above that block are left untouched
# on every subsequent run -- the same "vendored content stays in its own
# subtree, local content is never touched" split analysis/yara/sync-yara.sh
# uses for its own corpus.
#
# Sources (see #244 for the full evaluation):
#   - Spamhaus DROP (EDROP is merged into it as of this writing): known-
#     hijacked/leased netblocks used for spam and other abuse. Free for any
#     use per Spamhaus's own FAQ; their stated polling-cadence rule is no
#     more than once per hour, so the systemd timer driving this script is
#     daily -- comfortably inside that limit, not pushing against it.
#   - Tor bulk exit list: anonymized-traffic signal, not inherently
#     malicious -- gets its own "tor-exit" label rather than being lumped in
#     with reputation-list hits.
#   - AWS / GCP published IP ranges: ground truth for the existing "cloud"
#     provider classification, in place of an ASN-org-name guess.
#
# AbuseIPDB (needs a registered API key) is deliberately not included here --
# see #244's own sequencing: ship the zero-auth sources first, add it later
# as a separate, explicitly-enabled addition.
#
# Usage:
#   analysis/threat-intel/refresh-threat-cidrs.sh [--dry-run]
#
# Env (override only for testing against a local fixture, e.g. a file:// URL):
#   THREAT_SPAMHAUS_URL   default https://www.spamhaus.org/drop/drop.txt
#   THREAT_TOR_URL        default https://check.torproject.org/torbulkexitlist
#   THREAT_AWS_URL        default https://ip-ranges.amazonaws.com/ip-ranges.json
#   THREAT_GCP_URL        default https://www.gstatic.com/ipranges/cloud.json
set -euo pipefail

SPAMHAUS_URL="${THREAT_SPAMHAUS_URL:-https://www.spamhaus.org/drop/drop.txt}"
TOR_URL="${THREAT_TOR_URL:-https://check.torproject.org/torbulkexitlist}"
AWS_URL="${THREAT_AWS_URL:-https://ip-ranges.amazonaws.com/ip-ranges.json}"
GCP_URL="${THREAT_GCP_URL:-https://www.gstatic.com/ipranges/cloud.json}"
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) sed -n '2,39p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

command -v curl >/dev/null 2>&1 || { echo "curl is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 1; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dest="$root/threat-cidrs.csv"
begin_marker="# BEGIN AUTO-FETCHED (refresh-threat-cidrs.sh -- do not edit by hand; add manual entries above this line)"
end_marker="# END AUTO-FETCHED"

scratch="$(mktemp -d)"
new="$root/.threat-cidrs.csv.tmp.$$"
trap 'rm -rf "$scratch" "$new"' EXIT

fetch() {
  # fetch <name> <url> <outfile> -- a failed source is logged and skipped,
  # never fatal on its own: one bad feed must not take the other three down
  # with it, mirroring sync-yara.sh's "one bad rule file doesn't wipe the
  # corpus" posture.
  local name="$1" url="$2" out="$3"
  if curl -fsSL --max-time 30 "$url" -o "$out" 2>"$scratch/$name.err"; then
    return 0
  fi
  echo "WARN: $name fetch failed, skipping ($(head -1 "$scratch/$name.err" 2>/dev/null))" >&2
  return 1
}

entries="$scratch/entries.csv"
: > "$entries"
usable=0
attribution=""

# Previous run's auto-fetched entries (empty if threat-cidrs.csv does not
# exist yet). A per-source fetch failure or an empty/unparseable response
# falls back to that source's entries here instead of silently dropping its
# coverage until the next successful refresh -- a transient Spamhaus outage
# must not mean zero reputation-blocklist protection for a day.
old_entries="$scratch/old-entries.csv"
: > "$old_entries"
if [ -f "$dest" ]; then
  awk '
    /^# END AUTO-FETCHED/ { exit }
    in_block && $0 !~ /^#/ { print }
    /^# BEGIN AUTO-FETCHED/ { in_block = 1 }
  ' "$dest" > "$old_entries"
fi

# use_previous <label> -- appends the last successful refresh's entries for
# exactly this label, if any, and counts the source as usable if it found
# some. Silent (no source has any previous data, e.g. a brand-new file) is
# not itself an error -- the overall "nothing usable at all" gate below is.
use_previous() {
  local label="$1" n
  n=$(awk -F',' -v l="$label" '$2==l' "$old_entries" | tee -a "$entries" | wc -l)
  if [ "$n" -gt 0 ]; then
    echo "WARN: falling back to $n previous $label entries from the last successful refresh" >&2
    usable=$((usable + 1))
  fi
}

# ── Spamhaus DROP ────────────────────────────────────────────────────────────
if fetch spamhaus "$SPAMHAUS_URL" "$scratch/drop.txt"; then
  # Attribution/date header text Spamhaus's terms ask to keep alongside the
  # data -- comment lines in drop.txt start with ';'.
  attribution="$(grep '^;' "$scratch/drop.txt" | head -5 || true)"
  # Data lines are "CIDR ; SBL-ref"; only the CIDR is kept -- the SBL
  # reference is Spamhaus's own bookkeeping, not part of this file's shape.
  before=$(wc -l < "$entries")
  # || true: a fetched-but-all-comments/empty response makes the leading
  # grep -v exit 1 (nothing selected), which -- under pipefail -- would
  # otherwise abort the whole script instead of degrading to "0 new entries,
  # fall back" like every other empty/malformed response below.
  { grep -v '^;' "$scratch/drop.txt" | grep -v '^[[:space:]]*$' \
    | awk -F';' '{gsub(/[ \t]/,"",$1); if ($1 != "") print $1 ",blocklist:spamhaus"}' \
    >> "$entries"; } || true
  after=$(wc -l < "$entries")
  if [ "$after" -gt "$before" ]; then
    usable=$((usable + 1))
  else
    echo "WARN: spamhaus fetch succeeded but yielded no usable entries" >&2
    use_previous "blocklist:spamhaus"
  fi
else
  use_previous "blocklist:spamhaus"
fi

# ── Tor bulk exit list ───────────────────────────────────────────────────────
if fetch tor "$TOR_URL" "$scratch/tor.txt"; then
  before=$(wc -l < "$entries")
  { grep -v '^#' "$scratch/tor.txt" | grep -v '^[[:space:]]*$' | while read -r ip; do
      case "$ip" in
        *:*) bits=128 ;;
        *) bits=32 ;;
      esac
      printf '%s/%s,tor-exit\n' "$ip" "$bits"
    done >> "$entries"; } || true
  after=$(wc -l < "$entries")
  if [ "$after" -gt "$before" ]; then
    usable=$((usable + 1))
  else
    echo "WARN: tor fetch succeeded but yielded no usable entries" >&2
    use_previous "tor-exit"
  fi
else
  use_previous "tor-exit"
fi

# ── AWS published ranges ─────────────────────────────────────────────────────
if fetch aws "$AWS_URL" "$scratch/aws.json"; then
  before=$(wc -l < "$entries")
  # || true: malformed/unparseable JSON makes jq exit non-zero, which --
  # under pipefail -- would otherwise abort the whole script instead of
  # degrading to "0 new entries, fall back to previous data" below.
  { jq -r '(.prefixes[]?.ip_prefix), (.ipv6_prefixes[]?.ipv6_prefix)' "$scratch/aws.json" 2>/dev/null \
    | while read -r cidr; do
        [ -n "$cidr" ] && printf '%s,cloud:aws\n' "$cidr"
      done >> "$entries"; } || true
  after=$(wc -l < "$entries")
  if [ "$after" -gt "$before" ]; then
    usable=$((usable + 1))
  else
    echo "WARN: aws fetch succeeded but yielded no usable entries" >&2
    use_previous "cloud:aws"
  fi
else
  use_previous "cloud:aws"
fi

# ── GCP published ranges ─────────────────────────────────────────────────────
if fetch gcp "$GCP_URL" "$scratch/gcp.json"; then
  before=$(wc -l < "$entries")
  { jq -r '.prefixes[]? | (.ipv4Prefix // .ipv6Prefix // empty)' "$scratch/gcp.json" 2>/dev/null \
    | while read -r cidr; do
        [ -n "$cidr" ] && printf '%s,cloud:gcp\n' "$cidr"
      done >> "$entries"; } || true
  after=$(wc -l < "$entries")
  if [ "$after" -gt "$before" ]; then
    usable=$((usable + 1))
  else
    echo "WARN: gcp fetch succeeded but yielded no usable entries" >&2
    use_previous "cloud:gcp"
  fi
else
  use_previous "cloud:gcp"
fi

if [ ! -s "$entries" ]; then
  echo "every source failed and no previous data exists to fall back to -- leaving $dest untouched" >&2
  exit 1
fi

# ── Preserve any manually-added lines above the auto-fetched block ──────────
# threat-cidrs.csv itself is gitignored (generated/refreshed content, same
# reasoning as country.csv -- see .gitignore); threat-cidrs.csv.example is
# the tracked starter this seeds a first run from.
manual="$scratch/manual.csv"
if [ -f "$dest" ]; then
  awk -v b="$begin_marker" 'index($0,"# BEGIN AUTO-FETCHED"){exit} {print}' "$dest" > "$manual"
elif [ -f "$dest.example" ]; then
  awk -v b="$begin_marker" 'index($0,"# BEGIN AUTO-FETCHED"){exit} {print}' "$dest.example" > "$manual"
else
  cat > "$manual" <<'HEADER'
# Optional local intelligence overlays. Format: CIDR,label
# Manual entries go above the auto-fetched block below; refresh-threat-cidrs.sh
# never touches this part of the file. Populate the block below by running
# analysis/threat-intel/refresh-threat-cidrs.sh (#244), or add your own here.
HEADER
fi

{
  cat "$manual"
  echo "$begin_marker"
  echo "# Sources: Spamhaus DROP (blocklist:spamhaus), Tor bulk exit list"
  echo "# (tor-exit), AWS/GCP published ranges (cloud:aws / cloud:gcp)."
  echo "# Refreshed $(date -u +%FT%TZ) -- $usable/4 sources usable."
  if [ -n "$attribution" ]; then
    echo "#"
    echo "# Spamhaus DROP attribution (kept per https://www.spamhaus.org/drop/):"
    printf '%s\n' "$attribution" | sed 's/^/# /'
  fi
  sort -u "$entries"
  echo "$end_marker"
} > "$new"

if [ "$DRY_RUN" = 1 ]; then
  echo "--- dry run: would write $dest ---"
  cat "$new"
  exit 0
fi

chmod 0644 "$new"
mv -f "$new" "$dest"
echo "refreshed $dest: $(grep -vc '^#' "$dest" || true) entries ($usable/4 sources usable)"
