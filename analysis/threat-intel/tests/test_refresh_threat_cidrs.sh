#!/usr/bin/env bash
# Tests for refresh-threat-cidrs.sh (#244).
#
# Runs against a throwaway copy of analysis/threat-intel/ and local file://
# fixture URLs standing in for Spamhaus/Tor/AWS/GCP, so nothing here touches
# the real network or the real threat-cidrs.csv. Needs curl and jq -- the
# same tools the script itself requires.
#
# Usage: analysis/threat-intel/tests/test_refresh_threat_cidrs.sh
set -euo pipefail

for tool in curl jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "SKIP: $tool is not installed"
    exit 0
  fi
done

src_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# ── A tree to refresh into ───────────────────────────────────────────────────
root="$tmp/geoip"
mkdir -p "$root"
cp "$src_root/refresh-threat-cidrs.sh" "$root/"
cp "$src_root/threat-cidrs.csv.example" "$root/"

# ── Fixture sources ───────────────────────────────────────────────────────────
fixtures="$tmp/fixtures"
mkdir -p "$fixtures"
cat > "$fixtures/drop.txt" <<'EOF'
; Spamhaus DROP List 2026/08/02
; (c) 2026 The Spamhaus Project
;
192.0.2.0/24 ; SBL123456
198.51.100.0/24 ; SBL234567
EOF
cat > "$fixtures/tor.txt" <<'EOF'
# Tor bulk exit list
203.0.113.5
203.0.113.6
EOF
cat > "$fixtures/aws.json" <<'EOF'
{"prefixes":[{"ip_prefix":"192.0.2.0/24","region":"us-east-1"}],"ipv6_prefixes":[]}
EOF
cat > "$fixtures/gcp.json" <<'EOF'
{"prefixes":[{"ipv4Prefix":"198.51.100.0/24"},{"ipv6Prefix":"2001:db8::/32"}]}
EOF

run_refresh() {
  ( cd "$root" && \
    THREAT_SPAMHAUS_URL="file://$fixtures/drop.txt" \
    THREAT_TOR_URL="file://$fixtures/tor.txt" \
    THREAT_AWS_URL="file://$fixtures/aws.json" \
    THREAT_GCP_URL="file://$fixtures/gcp.json" \
    "$root/refresh-threat-cidrs.sh" "$@" )
}

# ── dry-run must not touch the filesystem ────────────────────────────────────
out="$(run_refresh --dry-run 2>&1)" || fail "dry-run exited non-zero:\n$out"
[ ! -e "$root/threat-cidrs.csv" ] || fail "--dry-run wrote threat-cidrs.csv"
grep -q "blocklist:spamhaus" <<<"$out" || fail "dry-run output does not show the merged data"
pass "--dry-run reports the merge without writing the file"

# ── first real run: seeds from .example, merges all four sources ────────────
out="$(run_refresh 2>&1)" || fail "refresh exited non-zero:\n$out"
dest="$root/threat-cidrs.csv"
[ -f "$dest" ] || fail "threat-cidrs.csv was not created"
grep -q "4/4 sources usable" <<<"$out" || fail "did not report all 4 sources usable:\n$out"
pass "first run creates threat-cidrs.csv and reports all sources usable"

grep -qx "192.0.2.0/24,blocklist:spamhaus" "$dest" || fail "spamhaus entry missing"
grep -qx "198.51.100.0/24,blocklist:spamhaus" "$dest" || fail "spamhaus entry missing"
grep -qx "203.0.113.5/32,tor-exit" "$dest" || fail "tor entry (converted to /32) missing"
grep -qx "192.0.2.0/24,cloud:aws" "$dest" || fail "aws entry missing"
grep -qx "198.51.100.0/24,cloud:gcp" "$dest" || fail "gcp ipv4 entry missing"
grep -qx "2001:db8::/32,cloud:gcp" "$dest" || fail "gcp ipv6 entry missing"
pass "all four sources are merged with their expected labels"

grep -q "Spamhaus DROP attribution" "$dest" || fail "Spamhaus attribution header was dropped"
grep -q "; Spamhaus DROP List 2026/08/02" "$dest" || fail "Spamhaus's own header text was not preserved"
pass "Spamhaus attribution text is kept alongside the data, per their terms"

grep -qx "# 192.0.2.0/24,scanner" "$dest" || fail "the .example's starter content was not carried over on first run"
pass "first run seeds the manual section from threat-cidrs.csv.example"

# ── a manually-added line survives a refresh ─────────────────────────────────
awk '/# BEGIN AUTO-FETCHED/{print "203.0.113.99/32,my-manual-entry"} {print}' "$dest" > "$tmp/with-manual.csv"
mv "$tmp/with-manual.csv" "$dest"
run_refresh >/dev/null 2>&1 || fail "refresh after a manual edit failed"
grep -qx "203.0.113.99/32,my-manual-entry" "$dest" || fail "manual entry did not survive a refresh"
pass "a manually-added line above the auto-fetched block survives a refresh"

# ── the auto-fetched block is fully regenerated, not appended to ────────────
count="$(grep -c '^192.0.2.0/24,blocklist:spamhaus$' "$dest")"
[ "$count" = 1 ] || fail "re-running duplicated an auto-fetched entry ($count copies)"
pass "re-running regenerates the auto-fetched block instead of duplicating it"

# ── a single source failing falls back to its last successful data ─────────
# $dest already carries real blocklist:spamhaus entries from the runs above --
# a transient outage at one upstream must not silently drop that source's
# coverage until the next successful refresh.
out="$(cd "$root" && \
  THREAT_SPAMHAUS_URL="file:///nonexistent/drop.txt" \
  THREAT_TOR_URL="file://$fixtures/tor.txt" \
  THREAT_AWS_URL="file://$fixtures/aws.json" \
  THREAT_GCP_URL="file://$fixtures/gcp.json" \
  "$root/refresh-threat-cidrs.sh" 2>&1)" || fail "partial failure should still exit 0:\n$out"
grep -q "WARN: spamhaus fetch failed" <<<"$out" || fail "spamhaus failure was not reported"
grep -q "falling back to .* previous blocklist:spamhaus entries" <<<"$out" || fail "fallback was not reported:\n$out"
grep -q "4/4 sources usable" <<<"$out" || fail "did not report 4/4 sources usable (3 fresh + 1 fallback):\n$out"
grep -qx "203.0.113.5/32,tor-exit" "$dest" || fail "tor data is missing after an unrelated source failed"
grep -qx "192.0.2.0/24,blocklist:spamhaus" "$dest" || fail "spamhaus coverage was dropped instead of falling back to previous data"
pass "one source failing falls back to its last successful data and does not block the others"

# ── every source failing, with no previous data at all, is a hard failure ───
fresh_root="$tmp/geoip-fresh"
mkdir -p "$fresh_root"
cp "$src_root/refresh-threat-cidrs.sh" "$fresh_root/"
# No threat-cidrs.csv and no .example here -- genuinely nothing to fall back to.
( cd "$fresh_root" && \
  THREAT_SPAMHAUS_URL="file:///nonexistent/a" \
  THREAT_TOR_URL="file:///nonexistent/b" \
  THREAT_AWS_URL="file:///nonexistent/c" \
  THREAT_GCP_URL="file:///nonexistent/d" \
  "$fresh_root/refresh-threat-cidrs.sh" >/dev/null 2>&1 ) && fail "a total fetch failure with nothing to fall back to exited 0"
[ ! -e "$fresh_root/threat-cidrs.csv" ] || fail "threat-cidrs.csv should not have been created"
pass "every source failing with no previous data anywhere is a hard failure"

# ── every source failing, WITH previous data, recovers via fallback ─────────
out="$(cd "$root" && \
  THREAT_SPAMHAUS_URL="file:///nonexistent/a" \
  THREAT_TOR_URL="file:///nonexistent/b" \
  THREAT_AWS_URL="file:///nonexistent/c" \
  THREAT_GCP_URL="file:///nonexistent/d" \
  "$root/refresh-threat-cidrs.sh" 2>&1)" || fail "a total fetch failure with previous data available should still succeed via fallback:\n$out"
grep -qx "192.0.2.0/24,blocklist:spamhaus" "$dest" || fail "spamhaus fallback data missing after every fetch failed"
grep -qx "203.0.113.5/32,tor-exit" "$dest" || fail "tor fallback data missing after every fetch failed"
grep -qx "203.0.113.99/32,my-manual-entry" "$dest" || fail "manual entry lost during a fully-fallback run"
pass "every source failing with previous data available recovers entirely via fallback"

# ── malformed/empty JSON from a source degrades to a warning, not a crash ───
echo "not json" > "$fixtures/broken-aws.json"
out="$(cd "$root" && \
  THREAT_SPAMHAUS_URL="file://$fixtures/drop.txt" \
  THREAT_TOR_URL="file://$fixtures/tor.txt" \
  THREAT_AWS_URL="file://$fixtures/broken-aws.json" \
  THREAT_GCP_URL="file://$fixtures/gcp.json" \
  "$root/refresh-threat-cidrs.sh" 2>&1)" || fail "malformed JSON from one source should not be fatal:\n$out"
grep -q "aws fetch succeeded but yielded no usable entries" <<<"$out" || fail "malformed JSON was not reported as yielding nothing usable"
grep -q "falling back to .* previous cloud:aws entries" <<<"$out" || fail "aws fallback was not reported after malformed JSON:\n$out"
pass "malformed JSON from one source degrades to a warning and falls back, not a crash"

echo
echo "all refresh-threat-cidrs tests passed"
