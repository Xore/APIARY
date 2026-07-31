#!/usr/bin/env bash
# test_denylist.sh — both halves of the retention denylist (#74) actually
# block, and a clean sample with no denylist hit is actually let through.
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: $*"; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

# --- String denylist: a sample embedding a denylisted identifier is blocked. ---
printf 'malware calls home to honeypot.internal.example and does other things' >"$work/tainted"
if "$script_dir/check-denylist.sh" "$work/tainted" deadbeef "honeypot.internal.example" "" 2>/dev/null; then
  fail "sample embedding a denylisted string was allowed through"
fi
pass "sample embedding a denylisted string is blocked"

printf 'perfectly ordinary malware with nothing special in it' >"$work/clean"
"$script_dir/check-denylist.sh" "$work/clean" deadbeef "honeypot.internal.example" "" \
  || fail "clean sample was blocked by the string denylist"
pass "clean sample passes the string denylist"

# --- Source-CIDR denylist: a capture attributed to a private-range source is blocked. ---
mkdir -p "$work/logs/cowrie" "$work/logs/dionaea"
printf 'sample bytes' >"$work/private-source"
sha=$(sha256sum "$work/private-source" | cut -d' ' -f1)
echo "{\"src_ip\":\"192.168.50.7\",\"shasum\":\"$sha\"}" >"$work/logs/cowrie/cowrie.json"
if HONEYPOT_LOGS_DIR="$work/logs" "$script_dir/check-denylist.sh" "$work/private-source" "$sha" "" "192.168.0.0/16" 2>/dev/null; then
  fail "capture attributed to a private-range source was allowed through"
fi
pass "private-range source is blocked"

printf 'sample bytes 2' >"$work/public-source"
sha2=$(sha256sum "$work/public-source" | cut -d' ' -f1)
echo "{\"src_ip\":\"203.0.113.9\",\"shasum\":\"$sha2\"}" >"$work/logs/cowrie/cowrie.json"
HONEYPOT_LOGS_DIR="$work/logs" "$script_dir/check-denylist.sh" "$work/public-source" "$sha2" "" "192.168.0.0/16" \
  || fail "capture attributed to a public source was blocked"
pass "public-range source passes the CIDR denylist"

# --- No log record at all: Phase 1 chooses not to block on an attribution miss. ---
printf 'sample bytes 3' >"$work/unattributed"
sha3=$(sha256sum "$work/unattributed" | cut -d' ' -f1)
: >"$work/logs/cowrie/cowrie.json"
HONEYPOT_LOGS_DIR="$work/logs" "$script_dir/check-denylist.sh" "$work/unattributed" "$sha3" "" "192.168.0.0/16" \
  || fail "an unattributed capture was blocked, which is not this phase's documented behavior"
pass "an unattributed capture is not blocked (documented gap, not a false pass)"

echo "OK: denylist blocks what it should and passes what it should"
