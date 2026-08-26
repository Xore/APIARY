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

# --- Needles are strings, not patterns (#2078): regex metacharacters in a
# --- denylist entry must still block the sample containing them literally.
printf 'payload drops [foo marker' >"$work/bracket"
if "$script_dir/check-denylist.sh" "$work/bracket" deadbeef "[foo" "" 2>/dev/null; then
  fail "needle '[foo' was compiled as a broken pattern and went inert"
fi
pass "a needle containing [ blocks literally"

printf 'artifacts staged under C:\\temp\\sensor-name' >"$work/backslash"
if "$script_dir/check-denylist.sh" "$work/backslash" deadbeef "C:\\temp\\sensor-name" "" 2>/dev/null; then
  fail "needle with backslashes was mangled as a pattern"
fi
pass "a needle containing \\ blocks literally"

printf 'repeat marker (abc)+ found in capture' >"$work/brace"
if "$script_dir/check-denylist.sh" "$work/brace" deadbeef "(abc)+" "" 2>/dev/null; then
  fail "needle '(abc)+' did not match its own literal text"
fi
pass "a needle containing ( ) + blocks literally"

# ...and literal semantics cut both ways: an ERE-habit needle must not
# silently widen into matching plain text that never contained it.
printf 'plain abc without the wrapper' >"$work/plain"
"$script_dir/check-denylist.sh" "$work/plain" deadbeef "(abc)+" "" \
  || fail "needle '(abc)+' matched plain 'abc' -- strings are being pattern-matched again"
pass "an ERE-shaped needle does not match text it does not literally contain"

# A sample grep cannot read at all is a refusal, not a pass (#2078).
if "$script_dir/check-denylist.sh" "$work/does-not-exist" deadbeef "anything" "" 2>/dev/null; then
  fail "unreadable sample sailed past the string check"
fi
pass "an unreadable sample is refused, not passed"

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

# --- A bare IP in the CIDR list is a host entry, not a no-op (#2078). ---
printf 'sample bytes 4' >"$work/bare-ip-source"
sha4=$(sha256sum "$work/bare-ip-source" | cut -d' ' -f1)
echo "{\"src_ip\":\"192.168.50.7\",\"shasum\":\"$sha4\"}" >"$work/logs/cowrie/cowrie.json"
if HONEYPOT_LOGS_DIR="$work/logs" "$script_dir/check-denylist.sh" "$work/bare-ip-source" "$sha4" "" "10.9.9.9, 192.168.50.7" 2>/dev/null; then
  fail "bare host IP in the CIDR list was skipped instead of blocking its own address"
fi
pass "a bare IP in the CIDR list blocks matching samples"

# --- An unparseable source IP is a logged skip, not a silent pass (#2078). ---
printf 'sample bytes 5' >"$work/v6-source"
sha5=$(sha256sum "$work/v6-source" | cut -d' ' -f1)
echo "{\"src_ip\":\"2001:db8::1\",\"shasum\":\"$sha5\"}" >"$work/logs/cowrie/cowrie.json"
v6err=$(HONEYPOT_LOGS_DIR="$work/logs" "$script_dir/check-denylist.sh" "$work/v6-source" "$sha5" "" "192.168.0.0/16" 2>&1 >/dev/null) \
  || fail "IPv6 source sample was blocked outright"
grep -q "not parseable as IPv4" <<<"$v6err" \
  || fail "IPv6 source skip was silent (stderr: $v6err)"
pass "an IPv6 source produces a logged CIDR-check skip"

echo "OK: denylist blocks what it should and passes what it should"
