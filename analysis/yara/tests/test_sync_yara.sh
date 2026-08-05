#!/usr/bin/env bash
# Tests for sync-yara.sh and scripts/check-yara-corpus.sh.
#
# Runs against a throwaway git repository standing in for upstream and a copy
# of this tree, so nothing here touches the real corpus. Needs a real yara(1):
# the whole point of the sync is that a corpus is compiled before it is
# adopted, and a stubbed compiler would test the stub.
#
# Usage: analysis/yara/tests/test_sync_yara.sh
set -euo pipefail

if ! command -v yara >/dev/null 2>&1 && ! command -v yarac >/dev/null 2>&1; then
  echo "SKIP: yara is not installed (apt-get install -y yara)"
  exit 0
fi

src_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
compile() {
  if command -v yarac >/dev/null 2>&1; then yarac -w "$1" /dev/null
  else yara -w "$1" /dev/null >/dev/null; fi
}

# ── A tree to sync into ──────────────────────────────────────────────────────
root="$tmp/root"
mkdir -p "$root/analysis/yara/rules" "$root/scripts"
cp "$src_root/analysis/yara/sync-yara.sh" "$root/analysis/yara/"
cp "$src_root/scripts/check-yara-corpus.sh" "$root/scripts/"
cat > "$root/analysis/yara/rules/honeypot.yar" <<'EOF'
rule HP_Local_Marker {
  condition: uint16(0) == 0x5a4d
}
EOF

# ── A repository to sync from ────────────────────────────────────────────────
up="$tmp/upstream"
mkdir -p "$up/yara-rules/auto"
cat > "$up/yara-rules/good.yar" <<'EOF'
rule Upstream_Good { strings: $a = "totally-benign" condition: $a }
EOF
cat > "$up/yara-rules/broken.yar" <<'EOF'
rule Upstream_Broken { condition: this is not yara }
EOF
cat > "$up/yara-rules/collides.yar" <<'EOF'
rule HP_Local_Marker { condition: uint16(0) == 0x4d5a }
EOF
cat > "$up/yara-rules/auto/generated.yar" <<'EOF'
rule AutoGen_Sample {
  meta: auto_generated = true
  strings: $a = "auto-generated-marker" condition: $a
}
EOF
cat > "$up/yara-rules/README.md" <<'EOF'
not a rule file
EOF
git -C "$up" init -q -b main
git -C "$up" -c user.email=t@example.invalid -c user.name=test add -A
git -C "$up" -c user.email=t@example.invalid -c user.name=test commit -qm corpus
upstream_commit="$(git -C "$up" rev-parse HEAD)"

run_sync() { ( cd "$root" && YARA_UPSTREAM_REPO="$up" "$root/analysis/yara/sync-yara.sh" "$@" ); }
run_check() { ( cd "$root" && "$root/scripts/check-yara-corpus.sh" ); }

# ── check passes when nothing is vendored ────────────────────────────────────
run_check >/dev/null || fail "check should skip cleanly with no corpus vendored"
pass "check skips when no corpus is vendored"

# ── sync ─────────────────────────────────────────────────────────────────────
out="$(run_sync 2>&1)" || fail "sync exited non-zero:\n$out"
rules="$root/analysis/yara/rules"

[ -f "$rules/upstream/good.yar" ] || fail "a compiling upstream rule was not adopted"
pass "compiling upstream rules are adopted"

[ ! -e "$rules/upstream/broken.yar" ] || fail "a rule that does not compile was shipped to the scanner"
grep -q "broken.yar (does not compile: " <<<"$out" || fail "the drop was not reported:\n$out"
pass "a rule that does not compile is dropped, and the drop is reported"

[ ! -e "$rules/upstream/collides.yar" ] || fail "a rule redefining a local rule name was adopted"
grep -q "duplicate rule HP_Local_Marker" <<<"$out" || fail "the collision was not reported"
pass "a rule identifier that collides with a local rule is dropped"

grep -q "^upstream/broken.yar (does not compile: " "$rules/upstream/DROPPED" ||
  fail "DROPPED does not record the file that failed to compile"
grep -q "^upstream/broken.yar (does not compile: .\{8,\}" "$rules/upstream/DROPPED" ||
  fail "DROPPED does not carry yara's own error through: $(cat "$rules/upstream/DROPPED")"
grep -q "^upstream/collides.yar (duplicate rule " "$rules/upstream/DROPPED" ||
  fail "DROPPED does not record the colliding file"
pass "DROPPED records every rejected file with its reason"

[ -f "$rules/upstream/auto/generated.yar" ] || fail "auto/ was not vendored"
grep -qx "AutoGen_Sample" "$rules/upstream/AUTO_RULES" || fail "AUTO_RULES does not list the auto rule"
grep -qx "Upstream_Good" "$rules/upstream/AUTO_RULES" && fail "AUTO_RULES lists a curated rule"
pass "auto-generated rule names are recorded separately from curated ones"

# ── the local rules are never touched ────────────────────────────────────────
grep -q "HP_Local_Marker" "$rules/honeypot.yar" || fail "local rules were overwritten"
[ "$(find "$rules" -maxdepth 1 -name '*.yar' | wc -l)" = 2 ] || fail "sync wrote loose files into rules/"
pass "local rules are untouched and upstream stays in its own subtree"

# ── the index is what the scanner loads ──────────────────────────────────────
head -3 "$rules/index.yar" | grep -q 'include "honeypot.yar"' || fail "index.yar does not include the local rules"
grep -q 'include "upstream/good.yar"' "$rules/index.yar" || fail "index.yar does not include the adopted rule"
grep -q 'broken.yar' "$rules/index.yar" && fail "index.yar includes a dropped file"
compile "$rules/index.yar" || fail "the generated index does not compile"
pass "index.yar includes local plus adopted rules and compiles"

# ── the pin ──────────────────────────────────────────────────────────────────
grep -qx "commit=$upstream_commit" "$rules/upstream.lock" || fail "upstream.lock does not pin the fetched commit"
grep -q "^manifest_sha256=[0-9a-f]\{64\}$" "$rules/upstream.lock" || fail "upstream.lock has no manifest hash"
grep -qx "files=2" "$rules/upstream.lock" || fail "upstream.lock miscounts the adopted files"
pass "upstream.lock pins the commit and the tree"

run_check >/dev/null || fail "check failed on a freshly synced tree"
pass "check passes on a freshly synced tree"

# ── tampering is caught ──────────────────────────────────────────────────────
echo "// local edit" >> "$rules/upstream/good.yar"
run_check >/dev/null 2>&1 && fail "an edit to a vendored rule went undetected"
pass "an edit to a vendored rule fails the check"
run_sync >/dev/null 2>&1 || fail "re-sync after a local edit failed"
run_check >/dev/null || fail "re-sync did not restore a clean tree"
pass "re-syncing restores the vendored tree"

# index.yar is outside the manifest, so an index that has lost an include passes
# every hash check above while the rule it named silently stops being scanned.
grep -v 'upstream/good.yar' "$rules/index.yar" > "$tmp/index.trimmed"
cp "$rules/index.yar" "$tmp/index.orig"
cp "$tmp/index.trimmed" "$rules/index.yar"
run_check >/dev/null 2>&1 && fail "a vendored rule that index.yar no longer includes went undetected"
pass "a vendored rule missing from index.yar fails the check"
cp "$tmp/index.orig" "$rules/index.yar"
run_check >/dev/null || fail "check did not recover once index.yar was restored"

# ── an upstream with nothing usable must not wipe the corpus ─────────────────
before="$(sha256sum "$rules/upstream/good.yar" | cut -d' ' -f1)"
bad="$tmp/bad-upstream"
mkdir -p "$bad/yara-rules"
cp "$up/yara-rules/broken.yar" "$bad/yara-rules/"
git -C "$bad" init -q -b main
git -C "$bad" -c user.email=t@example.invalid -c user.name=test add -A
git -C "$bad" -c user.email=t@example.invalid -c user.name=test commit -qm broken
( cd "$root" && YARA_UPSTREAM_REPO="$bad" "$root/analysis/yara/sync-yara.sh" >/dev/null 2>&1 ) &&
  fail "a wholly broken upstream was adopted"
[ "$(sha256sum "$rules/upstream/good.yar" | cut -d' ' -f1)" = "$before" ] ||
  fail "a failed sync damaged the existing corpus"
run_check >/dev/null || fail "check failed after a rejected sync"
pass "a wholly broken upstream is rejected and the existing corpus survives"

echo
echo "all sync-yara tests passed"
