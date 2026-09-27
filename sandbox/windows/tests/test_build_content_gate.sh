#!/usr/bin/env bash
# verify-built-image-contents.sh / build-with-retry.sh wiring (#3018) --
#
# The restored win11-analysis.qcow2 was promoted to the golden path with no
# content check ever run against it. It had been built on 2026-08-05, three
# days before #956 renamed the 'Samples' share to 'Inbox', so it shipped with
# 'Samples' and no 'Inbox' -- passed its own sha256, and only failed when
# something tried to detonate against it. 04-tools.ps1's comment claimed a
# post-build content check that would have caught this at build time; there
# was none.
#
# These cases drive the real gate with stubbed virt-ls / virt-win-reg, so
# nothing here needs a qcow2, libguestfs, or a Windows disk. What is under
# test is the thing that was actually missing: that the gate runs on the
# built artifact and refuses to promote an image that does not satisfy the
# #100 checklist. The checklist's own logic is unit-tested in
# sandbox/windows/orchestrate/test_run_sample_golden_check.py, and the gate
# delegates to that same implementation rather than re-deciding anything --
# the failure mode kvm_manage.sh's own comment records (two implementations
# of one check, one of them silently wrong).
set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "pass: $*"; }

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
gate="$script_dir/../packer/verify-built-image-contents.sh"
build_retry="$script_dir/../packer/build-with-retry.sh"
[[ -f $gate ]] || fail "verify-built-image-contents.sh not found at $gate"
[[ -f $build_retry ]] || fail "build-with-retry.sh not found at $build_retry"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

stubs="$work/stubs"
install -d "$stubs"

# A real, non-empty file: the gate refuses a missing image before it ever
# looks at tooling, so the "missing file" case would otherwise pass for the
# wrong reason.
image="$work/win11-analysis.qcow2"
: >"$image"

# Stub a healthy guest: every one of #100's four tool directories lists the
# file the check expects, and the registry export carries Inbox + Logs.
# Written as a helper so each case only states what it is varying.
write_stubs() {
  local shares_blob="$1" tool_dirs="$2"
  cat >"$stubs/virt-ls" <<EOF
#!/usr/bin/env bash
# args: -a <disk> <guest_dir>
for d in $tool_dirs; do
  if [ "\${!#}" = "\$d" ]; then
    case "\$d" in
      /Tools/Regshot)          echo 'Regshot-x64-Unicode.exe' ;;
      /Tools/FakeNet)          echo 'fakenet.exe'; echo 'configs' ;;
      /Tools/FakeNet/configs)  echo 'honeypot_fakenet.ini' ;;
      /Tools/SysinternalsSuite) echo 'Procmon64.exe' ;;
    esac
    exit 0
  fi
done
exit 0
EOF
  # virt-win-reg: print the hex(7) REG_MULTI_SZ export the real tool emits.
  cat >"$stubs/virt-win-reg" <<EOF
#!/usr/bin/env bash
cat <<'REGEOF'
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanServer\Shares]
$shares_blob
[HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\LanmanServer\Shares\Security]
"Logs"=hex(3):01,00
REGEOF
EOF
  chmod +x "$stubs/virt-ls" "$stubs/virt-win-reg"
}

# ShareName=Inbox / ShareName=Logs as UTF-16LE hex(7) values, matching the
# shape virt-win-reg actually renders (the name never appears as literal
# text, which is why a substring search over the raw export is meaningless).
utf16_hex() {
  python3 -c '
import sys
blob = ("ShareName=" + sys.argv[1] + "\x00" + "CSCFlags=0" + "\x00" + "\x00\x00").encode("utf-16-le")
print(",".join(f"{b:02x}" for b in blob))
' "$1"
}

ALL_DIRS="/Tools/Regshot /Tools/FakeNet /Tools/FakeNet/configs /Tools/SysinternalsSuite"

# run_gate: drive the gate with the stubs pointed at explicitly, through the
# same VIRT_LS_PATH / VIRT_WIN_REG_PATH env vars run_sample.py itself reads.
# Not done via PATH alone because the gate preflights the resolved absolute
# paths (defaulting to /usr/bin/...), and case 5 depends on that preflight
# firing when a tool genuinely is absent.
run_gate() {
  PATH="$stubs:$PATH" \
  VIRT_LS_PATH="$stubs/virt-ls" \
  VIRT_WIN_REG_PATH="$stubs/virt-win-reg" \
    bash "$gate" "$image" 2>&1
}

# --- case 1: a complete image is promoted ---------------------------------
good_shares="\"Inbox\"=hex(7):$(utf16_hex Inbox)
\"Logs\"=hex(7):$(utf16_hex Logs)"
write_stubs "$good_shares" "$ALL_DIRS"
out="$(run_gate)" || fail "gate rejected a complete image: $out"
grep -q 'PASSED' <<<"$out" || fail "gate did not report PASSED: $out"
pass "complete image passes the gate"

# --- case 2: the live #3018 state -- 'Samples', no 'Inbox' ---------------
# This is the exact share set read off the restored image's registry.
stale_shares="\"Logs\"=hex(7):$(utf16_hex Logs)
\"Public\"=hex(7):$(utf16_hex Public)
\"Samples\"=hex(7):$(utf16_hex Samples)"
write_stubs "$stale_shares" "$ALL_DIRS"
if out="$(run_gate)"; then
  fail "gate ACCEPTED an image with no Inbox share (the #3018 state)"
fi
grep -q "SMB share 'Inbox'" <<<"$out" \
  || fail "gate failed without naming the missing Inbox share: $out"
grep -q 'Nothing has been promoted to the golden path' <<<"$out" \
  || fail "gate failure did not say nothing was promoted: $out"
pass "image with 'Samples' and no 'Inbox' is rejected and named"

# --- case 3: a missing tool file is rejected ----------------------------
# A real directory listing carries more entries than the one file the check
# looks for; the stub returning only 'some-other-file.exe' for Regshot is the
# original #100 regression shape.
cat >"$stubs/virt-ls" <<'EOF'
#!/usr/bin/env bash
for d in /Tools/Regshot /Tools/FakeNet /Tools/FakeNet/configs /Tools/SysinternalsSuite; do
  if [ "${!#}" = "$d" ]; then
    if [ "$d" = /Tools/Regshot ]; then echo 'some-other-file.exe'; exit 0; fi
    case "$d" in
      /Tools/FakeNet)          echo 'fakenet.exe' ;;
      /Tools/FakeNet/configs)  echo 'honeypot_fakenet.ini' ;;
      /Tools/SysinternalsSuite) echo 'Procmon64.exe' ;;
    esac
    exit 0
  fi
done
exit 0
EOF
chmod +x "$stubs/virt-ls"
if out="$(run_gate)"; then
  fail "gate accepted an image missing Regshot"
fi
grep -q 'Regshot' <<<"$out" || fail "gate failure did not name Regshot: $out"
pass "missing tool file is rejected and named"

# --- case 4: a share read that FAILS is never a pass ---------------------
# #2023's own defect: a check that could not run was reported as one that
# passed. virt-ls/virt-win-reg exiting nonzero must fail the gate.
write_stubs "$good_shares" "$ALL_DIRS"
cat >"$stubs/virt-win-reg" <<'EOF'
#!/usr/bin/env bash
echo "virt-win-reg: simulated failure" >&2
exit 1
EOF
chmod +x "$stubs/virt-win-reg"
if out="$(run_gate)"; then
  fail "gate PASSED when the share registry read failed"
fi
pass "a failed share read is a failure, not a pass"

# --- case 5: missing tooling is a failure, not a skip --------------------
# An opt-out here would be a one-flag bypass of the only thing standing
# between a bad build and every detonation guest cloned from it.
write_stubs "$good_shares" "$ALL_DIRS"
if out="$(PATH="$stubs:$PATH" VIRT_LS_PATH="$work/no-such-virt-ls" \
         VIRT_WIN_REG_PATH="$stubs/virt-win-reg" bash "$gate" "$image" 2>&1)"; then
  fail "gate PASSED with virt-ls absent -- a check that could not run is not a check that passed"
fi
grep -q 'no-such-virt-ls' <<<"$out" || fail "gate failure did not name the missing tool: $out"
pass "missing virt-ls fails the gate rather than skipping it"

# --- case 6: build-with-retry runs the gate before promoting -------------
# The wiring itself. Guards the exact regression: a gate nobody calls.
gate_line=$(grep -n 'verify-built-image-contents.sh' "$build_retry" | grep -v '^\s*#' | head -1 | cut -d: -f1)
[[ -n $gate_line ]] || fail "build-with-retry.sh never calls verify-built-image-contents.sh"
promote_line=$(grep -n 'moving \$built_qcow2 -> \$qcow2_path' "$build_retry" | cut -d: -f1)
sha_line=$(grep -n 'sha256sum "\$vm_name.qcow2"' "$build_retry" | cut -d: -f1)
[[ -n $promote_line && -n $sha_line ]] || fail "could not locate promotion/checksum lines"
(( gate_line < promote_line )) \
  || fail "build-with-retry.sh promotes the image (line $promote_line) before verifying it (line $gate_line)"
(( gate_line < sha_line )) \
  || fail "build-with-retry.sh writes the checksum (line $sha_line) before verifying (line $gate_line)"
# A failed gate must not fall through to a successful build exit.
grep -q 'content check FAILED -- refusing to promote' "$build_retry" \
  || fail "build-with-retry.sh does not abort on a content-check failure"
pass "build-with-retry.sh verifies before promoting and before checksumming"

echo "OK: post-build content gate rejects incomplete images and build-with-retry runs it before promotion"
