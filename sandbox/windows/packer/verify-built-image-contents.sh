#!/usr/bin/env bash
# verify-built-image-contents.sh — run the #100/#2023 golden-image content
# check against a freshly built qcow2, BEFORE it is promoted to the golden
# path and before its .sha256 is written.
#
# Why this exists (#3018): build-with-retry.sh used to promote a built image
# straight to $output_dir/$vm_name.qcow2 and write its checksum, with no
# content verification whatsoever. The only callers of
# verify_golden_image_contents() were run_sample.py (detonation time) and
# kvm_manage.sh (manual operator create/revert) -- so the first time anything
# ever asked "is this image actually complete?" was at the first detonation
# attempt against a clone of it.
#
# That is how the restored win11-analysis.qcow2 got as far as it did: built
# 2026-08-05 (C:\golden_image_build.txt), three days before #956 renamed the
# 'Samples' share to 'Inbox', so it shipped with 'Samples' and no 'Inbox'. The
# checksum was written and verified, so it passed every check that looks at
# bytes, and the mismatch only surfaced once something tried to detonate
# against it. 04-tools.ps1's own comment claimed a "post-build content check"
# that would have caught this at build time -- there was none.
#
# This is the same defect class as #2023 (an invariant believed enforced and
# not), at the one point in the pipeline where catching it is still cheap: the
# image is not yet the root of trust for any detonation guest, and a failed
# build is a re-run rather than a restore-from-backup plus a code change.
#
# Deliberately NOT best-effort, and deliberately no opt-out. A check that
# could not run is not a check that passed (#2023): if the guest-inspection
# tooling is missing, this fails the build rather than promoting an
# unverified image. The build host already needs libguestfs to build at all
# (packer-golden-image-guide.md Step 0), and the provisioner itself hard-fails
# on a missing SMB share (04-tools.ps1), so a build that reaches this point
# with the tooling absent is already a host that cannot be trusted to have
# built what it thinks it built.
#
# Decoding is delegated to run_sample.py's verify_golden_image_contents()
# rather than reimplemented here -- the canonical implementation, with the
# reasoning and the unit tests. kvm_manage.sh's own comment records why two
# implementations of this one check is a bad idea: its first cut hand-rolled
# the UTF-16LE decode in awk and silently returned *no* share names.
#
# Usage: verify-built-image-contents.sh [path-to-qcow2]
#   Defaults to the standard build output path. Read-only (virt-ls and
#   virt-win-reg without --merge never write), so it is safe to run against an
#   image a domain is currently using -- unlike harden-defender-offline.sh,
#   which writes and therefore refuses while qemu holds the file.
set -euo pipefail

image="${1:-/var/dockge/sandbox/golden-images/win11-analysis.qcow2}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="$script_dir/../orchestrate/run_sample.py"

if [ ! -f "$image" ]; then
  echo "verify-built-image-contents: $image does not exist" >&2
  exit 1
fi

if [ ! -f "$checker" ]; then
  echo "verify-built-image-contents: cannot find the content checker at $checker" >&2
  echo "  refusing to promote an image whose contents were never checked." >&2
  exit 1
fi

# The same tool paths run_sample.py itself resolves (VIRT_LS_PATH /
# VIRT_WIN_REG_PATH), preflighted here so the failure names the missing
# package instead of surfacing as a traceback from a subprocess.
for tool in "${VIRT_LS_PATH:-/usr/bin/virt-ls}" "${VIRT_WIN_REG_PATH:-/usr/bin/virt-win-reg}"; do
  if [ ! -x "$tool" ]; then
    echo "verify-built-image-contents: $tool is missing or not executable." >&2
    echo "  The #100/#2023 content check cannot run without it, and a check that" >&2
    echo "  could not run is not a check that passed -- refusing to promote" >&2
    echo "  $image. On Debian: apt install libguestfs-tools libguestfs-winsupport." >&2
    echo "  On EL: dnf install guestfs-tools virt-win-reg libguestfs-winsupport." >&2
    echo "  (libguestfs-winsupport is what makes the guest's NTFS volume readable" >&2
    echo "   by the virt-* tools at all.)" >&2
    exit 1
  fi
done

echo "=== verify-built-image-contents: $(date -u +%FT%TZ) -- image: $image ==="

# verify_golden_image_contents() raises RuntimeError listing every missing
# item, and read_smb_share_names()/_virt_ls_ro() raise on a failed read rather
# than reporting it as absent. Both are caught here only to print the message
# without a traceback; the nonzero exit is the whole point.
if ! python3 -c '
import importlib.util, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("run_sample", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
try:
    mod.verify_golden_image_contents(Path(sys.argv[2]))
except RuntimeError as exc:
    print(f"verify-built-image-contents: FAILED: {exc}", file=sys.stderr)
    sys.exit(1)
' "$checker" "$image"; then
  cat >&2 <<EOF

=== The image above is NOT fit to become the golden image. ===
    It was left in place rather than deleted so it can be inspected:
      virt-ls   -a $image /Tools/Regshot
      virt-win-reg "$image" 'HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Shares'
    Nothing has been promoted to the golden path and no .sha256 was written.

    If a share is missing, the provisioner is the thing to look at first
    (packer/scripts/04-tools.ps1) -- it creates C:\Inbox and New-SmbShare's
    both shares, and throws if Get-SmbShare cannot see them. An image built
    before that provisioner existed cannot be repaired by re-running the
    build; it needs a from-scratch rebuild (IMPLEMENTATION_PLAN.md Phase 0).
EOF
  exit 1
fi

echo "=== verify-built-image-contents: PASSED (Regshot, FakeNet exe + config,"
echo "    Procmon, and the Inbox/Logs SMB shares all present) ==="
