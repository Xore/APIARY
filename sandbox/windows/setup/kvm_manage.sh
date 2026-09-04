#!/usr/bin/env bash
# kvm_manage.sh — KVM/virsh lifecycle helper for Windows 11 sandbox
# Usage: ./kvm_manage.sh <command>
#
# Commands:
#   create       Create thin-clone VM from golden qcow2
#   revert       Reset to a fresh clone of the golden image (before each
#                detonation; also serves as "first run after Packer build")
#   start        Start the VM
#   stop         Forcefully stop the VM
#   status       Show VM status
#   net-setup    Create isolated libvirt sandbox network
#   net-teardown Remove sandbox network
#
# There is no `snapshot`/GOLDEN_READY-snapshot command. virsh's memory-state
# snapshots are blocked outright by this domain's <cpu migratable='off'/>
# (deliberate -- see win11-kvm.xml's own comment on why), and disk-only
# snapshots hit a separate, reproducible QEMU/libvirt bug where a freshly
# spawned process fails to open the golden image on the resulting multi-layer
# backing chain, even though file permissions are fine (see #358). Since the
# golden image is already never written to, "revert to golden" is just
# `revert`: throw away the per-run CoW clone and make a fresh one. This is a
# cold boot every run, not a memory-state resume -- slower (~1-2 min instead
# of ~45s) but with no snapshot-machinery failure mode.

set -euo pipefail

# #2023: used to locate orchestrate/run_sample.py, whose
# decode_smb_share_names() this script reuses rather than reimplementing.
KVM_MANAGE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

VM_NAME="${VM_NAME:-win11-sandbox}"
# Defaults follow win11-analysis.pkr.hcl: the build deliberately puts both the
# ISO and the 25-35 GB golden image on the large /var spindle rather than the
# 233 GB root NVMe. Override for a host with a different layout — but then also
# update the <source file> in packer/win11-kvm.xml, which cannot read this.
SANDBOX_ROOT="${SANDBOX_ROOT:-/var/dockge/sandbox}"
GOLDEN_IMAGE="${GOLDEN_IMAGE:-$SANDBOX_ROOT/golden-images/win11-analysis.qcow2}"
VM_DISK="${VM_DISK:-$SANDBOX_ROOT/vms/${VM_NAME}.qcow2}"
# Overridable for the same reason VM_NAME/GOLDEN_IMAGE/VM_DISK above are: this
# host runs more than one Windows domain off this script. win11-cape has its
# own domain XML and its own libvirt network (sandbox/cape/win11-cape-kvm.xml,
# sandbox/cape/network.xml, network name "cape"), and before these three were
# overridable there was no way to drive it from here at all -- which is why
# nothing in the installer ever created that VM (#1609 Phase 7).
VM_XML="${VM_XML:-$(dirname "$0")/../packer/win11-kvm.xml}"
NET_NAME="${NET_NAME:-sandbox}"
NET_XML="${NET_XML:-$(dirname "$0")/sandbox-network.xml}"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

verify_golden_checksum() {
    # #86: the golden image is the root of trust for every detonation guest
    # cloned from it -- an unverified multi-GB file sitting on a shared
    # spindle for months between rebuilds (build-with-retry.sh writes the
    # .sha256 once, right after a successful build) is exactly the thing
    # worth hashing before trusting it. Failing the clone on mismatch is the
    # point, not a warning to skim past.
    #
    # A full sha256sum of a 25-35 GB file takes real time (well over a
    # minute), and revert happens before every single detonation -- possibly
    # several times an hour in a busy queue. Re-hashing an unchanged file
    # that often is wasted work, so the result is cached against the golden
    # image's mtime+size in a sentinel file next to the checksum; corruption
    # between two reverts with no intervening rebuild would only be caught
    # on the next actual re-verification, which is the accepted tradeoff for
    # not paying the full hash cost on every revert.
    local sums="$GOLDEN_IMAGE.sha256"
    [[ -f "$sums" ]] || { log "No $sums found -- skipping integrity check (run build-with-retry.sh to generate one)."; return 0; }

    local stamp="$GOLDEN_IMAGE.sha256.verified"
    local current
    current="$(stat -c '%Y-%s' "$GOLDEN_IMAGE")"
    if [[ -f "$stamp" ]] && [[ "$(cat "$stamp")" == "$current" ]]; then
        return 0
    fi

    log "Verifying golden image checksum (first use since last rebuild)..."
    ( cd "$(dirname "$GOLDEN_IMAGE")" && sha256sum -c "$(basename "$sums")" ) \
        || die "Golden image checksum mismatch: $GOLDEN_IMAGE does not match $sums. Refusing to clone -- every detonation guest would inherit a corrupted or tampered image."
    echo "$current" > "$stamp"
    log "Golden image checksum verified."
}

clone_disk() {
    # A backing-file clone, not a copy: the golden image is never written to,
    # so a sample cannot contaminate future runs and this is cheap to redo.
    [[ -f "$GOLDEN_IMAGE" ]] || die "Golden image not found: $GOLDEN_IMAGE. Run packer build first."
    [[ -e "$VM_DISK" ]] && die "$VM_DISK already exists. Remove it deliberately — it may hold a detonated guest."
    verify_golden_checksum
    mkdir -p "$(dirname "$VM_DISK")"
    qemu-img create -f qcow2 -F qcow2 -b "$GOLDEN_IMAGE" "$VM_DISK"
    log "Disk created: $VM_DISK (thin clone, CoW)"
}

verify_golden_image_contents() {
    # #100/#2023: the same five-point checklist
    # orchestrate/run_sample.py's verify_golden_image_contents() enforces on
    # every automated detonation (that is the canonical implementation, with
    # the reasoning and unit tests) — this is the manual/operator-path twin
    # so a `kvm_manage.sh revert` run by hand gets the same guard, not just
    # the automated pipeline. Offline via guestfish against "$1", before
    # `virsh start` — same ordering constraint as clone_disk() callers below:
    # libguestfs and a running qemu process cannot both hold the qcow2 open.
    local disk="$1"
    local -a tool_files=(
        "/Tools/Regshot/Regshot-x64-Unicode.exe"
        "/Tools/FakeNet/fakenet.exe"
        "/Tools/FakeNet/configs/honeypot_fakenet.ini"
        "/Tools/SysinternalsSuite/Procmon64.exe"
    )
    local -a missing=()
    local path present
    for path in "${tool_files[@]}"; do
        present="$(guestfish --ro -a "$disk" -i is-file "$path" 2>/dev/null || echo "false")"
        [[ "$present" == "true" ]] || missing+=("$path")
    done

    # Share names come out of the offline SYSTEM hive via virt-win-reg, the
    # same tool and key the Python twin uses. Not guestfish's hivex-*
    # commands: `guestfish --ro -a DISK -i hivex-open --unsafe ...` exits 1
    # with `unrecognized option '--unsafe'` before it opens the disk at all
    # (verified live), and hivex-node-get-value wants an integer node handle
    # plus a key name, not a path.
    #
    # This is NOT best-effort and does not degrade to a pass: a read failure
    # is a check that did not run, and reporting that as success is exactly
    # the defect #2023 exists to remove.
    #
    # virt-win-reg renders REG_MULTI_SZ as `hex(7):43,00,...` (UTF-16LE), so
    # the share name is never literal text in the export -- decode it and
    # read the authoritative `ShareName=` field. Scoped to the Shares key
    # itself; the \Shares\Security subkey repeats the same value names
    # against ACL blobs, which do not tell us a share exists.
    local shares_reg share_names
    if ! shares_reg="$(virt-win-reg "$disk" \
        'HKLM\SYSTEM\ControlSet001\Services\LanmanServer\Shares' 2>&1)"; then
        die "Could not read the SMB share registry state from $disk via virt-win-reg: ${shares_reg}. The SMB-share half of the #100 check could not run; refusing to report it as passed."
    fi
    # Decoding is delegated to run_sample.py's decode_smb_share_names()
    # rather than reimplemented here. That is deliberate: the first cut of
    # this twin hand-rolled the UTF-16LE decode in awk and silently returned
    # *no* share names, because gawk evaluates ("0x" byte)+0 as 0 without
    # --non-decimal-data -- so every byte decoded to NUL and the check
    # reported both shares missing on an image that has one of them. Two
    # implementations of one parse is how the twins drift; there is now one.
    local decoder="${KVM_MANAGE_DIR}/../orchestrate/run_sample.py"
    if [[ ! -f "$decoder" ]]; then
        die "Cannot find the share-name decoder at $decoder; refusing to report the #100 SMB-share check as passed."
    fi
    share_names="$(printf '%s' "$shares_reg" | python3 -c '
import importlib.util, sys
spec = importlib.util.spec_from_file_location("run_sample", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
print("\n".join(sorted(mod.decode_smb_share_names(sys.stdin.read()))))
' "$decoder")" || die "Could not decode the SMB share registry export from $disk; refusing to report the #100 SMB-share check as passed."
    local want
    for want in Inbox Logs; do
        grep -qxF "$want" <<<"$share_names" || missing+=("SMB share '$want'")
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Golden image content check failed: missing ${missing[*]}. The provisioner (packer/scripts/04-tools.ps1) may have regressed -- see #100/#2023. Refusing to start this VM against an incomplete golden image; rebuild it before retrying."
    fi
    log "Golden image content check passed (Regshot, FakeNet, Procmon, SMB shares present)."
}

create_vm() {
    log "Creating thin-clone VM disk from golden image..."
    [[ -f "$VM_XML" ]] || die "Domain XML not found: $VM_XML"
    clone_disk
    verify_golden_image_contents "$VM_DISK"
    if ! grep -q "$VM_DISK" "$VM_XML"; then
        log "WARNING: $VM_XML does not reference $VM_DISK — the domain will boot the wrong disk."
    fi
    log "Defining VM in libvirt..."
    virsh define "$VM_XML"
    log "VM '$VM_NAME' defined. Run: $0 start"
}

revert_vm() {
    log "Resetting VM to a fresh clone of the golden image..."
    virsh destroy "$VM_NAME" >/dev/null 2>&1 || true
    [[ -e "$VM_DISK" ]] && rm -f "$VM_DISK"
    clone_disk
    verify_golden_image_contents "$VM_DISK"
    virsh start "$VM_NAME"
    log "VM reset and running. WinRM available at 10.10.10.2:5985 in ~1-2min (cold boot)."
}

start_vm() {
    virsh start "$VM_NAME" && log "VM started"
}

stop_vm() {
    virsh destroy "$VM_NAME" 2>/dev/null && log "VM stopped" || log "VM was not running"
}

status_vm() {
    echo "=== VM State ==="
    virsh domstate "$VM_NAME" 2>/dev/null || echo "not found"
}

net_setup() {
    log "Creating sandbox network: $NET_NAME"
    [[ -f "$NET_XML" ]] || die "Network XML not found: $NET_XML"
    # Always destroy+undefine first, not just define-if-missing: `virsh
    # net-define` on an already-existing network fails outright ("network
    # 'sandbox' already exists"), and even if it didn't, updating the
    # persistent XML without a destroy first wouldn't reach the live dnsmasq
    # config either. Same fix sandbox/ghosts/install-network.sh already
    # applies for the GHOSTS network (see its own comment) -- confirmed live
    # (#518) that this one needed the identical fix for a clean re-run.
    virsh net-destroy "$NET_NAME" >/dev/null 2>&1 || true
    virsh net-undefine "$NET_NAME" >/dev/null 2>&1 || true
    virsh net-define "$NET_XML"
    virsh net-start "$NET_NAME"
    virsh net-autostart "$NET_NAME"
    log "Network '$NET_NAME' created and started."
}

net_teardown() {
    log "Removing sandbox network: $NET_NAME"
    virsh net-destroy "$NET_NAME" 2>/dev/null || true
    virsh net-undefine "$NET_NAME" 2>/dev/null || true
    log "Network '$NET_NAME' removed."
}

CMD="${1:-}"
[[ -n "$CMD" ]] || { echo "Usage: $0 <create|revert|start|stop|status|net-setup|net-teardown>"; exit 1; }

case "$CMD" in
    create)       create_vm      ;;
    revert)       revert_vm      ;;
    start)        start_vm       ;;
    stop)         stop_vm        ;;
    status)       status_vm      ;;
    net-setup)    net_setup      ;;
    net-teardown) net_teardown   ;;
    *) die "Unknown command: $CMD. Run $0 without args for usage." ;;
esac
