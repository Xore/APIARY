#!/usr/bin/env bash
# kvm_manage.sh — KVM/virsh lifecycle helper for Windows 11 sandbox
# Usage: ./kvm_manage.sh <command>
#
# Commands:
#   create       Create thin-clone VM from golden qcow2
#   snapshot     Take GOLDEN_READY snapshot (first run after Packer build)
#   revert       Revert to GOLDEN_READY (before each detonation)
#   start        Start the VM
#   stop         Forcefully stop the VM
#   status       Show VM + snapshot status
#   net-setup    Create isolated libvirt sandbox network
#   net-teardown Remove sandbox network

set -euo pipefail

VM_NAME="${VM_NAME:-win11-sandbox}"
# Defaults follow win11-analysis.pkr.hcl: the build deliberately puts both the
# ISO and the 25-35 GB golden image on the large /var spindle rather than the
# 233 GB root NVMe. Override for a host with a different layout — but then also
# update the <source file> in packer/win11-kvm.xml, which cannot read this.
SANDBOX_ROOT="${SANDBOX_ROOT:-/var/dockge/sandbox}"
GOLDEN_IMAGE="${GOLDEN_IMAGE:-$SANDBOX_ROOT/golden-images/win11-analysis.qcow2}"
VM_DISK="${VM_DISK:-$SANDBOX_ROOT/vms/${VM_NAME}.qcow2}"
VM_XML="$(dirname "$0")/../packer/win11-kvm.xml"
SNAP_NAME="${SNAP_NAME:-GOLDEN_READY}"
NET_NAME="sandbox"
NET_XML="$(dirname "$0")/sandbox-network.xml"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

create_vm() {
    log "Creating thin-clone VM disk from golden image..."
    [[ -f "$GOLDEN_IMAGE" ]] || die "Golden image not found: $GOLDEN_IMAGE. Run packer build first."
    [[ -f "$VM_XML" ]] || die "Domain XML not found: $VM_XML"
    # A backing-file clone, not a copy: reverting is cheap and the golden image
    # is never written to, so a sample cannot contaminate future runs.
    [[ -e "$VM_DISK" ]] && die "$VM_DISK already exists. Remove it deliberately — it may hold a detonated guest."
    mkdir -p "$(dirname "$VM_DISK")"
    qemu-img create -f qcow2 -F qcow2 -b "$GOLDEN_IMAGE" "$VM_DISK"
    log "Disk created: $VM_DISK (thin clone, CoW)"
    if ! grep -q "$VM_DISK" "$VM_XML"; then
        log "WARNING: $VM_XML does not reference $VM_DISK — the domain will boot the wrong disk."
    fi
    log "Defining VM in libvirt..."
    virsh define "$VM_XML"
    log "VM '$VM_NAME' defined. Run: $0 start"
}

take_snapshot() {
    log "Taking golden snapshot: $SNAP_NAME"
    virsh snapshot-create-as "$VM_NAME" "$SNAP_NAME" \
        --description "FLARE-VM + Sysmon + FakeNet-NG + PS logging ready" \
        --atomic
    log "Snapshot '$SNAP_NAME' created. This is the revert target for all detonation runs."
}

revert_vm() {
    log "Reverting VM to snapshot: $SNAP_NAME"
    virsh snapshot-revert "$VM_NAME" "$SNAP_NAME" --running
    log "VM reverted and running. WinRM available at 10.10.10.2:5985 in ~45s."
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
    echo "=== Snapshots ==="
    virsh snapshot-list "$VM_NAME" 2>/dev/null || echo "no snapshots"
}

net_setup() {
    log "Creating sandbox network: $NET_NAME"
    [[ -f "$NET_XML" ]] || die "Network XML not found: $NET_XML"
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
[[ -n "$CMD" ]] || { echo "Usage: $0 <create|snapshot|revert|start|stop|status|net-setup|net-teardown>"; exit 1; }

case "$CMD" in
    create)       create_vm      ;;
    snapshot)     take_snapshot  ;;
    revert)       revert_vm      ;;
    start)        start_vm       ;;
    stop)         stop_vm        ;;
    status)       status_vm      ;;
    net-setup)    net_setup      ;;
    net-teardown) net_teardown   ;;
    *) die "Unknown command: $CMD. Run $0 without args for usage." ;;
esac
