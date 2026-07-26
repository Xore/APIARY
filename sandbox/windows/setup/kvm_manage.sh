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

VM_NAME="win11-sandbox"
GOLDEN_IMAGE="/golden-images/win11-analysis.qcow2"
VM_DISK="/vms/${VM_NAME}.qcow2"
VM_XML="$(dirname "$0")/../packer/win11-kvm.xml"
SNAP_NAME="GOLDEN_READY"
NET_NAME="sandbox"
NET_XML="$(dirname "$0")/sandbox-network.xml"

log()  { echo "[$(date '+%H:%M:%S')] $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

create_vm() {
    log "Creating thin-clone VM disk from golden image..."
    [[ -f "$GOLDEN_IMAGE" ]] || die "Golden image not found: $GOLDEN_IMAGE. Run packer build first."
    mkdir -p /vms
    qemu-img create -f qcow2 -F qcow2 -b "$GOLDEN_IMAGE" "$VM_DISK"
    log "Disk created: $VM_DISK (thin clone, CoW)"
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
    virsh snapshot-list "$VM_NAME" 2>/dev/null || echo "no snaps