#!/bin/bash
# reset-vm.sh — Xore/honeypot-stack
#
# Reset an analysis VM to a clean state using either:
#   a) An internal libvirt snapshot  (MODE=snapshot)
#   b) A golden image overlay        (MODE=golden)
#
# Usage:
#   ./reset-vm.sh --vm <name> --mode snapshot --snapshot <snap-name>
#   ./reset-vm.sh --vm <name> --mode golden   --golden /path/to/golden.qcow2
#   ./reset-vm.sh --vm <name> --mode golden   --golden /path/to/golden.qcow2 \
#                 --sample /path/to/sample.elf
#
# Options:
#   --vm        VM domain name (required)
#   --mode      'snapshot' or 'golden' (required)
#   --snapshot  Snapshot name (required for mode=snapshot)
#   --golden    Path to golden .qcow2 (required for mode=golden)
#   --overlay   Where to write new overlay (default: /var/lib/libvirt/overlays/<vm>-<ts>.qcow2)
#   --sample    Optional: path to sample file to copy into VM after reset
#   --timeout   Seconds to wait for VM to boot before copying sample (default: 30)
#   --dry-run   Print commands without executing

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────
VM=""
MODE=""
SNAPSHOT=""
GOLDEN=""
OVERLAY_DIR="/var/lib/libvirt/overlays"
OVERLAY=""
SAMPLE=""
TIMEOUT=30
DRY_RUN=0

# ── Argument parsing ───────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vm)       VM="$2";       shift 2 ;;
    --mode)     MODE="$2";     shift 2 ;;
    --snapshot) SNAPSHOT="$2"; shift 2 ;;
    --golden)   GOLDEN="$2";   shift 2 ;;
    --overlay)  OVERLAY="$2";  shift 2 ;;
    --sample)   SAMPLE="$2";   shift 2 ;;
    --timeout)  TIMEOUT="$2"; shift 2 ;;
    --dry-run)  DRY_RUN=1;     shift   ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────
[[ -z "$VM" ]]   && { echo "ERROR: --vm is required";   exit 1; }
[[ -z "$MODE" ]] && { echo "ERROR: --mode is required"; exit 1; }

if [[ "$MODE" == "snapshot" && -z "$SNAPSHOT" ]]; then
  echo "ERROR: --snapshot is required for mode=snapshot"; exit 1
fi
if [[ "$MODE" == "golden" && -z "$GOLDEN" ]]; then
  echo "ERROR: --golden is required for mode=golden"; exit 1
fi
if [[ "$MODE" == "golden" && ! -f "$GOLDEN" ]]; then
  echo "ERROR: golden image not found: $GOLDEN"; exit 1
fi

# ── Helpers ──────────────────────────────────────────────────────────────

run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "[DRY-RUN] $*"
  else
    echo "[▶] $*"
    "$@"
  fi
}

log() { echo "[$(date +%H:%M:%S)] $*"; }

wait_for_agent() {
  local vm="$1" timeout="$2" elapsed=0
  log "Waiting for QEMU guest agent on $vm (timeout ${timeout}s)..."
  while ! virsh qemu-agent-command "$vm" '{"execute":"guest-ping"}' &>/dev/null; do
    sleep 2; elapsed=$((elapsed + 2))
    if [[ $elapsed -ge $timeout ]]; then
      log "WARNING: guest agent did not respond after ${timeout}s"
      return 1
    fi
  done
  log "Guest agent ready."
}

copy_sample_to_vm() {
  local vm="$1" sample="$2"
  local dest_name
  dest_name=$(basename "$sample")

  log "Copying $sample into $vm..."
  # Write sample via guest agent (no shared folders needed)
  local b64
  b64=$(base64 -w 0 "$sample")
  virsh qemu-agent-command "$vm" \
    "{\"execute\":\"guest-file-open\",\
       \"arguments\":{\"path\":\"C:\\\\Users\\\\Public\\\\$dest_name\",\
       \"mode\":\"wb\"}}"
  # For Linux guests, adjust the path:
  # virsh qemu-agent-command "$vm" \
  #   "{\"execute\":\"guest-file-open\",\
  #      \"arguments\":{\"path\":\"/tmp/$dest_name\",\"mode\":\"wb\"}}"
  log "Sample $dest_name available inside $vm."
}

# ── MODE: snapshot ─────────────────────────────────────────────────────────

if [[ "$MODE" == "snapshot" ]]; then
  log "MODE=snapshot | VM=$VM | SNAPSHOT=$SNAPSHOT"

  # Verify snapshot exists
  if ! virsh snapshot-list "$VM" --name 2>/dev/null | grep -qx "$SNAPSHOT"; then
    echo "ERROR: Snapshot '$SNAPSHOT' not found on VM '$VM'"
    echo "Available snapshots:"
    virsh snapshot-list "$VM"
    exit 1
  fi

  # Destroy if running
  if virsh domstate "$VM" 2>/dev/null | grep -q running; then
    log "Destroying running VM $VM..."
    run virsh destroy "$VM"
    sleep 1
  fi

  log "Reverting $VM to snapshot $SNAPSHOT..."
  run virsh snapshot-revert "$VM" "$SNAPSHOT" --running
  log "VM $VM reverted and started."

  if [[ -n "$SAMPLE" ]]; then
    wait_for_agent "$VM" "$TIMEOUT"
    copy_sample_to_vm "$VM" "$SAMPLE"
  fi

  exit 0
fi

# ── MODE: golden ───────────────────────────────────────────────────────────
if [[ "$MODE" == "golden" ]]; then
  log "MODE=golden | VM=$VM | GOLDEN=$GOLDEN"

  TS=$(date +%s)
  mkdir -p "$OVERLAY_DIR"

  if [[ -z "$OVERLAY" ]]; then
    OVERLAY="${OVERLAY_DIR}/${VM}-${TS}.qcow2"
  fi

  # 1. Destroy and undefine existing analysis VM if it exists
  if virsh domstate "$VM" &>/dev/null; then
    log "Destroying and undefining existing VM $VM..."
    run virsh destroy  "$VM" 2>/dev/null || true
    sleep 1
    run virsh undefine "$VM" 2>/dev/null || true
  fi

  # 2. Remove old overlay for this VM name
  OLD_OVERLAYS=( "${OVERLAY_DIR}/${VM}-"*.qcow2 )
  for old in "${OLD_OVERLAYS[@]}"; do
    [[ -f "$old" ]] && run rm -f "$old" && log "Removed old overlay: $old"
  done

  # 3. Create fresh thin overlay on top of golden image
  log "Creating overlay $OVERLAY on top of $GOLDEN..."
  run qemu-img create -f qcow2 -b "$GOLDEN" -F qcow2 "$OVERLAY"

  # 4. Clone domain XML with new overlay, define and start
  #    We assume the golden VM domain XML is registered as "golden-<basename>"
  GOLDEN_BASENAME=$(basename "$GOLDEN" .qcow2)
  GOLDEN_DOMAIN="golden-${GOLDEN_BASENAME}"

  if ! virsh dominfo "$GOLDEN_DOMAIN" &>/dev/null; then
    echo "ERROR: Golden domain '$GOLDEN_DOMAIN' is not defined in libvirt."
    echo "Register it once with: virsh define <golden-domain.xml>"
    exit 1
  fi

  log "Cloning domain $GOLDEN_DOMAIN -> $VM with overlay $OVERLAY..."
  run virt-clone \
    --original       "$GOLDEN_DOMAIN" \
    --name           "$VM" \
    --file           "$OVERLAY" \
    --preserve-data

  run virsh start "$VM"
  log "VM $VM started."

  if [[ -n "$SAMPLE" ]]; then
    wait_for_agent "$VM" "$TIMEOUT"
    copy_sample_to_vm "$VM" "$SAMPLE"
  fi

  exit 0
fi

echo "ERROR: Unknown mode '$MODE'. Use 'snapshot' or 'golden'."
exit 1
