#!/usr/bin/env bash
# detonate.sh <runname> - spin up a throwaway overlay of the golden image.
# The golden qcow2 is never written to. Delete the overlay when done.
set -euo pipefail
cd "$(dirname "$0")"

RUN="${1:?usage: ./detonate.sh <runname>}"
GOLDEN="output-win11/win11-finance-detnode.qcow2"
OVERLAY="detonations/$RUN.qcow2"

[ -f "$GOLDEN" ] || { echo "!! golden image missing: $GOLDEN (run ./build.sh first)"; exit 1; }
mkdir -p detonations

echo "==> Creating overlay $OVERLAY (backing: golden image)"
qemu-img create -f qcow2 -b "$GOLDEN" -F qcow2 "$OVERLAY"

OVMF=""
for f in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd \
         /usr/share/edk2/ovmf/OVMF_CODE.fd; do
  [ -f "$f" ] && OVMF="$f" && break
done

echo "==> Booting $RUN on an isolated user-mode network (no outbound by default)"
echo "    FakeNet answers DNS/HTTP/etc. inside the guest."
echo "    VNC display :0  |  Ctrl-C to stop. Overlay kept at $OVERLAY"

exec qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -smp 4 -m 8192 \
  -drive if=pflash,format=raw,readonly=on,file="$OVMF" \
  -drive file="$OVERLAY",if=virtio,format=qcow2 \
  -device virtio-net-pci,netdev=n0 \
  -netdev user,id=n0,restrict=on \
  -smbios type=1,manufacturer="Dell Inc.",product="OptiPlex 7010",serial=7XQ9VM2 \
  -usb -device usb-tablet \
  -display vnc=:0 \
  -name "detnode-$RUN"

# Notes:
#  - netdev 'restrict=on' isolates the guest from the host LAN (FakeNet serves
#    everything inside the guest). Remove it if you want controlled egress.
#  - To instead use a real isolated libvirt bridge (recommended for C2 that
#    needs a routable LAN), replace the -netdev/-device lines with:
#      -device virtio-net-pci,netdev=n0 -netdev bridge,id=n0,br=detnet0
