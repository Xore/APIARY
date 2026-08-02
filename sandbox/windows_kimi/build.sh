#!/usr/bin/env bash
# build.sh - host prep + unattended Packer build of the Win11 detnode image.
# Tested target: Ubuntu 26.04, QEMU/KVM, Packer >= 1.10.
set -euo pipefail
cd "$(dirname "$0")"

ISO_URL="${ISO_URL:-/opt/iso/Win11_24H2_English_x64.iso}"
ISO_SUM="${ISO_SUM:-}"

echo "==> Installing host packages"
sudo apt update
sudo apt install -y qemu-kvm libvirt-daemon-system libguestfs-tools \
  ovmf swtpm swtpm-tools mkisofs cpu-checker git curl

if ! command -v packer >/dev/null; then
  echo "==> Installing Packer"
  wget -O- https://apt.releases.hashicorp.com/gpg | \
    sudo gpg --dearmor -o /usr/share/keyrings/hashicorp.gpg
  echo "deb [signed-by=/usr/share/keyrings/hashicorp.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
    sudo tee /etc/apt/sources.list.d/hashicorp.list >/dev/null
  sudo apt update && sudo apt install -y packer
fi

if ! kvm-ok >/dev/null 2>&1 && [ ! -e /dev/kvm ]; then
  echo "!! /dev/kvm unavailable - enable VT-x/AMD-V or nested virtualization."
  exit 1
fi

# Locate OVMF firmware
OVMF=""
for f in /usr/share/OVMF/OVMF_CODE_4M.fd /usr/share/OVMF/OVMF_CODE.fd \
         /usr/share/edk2/ovmf/OVMF_CODE.fd /usr/share/edk2-ovmf/x64/OVMF_CODE.fd; do
  [ -f "$f" ] && OVMF="$f" && break
done
[ -n "$OVMF" ] || { echo "!! OVMF firmware not found (apt install ovmf)"; exit 1; }
echo "==> OVMF: $OVMF"

# ISO checksum
[ -f "$ISO_URL" ] || { echo "!! ISO missing: $ISO_URL (set ISO_URL=...)"; exit 1; }
if [ -z "$ISO_SUM" ]; then
  echo "==> Computing ISO sha256 (one-time, slow)..."
  ISO_SUM="sha256:$(sha256sum "$ISO_URL" | cut -d' ' -f1)"
fi

echo "==> packer init + build"
packer init .
packer build \
  -var "iso_url=$ISO_URL" \
  -var "iso_checksum=$ISO_SUM" \
  win11.pkr.hcl

echo "==> Done. Golden image: output-win11/win11-finance-detnode.qcow2"
echo "    Detonate with: ./detonate.sh <runname>"
