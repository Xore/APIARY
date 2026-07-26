#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

release=${SANDBOX_UBUNTU_RELEASE:-noble}
image_name=${SANDBOX_UBUNTU_IMAGE:-${release}-server-cloudimg-amd64.img}
image_url="https://cloud-images.ubuntu.com/${release}/current"
root_dir=/var/lib/honeypot-sandbox
base="$root_dir/base/ubuntu-${release}.qcow2"
work=$(mktemp -d /var/lib/honeypot-sandbox/base/.prepare.XXXXXX)
trap 'rm -rf -- "$work"; rm -f -- "$base.new"' EXIT

available_kib=$(df -Pk "$root_dir" | awk 'NR==2 {print $4}')
[[ $available_kib =~ ^[0-9]+$ ]] && (( available_kib >= 10 * 1024 * 1024 )) || {
  echo "At least 10 GiB free space is required on the sandbox filesystem" >&2
  exit 1
}

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  ca-certificates curl gpgv ubuntu-cloudimage-keyring libguestfs-tools

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$work/$image_name" "$image_url/$image_name"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$work/SHA256SUMS" "$image_url/SHA256SUMS"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$work/SHA256SUMS.gpg" "$image_url/SHA256SUMS.gpg"

keyring=/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
[[ -r $keyring ]] || { echo "Ubuntu cloud-image keyring is missing" >&2; exit 1; }
gpgv --keyring "$keyring" "$work/SHA256SUMS.gpg" "$work/SHA256SUMS"
(cd "$work" && grep " \*$image_name\|  $image_name" SHA256SUMS | sha256sum --check -)

# Growing only the qcow2 container does not enlarge the filesystem inside it.
# Build a new 20 GiB target and let virt-resize copy every partition while
# expanding Ubuntu's largest ext4 filesystem (normally /dev/sda1).
root_partition=$(
  virt-filesystems --filesystems --long -a "$work/$image_name" |
    awk 'NR == 1 {for (i = 1; i <= NF; i++) if ($i == "Size") size_col = i; next}
         $2 == "filesystem" && $3 == "ext4" && size_col {print $size_col, $1}' |
    sort -nr | awk 'NR == 1 {print $2}'
)
[[ $root_partition == /dev/* ]] || {
  echo "Could not identify the Ubuntu root filesystem in $image_name" >&2
  exit 1
}
qemu-img create -q -f qcow2 "$base.new" 20G
virt-resize --expand "$root_partition" "$work/$image_name" "$base.new"
chown root:libvirt "$base.new"
chmod 0640 "$base.new"

# Customization happens offline. The base never boots and never sees a sample.
virt-customize -a "$base.new" \
  --run-command 'dpkg --add-architecture i386 && apt-get update' \
  --install strace,lsof,file,jq,procps,iproute2,tcpdump,binutils,python3-pefile,libimage-exiftool-perl,osslsigncode,cabextract,p7zip-full,xvfb,wine,wine64,wine32:i386,nodejs,php-cli \
  --run-command 'useradd --create-home --shell /bin/bash --uid 1500 sandbox 2>/dev/null || true' \
  --run-command 'passwd --lock sandbox' \
  --run-command 'install -d -m 0700 -o sandbox -g sandbox /home/sandbox/.wine' \
  --run-command 'timeout 180s runuser -u sandbox -- env HOME=/home/sandbox WINEPREFIX=/home/sandbox/.wine WINEARCH=win64 WINEDLLOVERRIDES=winemenubuilder.exe=d xvfb-run -a wineboot --init >/var/log/honeypot-wineboot.log 2>&1 || true' \
  --run-command 'runuser -u sandbox -- env HOME=/home/sandbox WINEPREFIX=/home/sandbox/.wine wineserver -k >/dev/null 2>&1 || true' \
  --run-command 'apt-get clean && rm -rf /var/lib/apt/lists/*' \
  --run-command 'systemctl disable --now ssh.service ssh.socket 2>/dev/null || true' \
  --run-command 'systemctl disable --now systemd-resolved.service 2>/dev/null || true' \
  --run-command 'systemctl mask cloud-init-network.service 2>/dev/null || true' \
  --run-command 'mkdir -p /opt/honeypot/input /var/lib/honeypot-result' \
  --run-command 'chown sandbox:sandbox /opt/honeypot/input' \
  --selinux-relabel

mv -f -- "$base.new" "$base"
chmod 0640 "$base"
qemu-img info "$base"
echo "Verified Linux base prepared: $base"
