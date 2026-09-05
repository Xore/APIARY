#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root: sudo bash $0" >&2
  exit 1
fi

release=${SANDBOX_UBUNTU_RELEASE:-noble}
image_name=${SANDBOX_UBUNTU_IMAGE:-${release}-server-cloudimg-amd64.img}
image_url="https://cloud-images.ubuntu.com/${release}/current"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root_dir=/var/lib/honeypot-sandbox
base="$root_dir/base/ubuntu-${release}.qcow2"
work=$(mktemp -d /var/lib/honeypot-sandbox/base/.prepare.XXXXXX)
trap 'rm -rf -- "$work"; rm -f -- "$base.new"' EXIT

available_kib=$(df -Pk "$root_dir" | awk 'NR==2 {print $4}')
[[ $available_kib =~ ^[0-9]+$ ]] && (( available_kib >= 10 * 1024 * 1024 )) || {
  echo "At least 10 GiB free space is required on the sandbox filesystem" >&2
  exit 1
}

# Same class of fix as sandbox/install-host.sh (#1609/#3015): this was an
# unconditional apt-get, which is exit-127 on EL and takes every later step
# with it (#3019). ubuntu-cloudimage-keyring does not exist as an EL package
# at all -- see the keyring block below -- so gnupg2 (which ships gpgv) and
# guestfs-tools (EL's name for libguestfs-tools) go in its place.
if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates curl gpgv ubuntu-cloudimage-keyring libguestfs-tools
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y \
    ca-certificates curl gnupg2 guestfs-tools
else
  echo "no apt-get or dnf on this host -- install ca-certificates, curl, a gpgv-capable gnupg and libguestfs by hand" >&2
  exit 1
fi

curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$work/$image_name" "$image_url/$image_name"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$work/SHA256SUMS" "$image_url/SHA256SUMS"
curl --fail --location --proto '=https' --tlsv1.2 \
  --output "$work/SHA256SUMS.gpg" "$image_url/SHA256SUMS.gpg"

keyring=/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
if [[ ! -r $keyring ]]; then
  # EL has no ubuntu-cloudimage-keyring package (#3019), so there is nothing
  # at the Debian/Ubuntu path above. Build an equivalent keyring locally from
  # Ubuntu's own "UEC Image Automatic Signing Key <cdimage@ubuntu.com>" --
  # the same key that package ships -- fetched by PINNED fingerprint, never
  # trusted on TLS alone (that would defeat the entire point of the gpgv
  # check two lines down). The fingerprint below is a deliberate, reviewed
  # choice (issue #3019), cross-checked 2026-09 against Ubuntu's own
  # published cloud-image verification docs and independent mirrors of the
  # UEC signing key -- do not change it without re-verifying against an
  # official Ubuntu source.
  uec_key_fpr="D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
  el_keyring_dir=/etc/apiary/sandbox-keyrings
  el_keyring="$el_keyring_dir/ubuntu-cloudimage-keyring.gpg"
  if [[ ! -r $el_keyring ]]; then
    command -v gpg >/dev/null 2>&1 || {
      echo "gpg is required to build the EL cloud-image keyring (install gnupg2)" >&2
      exit 1
    }
    mkdir -p "$el_keyring_dir"
    rm -f -- "$el_keyring"
    # gpg writes a keybox here, not a legacy keyring, despite the .gpg suffix.
    # gpgv 2.4.5 (EL10's gnupg2) reads it -- verified live against a real
    # cloud-images SHA256SUMS.gpg signature, not assumed. A gpgv too old to
    # read a keybox would fail closed at the verify step below, never open.
    #
    # The fetch runs in a throwaway GNUPGHOME: on a host where the invoking
    # account has never run gpg there is no ~/.gnupg, and gpg then dies on its
    # own lockfile ("failed to create temporary file ... No such file or
    # directory") before it ever reaches the keyserver. Observed on a clean EL
    # host. This also keeps the operator's own keyring out of the picture.
    gnupg_home="$work/gnupg"
    mkdir -p "$gnupg_home"
    chmod 700 "$gnupg_home"
    GNUPGHOME="$gnupg_home" gpg --no-default-keyring --keyring "$el_keyring" \
      --keyserver hkps://keyserver.ubuntu.com \
      --recv-keys "$uec_key_fpr" \
      || { echo "Failed to fetch the Ubuntu cloud-image signing key ($uec_key_fpr) from keyserver.ubuntu.com" >&2; rm -f -- "$el_keyring"; exit 1; }
  fi
  # Re-read the fingerprint on EVERY run, not only on the run that creates the
  # keyring: a file that is already at $el_keyring would otherwise be trusted
  # forever on the strength of a check some earlier run made.
  gnupg_read_home="$work/gnupg-read"
  mkdir -p "$gnupg_read_home"
  chmod 700 "$gnupg_read_home"
  fetched_fpr=$(
    GNUPGHOME="$gnupg_read_home" gpg --no-default-keyring --keyring "$el_keyring" \
      --with-colons --fingerprint \
      | awk -F: '$1=="fpr"{print $10; exit}'
  )
  [[ $fetched_fpr == "$uec_key_fpr" ]] || {
    echo "Cloud-image keyring fingerprint ($fetched_fpr) does not match the pinned fingerprint ($uec_key_fpr) -- refusing to trust it" >&2
    rm -f -- "$el_keyring"
    exit 1
  }
  keyring="$el_keyring"
fi
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
  --run-command 'systemctl mask cloud-init-local.service cloud-init-network.service cloud-init.service cloud-config.service cloud-final.service systemd-networkd-wait-online.service 2>/dev/null || true' \
  --run-command 'rm -rf /var/lib/cloud/instance /var/lib/cloud/instances' \
  --run-command 'ln -sf /lib/systemd/system/multi-user.target /etc/systemd/system/default.target' \
  --run-command 'systemctl enable serial-getty@ttyS0.service 2>/dev/null || true' \
  --run-command 'mkdir -p /opt/honeypot/input /var/lib/honeypot-result' \
  --run-command 'chown sandbox:sandbox /opt/honeypot/input' \
  --selinux-relabel

mv -f -- "$base.new" "$base"
chmod 0640 "$base"
bash "$script_dir/extract-linux-boot.sh" "$base"
qemu-img info "$base"
echo "Verified Linux base prepared: $base"
