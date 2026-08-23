#!/usr/bin/env bash
# Mount the homeserver's Arkime pcap store on the VPS (#1737, decision 1).
#
# ---------------------------------------------------------------------------
# Read this before running it: the trust direction changes
# ---------------------------------------------------------------------------
# Every other mount between these hosts runs the safe way round -- the
# homeserver PULLS from the VPS, read-only. The internet-facing box has no
# access to the internal one.
#
# Live capture inverts that for this one path: the VPS must WRITE to the
# homeserver, which means the internet-facing box holds a credential into the
# internal network. That is a real change in blast radius if the VPS is ever
# compromised, and it is a direct consequence of choosing live capture with
# 30-day retention -- the packets have to reach the disk that can hold them,
# and the VPS is the only thing that has them.
#
# So the credential is deliberately narrow. On the HOMESERVER, before running
# this:
#
#   1. Create a dedicated account that owns nothing else:
#        useradd --system --home /opt/stacks/apiary/arkime-pcap \
#                --shell /usr/sbin/nologin arkime-pcap
#        install -d -o arkime-pcap -g arkime-pcap -m 0750 \
#                /opt/stacks/apiary/arkime-pcap
#
#   2. Authorise the VPS key for SFTP only, chrooted to that directory, with
#      every forwarding option off. In sshd_config:
#
#        Match User arkime-pcap
#            ChrootDirectory /opt/stacks/apiary
#            ForceCommand internal-sftp -d /arkime-pcap
#            AllowTcpForwarding no
#            AllowAgentForwarding no
#            X11Forwarding no
#            PermitTunnel no
#
#   3. Restrict the key itself in authorized_keys, so a config mistake in
#      sshd_config is not the only thing standing between a compromised VPS
#      and a shell:
#
#        restrict,from="10.8.0.1" ssh-ed25519 AAAA... vps-arkime-pcap
#
# A compromised VPS can then write pcap files into one directory and nothing
# else. It cannot read the rest of the homeserver, open a shell, or forward a
# port back out.
#
# The remaining exposure is honest and worth stating: it can fill that
# directory, and it can write junk into it. Arkime's freeSpaceG prune bounds
# the first; nothing bounds the second except the account owning nothing of
# value.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root: sudo ./setup-arkime-pcap-mount.sh" >&2
    exit 1
fi

HOMESERVER_WG="${HOMESERVER_WG:-10.8.0.2}"
MOUNT_POINT="${MOUNT_POINT:-/opt/stacks/apiary/arkime-pcap}"
SSH_KEY="${SSH_KEY:-/root/.ssh/arkime_pcap}"
REMOTE_USER="${REMOTE_USER:-arkime-pcap}"

command -v sshfs >/dev/null || {
    echo "sshfs is not installed on this host" >&2
    exit 1
}
[[ -f "$SSH_KEY" ]] || {
    echo "Missing $SSH_KEY -- generate it and authorise it on the homeserver first (see the header)." >&2
    exit 1
}

install -d -m 0755 "$MOUNT_POINT"

# reconnect + ServerAlive: an sshfs mount that loses its connection otherwise
# stays mounted and fails every write, which is the shape of #1409. These make
# it recover on its own; the container healthcheck catches the case where it
# cannot.
opts="_netdev,rw,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3"
opts="${opts},IdentityFile=${SSH_KEY},allow_other,default_permissions"
opts="${opts},StrictHostKeyChecking=accept-new"

if ! grep -q " ${MOUNT_POINT} " /etc/fstab; then
    cat >>/etc/fstab <<EOF

# #1737: Arkime writes captured pcap to the homeserver, which is where the
# disk for a 30-day window actually is. Write-direction mount -- see the
# header of vps/setup-arkime-pcap-mount.sh for the trust implications.
${REMOTE_USER}@${HOMESERVER_WG}:/ ${MOUNT_POINT} fuse.sshfs ${opts} 0 0
EOF
fi

mountpoint -q "$MOUNT_POINT" || mount "$MOUNT_POINT"

if ! mountpoint -q "$MOUNT_POINT"; then
    echo "mount failed: $MOUNT_POINT" >&2
    exit 1
fi
if ! touch "${MOUNT_POINT}/.write-test" 2>/dev/null; then
    echo "mounted but not writable: $MOUNT_POINT -- check the homeserver account's ownership" >&2
    exit 1
fi
rm -f "${MOUNT_POINT}/.write-test"

echo "arkime pcap mount is up and writable: $MOUNT_POINT"
