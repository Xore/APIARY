#!/bin/sh
# #342: virtio-net's hardware-accelerated GRO (rx-gro-hw) coalesces multiple
# physical frames into one oversized "packet" with an inflated IP
# total-length. It is a separate feature from the standard
# generic-receive-offload toggle (which was already off) and is common on
# KVM/QEMU virtio-net interfaces. Suricata's AF_PACKET capture then reports
# the coalesced/truncated result as a decoder-event alert (SID 2200003
# "SURICATA IPv4 truncated packet", SID 2200122 "SURICATA AF-PACKET truncated
# packet") -- confirmed by decoding a sample alert's packet bytes and by
# live-toggling `ethtool -K <iface> rx-gro-hw off`, which took truncation
# alerts from ~70% of all alert volume to zero in a subsequent clean window.
#
# `ethtool -K` alone does not survive a reboot or interface recreation.
# systemd 259's `.link` file gained a native directive for exactly this
# setting (GenericReceiveOffloadHardware=), so this installs that instead of
# a custom ethtool-invoking service. Matches by driver rather than interface
# name since that is what actually determines whether rx-gro-hw applies.
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root: sudo ./disable-nic-hw-gro.sh [--apply]" >&2
    exit 1
fi

apply=false
case "${1:-}" in
    --apply) apply=true ;;
    "") ;;
    *)
        echo "Usage: sudo ./disable-nic-hw-gro.sh [--apply]" >&2
        exit 2
        ;;
esac

install -d -m 0755 /etc/systemd/network
cat >/etc/systemd/network/10-honeypot-disable-hw-gro.link <<'EOF'
[Match]
Driver=virtio_net

[Link]
GenericReceiveOffloadHardware=false
EOF
chmod 0644 /etc/systemd/network/10-honeypot-disable-hw-gro.link

if [ "$apply" = true ]; then
    udevadm control --reload
    udevadm trigger --settle --action=add --subsystem-match=net
    for iface in /sys/class/net/*; do
        name=$(basename "$iface")
        driver=$(cat "$iface/device/uevent" 2>/dev/null | grep -o '^DRIVER=.*' | cut -d= -f2 || true)
        [ "$driver" = "virtio_net" ] || continue
        ethtool -k "$name" | grep -i gro-hw
    done
else
    echo "Configuration installed but not applied."
    echo "Review /etc/systemd/network/10-honeypot-disable-hw-gro.link, then run:"
    echo "  sudo ./disable-nic-hw-gro.sh --apply"
fi
