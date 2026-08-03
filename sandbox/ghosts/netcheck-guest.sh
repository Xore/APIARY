#!/bin/bash
# netcheck-guest.sh — runs inside a throwaway Linux guest on virbr-ghosts,
# injected and invoked by verify-network-isolation.sh (#325). Not part of
# the GHOSTS Windows guest itself -- this only tests the network policy at
# the bridge/iptables level, which is OS-agnostic.
#
# Writes PASS/FAIL lines to /root/netcheck-result.txt, then powers off so
# the host driver can virt-copy-out the result from a stopped guest, the
# same offline-artifact-collection pattern the rest of sandbox/ uses.
#
# TCP checks use bash's /dev/tcp rather than curl/wget/nc -- no assumption
# about what's installed in the base image, since this script is injected
# fresh and only bash itself is guaranteed.

result=/root/netcheck-result.txt
: >"$result"

# firstboot can run before systemd-networkd finishes DHCP; give it a window
# rather than testing "unreachable" against an interface that just isn't up
# yet, which would pass every negative check for the wrong reason.
tries=60
while [ "$tries" -gt 0 ] && ! ip route show default | grep -q default; do
  # Nudge a fresh DHCPDISCOVER rather than passively waiting on whatever
  # backoff systemd-networkd's client already committed to -- a missed
  # first attempt (dnsmasq not fully up yet when firstboot fires) can
  # otherwise leave the guest with no lease for far longer than this loop
  # waits, observed live (#325).
  if [ $((tries % 10)) -eq 0 ]; then
    networkctl reconfigure enp1s0 2>/dev/null || systemctl restart systemd-networkd 2>/dev/null || true
  fi
  sleep 1
  tries=$((tries - 1))
done

# Written here, at test time, rather than offline during image customization:
# something in this image's boot path (systemd-resolved stub symlink most
# likely) resets /etc/resolv.conf between when virt-customize can write it
# and when this firstboot script actually runs, so writing it any earlier
# doesn't stick.
rm -f /etc/resolv.conf
printf 'nameserver 10.20.30.1\noptions attempts:1 timeout:2\n' >/etc/resolv.conf

{
  echo "--- ip addr ---"; ip addr
  echo "--- ip route ---"; ip route
  echo "--- resolv.conf (before) ---"; ls -la /etc/resolv.conf; cat /etc/resolv.conf 2>&1
  echo "--- route to 10.20.30.1 ---"; ip route get 10.20.30.1 2>&1
  echo "--- manual /dev/tcp attempt to 10.20.30.1:5000 ---"
  timeout 5 bash -c 'exec 3<>/dev/tcp/10.20.30.1/5000' 2>&1
  echo "exit: $?"
} >/root/netcheck-diag.txt 2>&1

tcp_open() {
  timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
}

check() {
  desc=$1; expect=$2; shift 2
  if "$@" >/dev/null 2>&1; then got=pass; else got=fail; fi
  if [ "$got" = "$expect" ]; then
    echo "PASS: $desc" >>"$result"
  else
    echo "FAIL: $desc (expected to $expect, did not)" >>"$result"
  fi
}

# WAN must work -- this is the whole point of the network.
check "WAN ICMP reaches 1.1.1.1" pass \
  ping -c1 -W3 1.1.1.1
check "WAN DNS resolves example.com" pass \
  getent hosts example.com
check "WAN HTTPS reaches example.com" pass \
  tcp_open example.com 443

# The one documented exception must work: ghosts-api publishes on this
# bridge's own gateway address (#324), not a docker-internal IP.
check "GHOSTS API exception (10.20.30.1:5000) is reachable" pass \
  tcp_open 10.20.30.1 5000

# Everything private must not.
check "host LAN gateway (192.168.42.254) is unreachable" fail \
  ping -c1 -W2 192.168.42.254
check "host's own LAN address (192.168.42.249) is unreachable" fail \
  ping -c1 -W2 192.168.42.249
check "another libvirt guest network (10.10.10.254, sandbox bridge) is unreachable" fail \
  ping -c1 -W2 10.10.10.254
check "a docker bridge gateway (172.18.0.1) is unreachable" fail \
  tcp_open 172.18.0.1 1
check "the Linux sandbox's forensic-egress net (198.18.0.1) is unreachable" fail \
  ping -c1 -W2 198.18.0.1
# The GHOSTS API's docker-internal backend address must stay unreachable
# too -- both the RFC1918 DROP above and Docker's own raw-table protection
# (see network-filter.sh's header) should catch this; a guest reaching this
# directly would mean the "one address, one port" boundary wasn't as narrow
# as documented.
check "ghosts-api's docker-internal address (10.90.0.2:5000, not the published one) is unreachable" fail \
  tcp_open 10.90.0.2 5000
check "ghosts-postgres (10.90.0.3:5432) is unreachable" fail \
  tcp_open 10.90.0.3 5432

sync
poweroff
