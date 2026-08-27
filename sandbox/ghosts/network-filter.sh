#!/usr/bin/env bash
# network-filter.sh — belt-and-braces iptables policy for virbr-ghosts (#325).
#
# network.xml's <forward mode='nat'> makes the GHOSTS guest's traffic
# routable to anywhere the host can reach -- LAN included. This is what
# actually narrows that down to "WAN yes, LAN no, one documented exception":
#
#   1. GHOSTS-FWD, jumped to first in FORWARD (ahead of libvirt's own
#      permissive per-network rules and Docker's), ACCEPTs only the GHOSTS
#      API's docker-internal backend address and DROPs every RFC1918
#      destination plus the Linux sandbox's forensic-egress network
#      (198.18.0.0/24, not RFC1918 -- it's IANA benchmarking space, so the
#      RFC1918 rules alone miss it).
#
#      Why a docker-internal address (10.90.0.2), when #324's compose.yml
#      publishes the API on this bridge's own gateway (10.20.30.1) instead?
#      Because Docker's own port-publishing NATs it right back: a SYN to
#      10.20.30.1:5000 gets DNAT'd to 10.90.0.2:5000 in `nat` PREROUTING
#      (before routing/FORWARD ever runs), so by the time the packet reaches
#      GHOSTS-FWD its destination is already the backend address --
#      verified live (#325) with `nft monitor trace`, after first assuming
#      the gateway-only GHOSTS-IN rule would be enough and finding the
#      connection still timed out because GHOSTS-FWD's own RFC1918 DROP
#      caught the post-DNAT packet. This ACCEPT has to match the
#      *post-DNAT* address, not the published one.
#
#      This does not reopen the direct-routing hole an earlier version of
#      this file hit: a guest that tries to skip the publish and address
#      10.90.0.2 directly (bypassing 10.20.30.1) is stopped upstream of
#      this chain entirely, by a `raw` table PREROUTING rule Docker itself
#      installs (`ip daddr <container> iifname != <container's own bridge>
#      drop`) -- verified live (#325) as the reason that direct-addressing
#      attempt failed before this rule ever existed. Only traffic that
#      actually went through the legitimate publish-and-DNAT path reaches
#      GHOSTS-FWD with this destination at all.
#
#   2. A DOCKER-USER rule for the *return* leg of that flow. The reply's
#      ingress interface is the docker bridge, not virbr-ghosts, so
#      GHOSTS-FWD's `-i virbr-ghosts` jump never sees it, and nothing else
#      in FORWARD has a reason to expect a reply addressed back out to a
#      non-docker interface -- verified live (#325) as SYNs retransmitting
#      with nothing coming back until this was added. DOCKER-USER is
#      Docker's own documented, persists-across-`docker network`-changes
#      hook for exactly this: rules that must run before Docker's generated
#      ones.
#
#   3. A GHOSTS-IN chain on INPUT for virbr-ghosts, DROPping everything
#      except this bridge's own gateway (needed for the guest's DHCP/DNS,
#      and it's also where ghosts-api's published port is *addressed*,
#      even though the traffic that actually reaches the container is
#      handled by (1)/(2) above after Docker's DNAT). Without this chain,
#      "unreachable" only held for genuinely remote hosts -- verified live
#      (#325): a guest on this network could ping other bridges' *own*
#      addresses (192.168.42.249 on eno2, 10.10.10.254 on virbr-sandbox,
#      198.18.0.1 on virbr-hpsbx) and get real replies, because a
#      multi-homed Linux host answers ICMP/etc for its own addresses via
#      INPUT regardless of which interface the packet arrived on --
#      FORWARD-chain rules never see that traffic at all. This closes that
#      off, and incidentally also closes off any host-bound service
#      listening on 0.0.0.0 that isn't meant to be reachable from here.
#
#   4. Source-pinning the API socket itself (#2257 step 1 / #2444 AC#1).
#      The ACCEPT in GHOSTS-FWD was originally unqualified by source: every
#      guest libvirt hands out from the bridge's dynamic DHCP range
#      (.10-.99, the WAN-detonation population #325/#331 exist to receive)
#      could reach ghosts-api at all. Ghosts.Api serves its entire upstream
#      management plane there -- including POST /api/animations/workflows,
#      which schedules an in-container recurring GET to any caller-supplied
#      URL (#2444), and POST /api/attack/import. The accept is now pinned to
#      the enrolled clients listed below (today exactly one: the static MAC
#      host entry in network.xml, win11-ghosts at 10.20.30.50), followed by
#      an explicit drop for everything else bound for the API backend so a
#      non-pinned guest fails closed immediately instead of depending on the
#      rule ordering into the RFC1918 drops. To admit a NEW client later:
#      add another static <host mac=... ip=.../> entry in network.xml AND its
#      address below -- one fixed documented pair per client, same pattern as
#      RevDeck's REVDECK_API_BASE; don't open the dynamic range back up.
#      Ephemeral verification flows are exempt by construction rather than
#      widening these lists: verify-client-enrollment.sh grants its own
#      throwaway lease a scoped rule for the duration of its run and removes
#      it again on exit, so the standing policy never grows an exception no
#      one remembers.
#
# Idempotent the same way forensic-egress-network.sh's nft table is: flush
# and repopulate the custom chains rather than trying to detect and skip
# individual duplicate rules. The FORWARD/INPUT/DOCKER-USER jumps are each
# checked with -C before insertion, since -I unconditionally would stack a
# duplicate on every re-run.
#
# Usage:
#   sudo network-filter.sh apply    # (re)apply the policy -- idempotent
#   sudo network-filter.sh verify   # print PASS/FAIL for each rule, no changes
#   sudo network-filter.sh teardown # remove the jumps and the chains

set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "Run as root" >&2; exit 1; }

BRIDGE=virbr-ghosts
BRIDGE_GATEWAY=10.20.30.1
FWD_CHAIN=GHOSTS-FWD
IN_CHAIN=GHOSTS-IN
# The GHOSTS API container's docker-internal backend address -- see the
# header above for why the FORWARD-chain exception has to target this, not
# the published 10.20.30.1 address the guest actually connects to.
GHOSTS_API_BACKEND=10.90.0.2/32
GHOSTS_API_PORT=5000
# The enrolled ghosts clients allowed to reach the API socket above (#2444,
# see the "(4)" note in the header for how this list is maintained). Must
# stay in lockstep with the static <host .../> entries in network.xml -- the
# only enrolled client today is win11-ghosts at its pinned address.
GHOSTS_API_CLIENTS=("10.20.30.50/32")
# Not RFC1918 -- IANA benchmarking space (RFC 2544) -- so it needs its own
# DROP line; the sandbox/network.xml Linux runner's forensic-egress proxy
# lives here (198.18.0.1) and must stay unreachable from this guest too.
FORENSIC_EGRESS_NET=198.18.0.0/24
RFC1918=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)

apply() {
  iptables -N "$FWD_CHAIN" 2>/dev/null || true
  iptables -F "$FWD_CHAIN"
  for client in "${GHOSTS_API_CLIENTS[@]}"; do
    iptables -A "$FWD_CHAIN" -s "$client" -d "$GHOSTS_API_BACKEND" -p tcp --dport "$GHOSTS_API_PORT" -j ACCEPT
  done
  # Fail closed for any other source bound for the API socket, right here,
  # instead of letting an unpinned guest's packet walk on (it would only hit
  # the 10.0.0.0/8 DROP further down, but depending on that ordering hides
  # what actually guards this surface).
  iptables -A "$FWD_CHAIN" -d "$GHOSTS_API_BACKEND" -p tcp --dport "$GHOSTS_API_PORT" -j DROP
  iptables -A "$FWD_CHAIN" -d "$FORENSIC_EGRESS_NET" -j DROP
  for net in "${RFC1918[@]}"; do
    iptables -A "$FWD_CHAIN" -d "$net" -j DROP
  done
  # Everything else (real WAN) falls through GHOSTS-FWD unmatched and hits
  # libvirt's own ACCEPT rules for a NAT'd forward network.
  iptables -A "$FWD_CHAIN" -j RETURN
  if ! iptables -C FORWARD -i "$BRIDGE" -j "$FWD_CHAIN" 2>/dev/null; then
    iptables -I FORWARD 1 -i "$BRIDGE" -j "$FWD_CHAIN"
  fi

  iptables -N "$IN_CHAIN" 2>/dev/null || true
  iptables -F "$IN_CHAIN"
  iptables -A "$IN_CHAIN" -d "$BRIDGE_GATEWAY" -j ACCEPT
  # DHCPDISCOVER/DHCPREQUEST go out as broadcast (dst 255.255.255.255), not
  # to the bridge's own address, until the guest has a lease -- without this
  # the guest can never get one in the first place, verified live (#325)
  # after adding the chain and finding DHCP itself broken, not just LAN
  # reachability tightened.
  iptables -A "$IN_CHAIN" -d 255.255.255.255 -p udp --dport 67 -j ACCEPT
  iptables -A "$IN_CHAIN" -j DROP
  if ! iptables -C INPUT -i "$BRIDGE" -j "$IN_CHAIN" 2>/dev/null; then
    iptables -I INPUT 1 -i "$BRIDGE" -j "$IN_CHAIN"
  fi

  if ! iptables -C DOCKER-USER -o "$BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; then
    iptables -I DOCKER-USER 1 -o "$BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  fi

  echo "applied: FORWARD -> $FWD_CHAIN, INPUT -> $IN_CHAIN, DOCKER-USER return leg, all for $BRIDGE"
}

teardown() {
  iptables -D FORWARD -i "$BRIDGE" -j "$FWD_CHAIN" 2>/dev/null || true
  iptables -F "$FWD_CHAIN" 2>/dev/null || true
  iptables -X "$FWD_CHAIN" 2>/dev/null || true
  iptables -D INPUT -i "$BRIDGE" -j "$IN_CHAIN" 2>/dev/null || true
  iptables -F "$IN_CHAIN" 2>/dev/null || true
  iptables -X "$IN_CHAIN" 2>/dev/null || true
  iptables -D DOCKER-USER -o "$BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
  echo "removed: $FWD_CHAIN, $IN_CHAIN, and the DOCKER-USER return-leg rule"
}

verify() {
  local ok=1
  check() {
    if eval "$1" >/dev/null 2>&1; then
      echo "PASS: $2"
    else
      echo "FAIL: $2"
      ok=0
    fi
  }
  check "iptables -C FORWARD -i $BRIDGE -j $FWD_CHAIN" \
    "FORWARD jumps to $FWD_CHAIN for $BRIDGE"
  for client in "${GHOSTS_API_CLIENTS[@]}"; do
    check "iptables -C $FWD_CHAIN -s $client -d $GHOSTS_API_BACKEND -p tcp --dport $GHOSTS_API_PORT -j ACCEPT" \
      "$FWD_CHAIN accepts enrolled client $client for the API backend ($GHOSTS_API_BACKEND:$GHOSTS_API_PORT)"
  done
  check "iptables -C $FWD_CHAIN -d $GHOSTS_API_BACKEND -p tcp --dport $GHOSTS_API_PORT -j DROP" \
    "$FWD_CHAIN drops the API backend for every non-enrolled source (fail closed, #2444)"
  check "iptables -C $FWD_CHAIN -d $FORENSIC_EGRESS_NET -j DROP" \
    "$FWD_CHAIN drops the forensic-egress net ($FORENSIC_EGRESS_NET)"
  for net in "${RFC1918[@]}"; do
    check "iptables -C $FWD_CHAIN -d $net -j DROP" "$FWD_CHAIN drops $net"
  done
  check "iptables -C INPUT -i $BRIDGE -j $IN_CHAIN" \
    "INPUT jumps to $IN_CHAIN for $BRIDGE"
  check "iptables -C $IN_CHAIN -d $BRIDGE_GATEWAY -j ACCEPT" \
    "$IN_CHAIN accepts this bridge's own gateway ($BRIDGE_GATEWAY, for DHCP/DNS/the GHOSTS API's published address)"
  check "iptables -C $IN_CHAIN -d 255.255.255.255 -p udp --dport 67 -j ACCEPT" \
    "$IN_CHAIN accepts broadcast DHCP discover/request"
  check "iptables -C $IN_CHAIN -j DROP" \
    "$IN_CHAIN drops everything else inbound to the host"
  check "iptables -C DOCKER-USER -o $BRIDGE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT" \
    "DOCKER-USER accepts the established return leg for $BRIDGE"

  # Ordering matters twice over: the enrolled-client ACCEPTs have to precede
  # both the fail-closed API-backend DROP that would otherwise match the
  # same socket, and the RFC1918 DROP that would otherwise also match
  # 10.90.0.2 (it's inside 10.0.0.0/8).
  local accept_line api_drop_line drop_line
  accept_line=$(iptables -L "$FWD_CHAIN" -n --line-numbers | awk -v ip="${GHOSTS_API_BACKEND%/*}" '$0 ~ ip && /ACCEPT/ {print $1; exit}')
  api_drop_line=$(iptables -L "$FWD_CHAIN" -n --line-numbers | awk -v ip="${GHOSTS_API_BACKEND%/*}" -v pt="$GHOSTS_API_PORT" '$0 ~ ip && /DROP/ && $0 ~ pt {print $1; exit}')
  drop_line=$(iptables -L "$FWD_CHAIN" -n --line-numbers | awk '$0 ~ /10\.0\.0\.0\/8/ {print $1; exit}')
  if [[ -n $accept_line && -n $api_drop_line && $accept_line -lt $api_drop_line ]]; then
    echo "PASS: the enrolled-client ACCEPT precedes the fail-closed API-backend DROP"
  else
    echo "FAIL: the enrolled-client ACCEPT does not precede the fail-closed API-backend DROP"
    ok=0
  fi
  if [[ -n $accept_line && -n $drop_line && $accept_line -lt $drop_line ]]; then
    echo "PASS: the API backend exception precedes the 10.0.0.0/8 DROP"
  else
    echo "FAIL: the API backend exception does not precede the 10.0.0.0/8 DROP"
    ok=0
  fi
  [[ $ok -eq 1 ]]
}

case "${1:-}" in
  apply)    apply    ;;
  teardown) teardown ;;
  verify)   verify   ;;
  *) echo "Usage: $0 <apply|verify|teardown>" >&2; exit 2 ;;
esac
