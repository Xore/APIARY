#!/usr/bin/env bash
# isolation-audit.sh — asserts the honeypot-sandbox isolation invariants
# documented in docs/honeypot-network-isolation.md (#88) still hold.
#
# These properties are all negative — the absence of a <forward>, a route, a
# capability. Nothing fails loudly when one is removed: a detonation on a
# NAT-mode sandbox network works perfectly, it just puts live malware on the
# internet. This script exists to fail loudly instead.
#
# Read-only. It reports; it does not fix. Run on the home stack's own host
# (the self-hosted Actions runner, see .github/workflows/diagnostics.yml, or
# a root systemd timer) — not from the dashboard, which is deliberately
# unprivileged and cannot see libvirt, iptables, or the Docker socket.
#
# Must never print HP_BIND or any WireGuard address (same rule
# diagnostics.yml's own steps already follow).
set -uo pipefail

fail=0
ok()   { printf '  OK    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }
info() { printf '  --    %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------------------
section "Sandbox libvirt networks: no <forward>"
# 'ghosts' is the one deliberate exception (#331: WAN-permitted by design,
# NAT forward is intentional) -- every OTHER sandbox network must have none.
for net in sandbox honeypot-sandbox; do
  if ! virsh net-info "$net" >/dev/null 2>&1; then
    bad "libvirt network '$net' does not exist (expected active, isolated)"
    continue
  fi
  forwards=$(virsh net-dumpxml "$net" 2>/dev/null | grep -c '<forward' || true)
  if [ "$forwards" -eq 0 ]; then
    ok "'$net' has no <forward> element"
  else
    bad "'$net' has $forwards <forward> element(s) -- this network can route to the internet"
  fi
done
if virsh net-info ghosts >/dev/null 2>&1; then
  info "'ghosts' intentionally has a <forward> (#331, WAN-permitted persona network) -- not checked"
fi

# ---------------------------------------------------------------------------
section "Phase 0 iptables barrier (virbr-sandbox)"
# sandbox/honeypot-sandbox have no <forward> element, so libvirt never adds a
# LIBVIRT_FWI/FWO/FWX rule routing them anywhere -- the isolation is the
# FORWARD chain's own default policy catching everything libvirt didn't
# explicitly allow, not a named per-bridge DROP rule. The real failure mode
# to catch is the default policy being ACCEPT, or an explicit ACCEPT rule
# for virbr-sandbox added later (by hand, or by an unrelated tool) that would
# override the default.
if ! command -v iptables >/dev/null 2>&1; then
  bad "iptables not found"
elif iptables_rules=$(sudo -n iptables -S FORWARD 2>&1); then
  policy=$(grep '^-P FORWARD' <<<"$iptables_rules" | awk '{print $3}')
  if [ "$policy" != "DROP" ]; then
    bad "FORWARD chain default policy is '$policy', not DROP -- sandbox traffic with no explicit rule would be forwarded"
  elif grep -q 'virbr-sandbox.*ACCEPT' <<<"$iptables_rules"; then
    bad "an explicit ACCEPT rule references virbr-sandbox in the FORWARD chain -- this overrides the default-DROP isolation"
  else
    ok "FORWARD default policy is DROP and nothing explicitly ACCEPTs virbr-sandbox traffic"
  fi
else
  bad "could not read iptables FORWARD chain (sudo -n iptables failed: needs the isolation-audit sudoers grant)"
fi

# ---------------------------------------------------------------------------
section "sbx-* macvlan network (docker-compose.sandbox.yml)"
if net_json=$(sudo -n docker network inspect sandbox_sandbox 2>/dev/null || sudo -n docker network inspect honeypot-sandbox_sandbox 2>/dev/null); then
  if grep -q '"Internal": true' <<<"$net_json"; then
    ok "docker sandbox network is internal: true"
  else
    bad "docker sandbox network is NOT internal -- containers may have a default route out"
  fi
else
  info "docker sandbox network not found (compose stack not currently up -- expected between detonations, not a failure by itself)"
fi

# ---------------------------------------------------------------------------
section "honeypot-sandbox-strict nwfilter"
if virsh nwfilter-dumpxml honeypot-sandbox-strict >/dev/null 2>&1; then
  ok "'honeypot-sandbox-strict' nwfilter is defined"
else
  bad "'honeypot-sandbox-strict' nwfilter is missing"
fi

# ---------------------------------------------------------------------------
section "No host route into the sandbox subnet other than the bridge"
route_hits=$(ip route show 10.10.10.0/24 2>/dev/null)
route_count=$(printf '%s\n' "$route_hits" | grep -c 'dev virbr-sandbox' || true)
other_count=$(printf '%s\n' "$route_hits" | grep -vc 'dev virbr-sandbox\|^$' || true)
if [ -z "$route_hits" ]; then
  info "no route to 10.10.10.0/24 at all (bridge not currently up -- expected between detonations)"
elif [ "$route_count" -ge 1 ] && [ "$other_count" -eq 0 ]; then
  ok "only the virbr-sandbox bridge routes to 10.10.10.0/24"
else
  bad "unexpected route(s) to 10.10.10.0/24: $route_hits"
fi

# ---------------------------------------------------------------------------
section "Stack containers (hp-*/sbx-* only -- this host also runs unrelated stacks: dockge, pihole, ghidra/ollama, ghosts-*, etc.)"
if containers=$(sudo -n docker ps -a --format '{{.Names}}\t{{.Image}}' 2>&1 | grep -E '^(hp-|sbx-)'); then
  privileged_others=""
  while IFS=$'\t' read -r name _; do
    [ -z "$name" ] && continue
    is_priv=$(sudo -n docker inspect "$name" --format '{{.HostConfig.Privileged}}' 2>/dev/null || echo false)
    if [ "$is_priv" = "true" ] && [ "$name" != "hp-tanner-docker" ]; then
      privileged_others="$privileged_others $name"
    fi
    sock=$(sudo -n docker inspect "$name" --format '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null | grep -o '/var/run/docker.sock' || true)
    if [ -n "$sock" ] && [ "$name" != "hp-tanner-docker" ] && [ "$name" != "hp-services-adapter" ] && [ "$name" != "hp-autoheal" ] && [ "$name" != "hp-docker-socket-proxy" ]; then
      bad "$name mounts /var/run/docker.sock (root-equivalent) -- not one of the known, deliberate exceptions"
    fi
  done <<<"$containers"
  if [ -n "$privileged_others" ]; then
    bad "privileged container(s) other than hp-tanner-docker:$privileged_others"
  else
    ok "no privileged container besides hp-tanner-docker (deliberate, isolated tanner_local network + tmpfs docker)"
  fi

  cap_offenders=""
  for name in $(printf '%s\n' "$containers" | cut -f1); do
    [ -z "$name" ] && continue
    caps=$(sudo -n docker inspect "$name" --format '{{range .HostConfig.CapAdd}}{{.}} {{end}}' 2>/dev/null || true)
    if grep -qE 'NET_ADMIN|NET_RAW' <<<"$caps"; then
      case "$name" in
        sbx-zeek|sbx-suricata|sbx-tcpdump) : ;;
        *) cap_offenders="$cap_offenders $name" ;;
      esac
    fi
  done
  if [ -n "$cap_offenders" ]; then
    bad "NET_ADMIN/NET_RAW granted outside sbx-zeek/sbx-suricata/sbx-tcpdump:$cap_offenders"
  else
    ok "NET_ADMIN/NET_RAW confined to sbx-zeek/sbx-suricata/sbx-tcpdump"
  fi
else
  bad "could not enumerate containers (sudo -n docker ps failed: needs the isolation-audit sudoers grant)"
fi

# ---------------------------------------------------------------------------
section "Host posture (reports only, does not fix)"
if ss_out=$(sudo -n ss -tlnp 2>/dev/null | grep ':22 '); then
  if grep -qE '10\.8\.0\.|10\.10\.10\.' <<<"$ss_out"; then
    bad "sshd appears to be listening on a honeypot-facing address"
  else
    ok "sshd is not listening on a honeypot-facing address"
  fi
else
  info "could not confirm sshd listen address (needs the isolation-audit sudoers grant for 'ss -tlnp')"
fi

sock_path=/var/run/libvirt/libvirt-sock
if [ -S "$sock_path" ]; then
  # The security-relevant property is "root:libvirt owned, no world access" --
  # whether the group bit also carries execute (770 vs 660) varies by distro
  # default and is meaningless for a socket anyway (the x bit isn't
  # consulted for AF_UNIX connect()), so both are accepted.
  mode=$(stat -c '%a' "$sock_path" 2>/dev/null)
  owner=$(stat -c '%U:%G' "$sock_path" 2>/dev/null)
  other_bits=${mode: -1}
  if [ "$owner" = "root:libvirt" ] && [ "$other_bits" = "0" ]; then
    ok "libvirt socket is $mode $owner (root:libvirt, no world access)"
  else
    bad "libvirt socket is $mode $owner -- expected root:libvirt with no world access"
  fi
else
  bad "libvirt socket not found at $sock_path"
fi
if grep -qE '^\s*listen_tcp\s*=\s*1' /etc/libvirt/libvirtd.conf 2>/dev/null; then
  bad "libvirtd.conf has listen_tcp = 1 -- the TCP socket is enabled"
else
  ok "libvirtd TCP socket is not enabled (listen_tcp is unset or 0)"
fi

if command -v aa-status >/dev/null 2>&1; then
  if aa_out=$(sudo -n aa-status 2>/dev/null); then
    if grep -qE 'libvirtd|virt-aa-helper' <<<"$aa_out" && ! grep -A5 'processes are in complain mode' <<<"$aa_out" | grep -qE 'libvirtd|virt-aa-helper'; then
      ok "libvirt/QEMU AppArmor profiles are enforcing, not complain"
    else
      bad "a libvirt/QEMU AppArmor profile is in complain mode, or aa-status output didn't match expectations -- check manually"
    fi
  else
    info "could not run aa-status (needs the isolation-audit sudoers grant)"
  fi
else
  info "AppArmor not installed on this host"
fi

# ---------------------------------------------------------------------------
printf '\n'
if [ "$fail" -eq 0 ]; then
  printf 'isolation-audit: all checks passed (or skipped as expected)\n'
else
  printf 'isolation-audit: ONE OR MORE CHECKS FAILED -- see FAIL lines above\n'
fi
exit "$fail"
