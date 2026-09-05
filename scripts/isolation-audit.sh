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
warns=0
ok()   { printf '  OK    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; fail=1; }
# A known, triaged gap with a named owner issue: visible on every run, but it
# does NOT fail the job. diagnostics.yml exits on this script's status, so a
# finding nobody can act on today would make the whole isolation audit
# permanently red -- and a check that can never go green is a check people
# stop reading, which is the exact failure mode #2366 exists to end. WARN is
# for "triaged, tracked, not yet done"; FAIL stays for "nobody has looked at
# this", which is always actionable.
warn() { printf '  WARN  %s\n' "$*"; warns=$((warns + 1)); }
info() { printf '  --    %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------------------
# Every isolated sandbox bridge/network this script audits, in one place the
# iptables and route sections below both read (#2295: each used to hardcode
# virbr-sandbox alone, leaving the Linux lane's virbr-hpsbx unaudited by
# either). A third sandbox network only needs a line here, not a second
# hand-written check block.
#
# fields: <virsh network> <bridge> <subnet> <probe IP in the subnet> <mode>
#   mode=always           the bridge carries this subnet's host route
#                         whenever it's up (Windows lane: static gateway).
#   mode=forensic-egress  the bridge is address-less by design (see
#                         sandbox/network.xml) and may only carry this route
#                         while sandbox/forensic-egress-network.sh's systemd
#                         unit is intentionally active.
GUARDED_BRIDGES=(
  "sandbox          virbr-sandbox 10.10.10.0/24 10.10.10.1 always"
  "honeypot-sandbox virbr-hpsbx   198.18.0.0/24 198.18.0.1 forensic-egress"
)

# ---------------------------------------------------------------------------
section "Sandbox libvirt networks: no <forward>"
# 'ghosts' is the one deliberate exception (#331: WAN-permitted by design,
# NAT forward is intentional) -- every OTHER sandbox network must have none.
for entry in "${GUARDED_BRIDGES[@]}"; do
  read -r net _ <<<"$entry"
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
section "Phase 0 iptables barrier (guarded sandbox bridges)"
# sandbox/honeypot-sandbox have no <forward> element, so libvirt never adds a
# LIBVIRT_FWI/FWO/FWX rule routing them anywhere -- the isolation is the
# FORWARD chain's own default policy catching everything libvirt didn't
# explicitly allow, not a named per-bridge DROP rule. The real failure mode
# to catch is the default policy being ACCEPT, or an explicit ACCEPT rule
# for a guarded bridge added later (by hand, or by an unrelated tool) that
# would override the default. Checked for every bridge in GUARDED_BRIDGES,
# not just the Windows one (#2295).
if ! command -v iptables >/dev/null 2>&1; then
  bad "iptables not found"
elif iptables_rules=$(sudo -n iptables -S FORWARD 2>&1); then
  policy=$(grep '^-P FORWARD' <<<"$iptables_rules" | awk '{print $3}')
  if [ "$policy" != "DROP" ]; then
    bad "FORWARD chain default policy is '$policy', not DROP -- sandbox traffic with no explicit rule would be forwarded"
  else
    ok "FORWARD default policy is DROP"
    for entry in "${GUARDED_BRIDGES[@]}"; do
      read -r _ bridge _ _ _ <<<"$entry"
      if grep -q "$bridge.*ACCEPT" <<<"$iptables_rules"; then
        bad "an explicit ACCEPT rule references $bridge in the FORWARD chain -- this overrides the default-DROP isolation"
      else
        ok "nothing explicitly ACCEPTs $bridge traffic"
      fi
    done
  fi
else
  bad "could not read iptables FORWARD chain (sudo -n iptables failed: needs the isolation-audit sudoers grant)"
fi

# ---------------------------------------------------------------------------
section "sbx-* macvlan network (docker-compose.sandbox.yml)"
# docker-group membership (already granted, see #2565/#2780) covers plain
# 'docker' commands without sudo -- the isolation-audit sudoers grant this
# script otherwise references is only for iptables/ss/aa-status, which do
# need root (#2778).
if net_json=$(docker network inspect sandbox_sandbox 2>/dev/null || docker network inspect honeypot-sandbox_sandbox 2>/dev/null); then
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
section "No host route into guarded sandbox subnets other than their own bridge"
# 'ip route get' resolves the route the kernel would actually use for an
# address in the subnet, so a covering supernet route (e.g. someone
# aggregates lab ranges under a /16) is caught the same way an exact-prefix
# one is -- 'ip route show <subnet>' (the old check) only matched the
# latter. Comparing the resolved device against the host's own default
# route tells "nothing sandbox-specific is configured right now" (expected
# between detonations) apart from "some other specific route exists" (never
# expected).
default_dev=$(ip route show default 2>/dev/null | awk '/^default/ {print $5; exit}')
for entry in "${GUARDED_BRIDGES[@]}"; do
  read -r _ bridge subnet probe_ip bridge_mode <<<"$entry"
  authorized=0
  if [ "$bridge_mode" = "forensic-egress" ] && command -v systemctl >/dev/null 2>&1 \
     && systemctl is-active --quiet honeypot-sandbox-egress-network.service 2>/dev/null; then
    authorized=1
  fi
  route_out=$(ip route get "$probe_ip" 2>/dev/null)
  routed_dev=$(grep -oE 'dev [^ ]+' <<<"$route_out" | head -1 | awk '{print $2}')
  if [ "$bridge_mode" = "forensic-egress" ] && [ "$authorized" -eq 0 ] && [ "$routed_dev" = "$bridge" ]; then
    bad "$subnet has a host route via $bridge outside the forensic-egress window (honeypot-sandbox-egress-network.service is not active) -- did teardown fail?"
  elif [ -n "$routed_dev" ] && [ "$routed_dev" != "$bridge" ] && [ "$routed_dev" != "$default_dev" ]; then
    bad "$subnet resolves via '$routed_dev', neither $bridge nor the host default route -- unexpected route (possibly a covering supernet): $route_out"
  elif [ "$routed_dev" = "$bridge" ]; then
    ok "$subnet is only reachable via $bridge"
  else
    info "no sandbox-specific route to $subnet ($bridge not currently up, or the forensic-egress window is closed -- expected between detonations)"
  fi
done

# ---------------------------------------------------------------------------
section "Stack containers (hp-*/sbx-* only -- this host also runs unrelated stacks: dockge, pihole, ghidra/ollama, ghosts-*, etc.)"
if containers=$(docker ps -a --format '{{.Names}}\t{{.Image}}' 2>&1 | grep -E '^(hp-|sbx-)'); then
  privileged_others=""
  while IFS=$'\t' read -r name _; do
    [ -z "$name" ] && continue
    is_priv=$(docker inspect "$name" --format '{{.HostConfig.Privileged}}' 2>/dev/null || echo false)
    if [ "$is_priv" = "true" ] && [ "$name" != "hp-tanner-docker" ]; then
      privileged_others="$privileged_others $name"
    fi
    sock=$(docker inspect "$name" --format '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null | grep -o '/var/run/docker.sock' || true)
    # #2877: hp-arcane's socket mount is deliberate and already documented --
    # it is the deploy control plane, and a manager that creates containers on
    # this host cannot do its job without the socket. So FAIL was the wrong
    # tier. But it must NOT become silence: CAP_EXCEPTIONS below grants
    # hp-arcane its capability exception *on the express grounds that* "the
    # exposure that matters for it is the socket mount, which the 'Stack
    # containers' section above already reports separately, deliberately and
    # by name". Suppressing the line outright would make that sentence false
    # and would quietly retire the only report of a root-equivalent mount on
    # the deploy control plane. It is reported here as an info line instead:
    # named on every run, not failing the run.
    if [ -n "$sock" ] && [ "$name" = "hp-arcane" ]; then
      info "$name mounts /var/run/docker.sock (root-equivalent) -- deliberate and permanent: the deploy control plane cannot create containers on this host without it. Reported, not failed; see CAP_EXCEPTIONS below, which depends on this line existing"
    elif [ -n "$sock" ] && [ "$name" != "hp-tanner-docker" ] && [ "$name" != "hp-services-adapter" ] && [ "$name" != "hp-autoheal" ] && [ "$name" != "hp-docker-socket-proxy" ]; then
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
    caps=$(docker inspect "$name" --format '{{range .HostConfig.CapAdd}}{{.}} {{end}}' 2>/dev/null || true)
    if grep -qE 'NET_ADMIN|NET_RAW' <<<"$caps"; then
      case "$name" in
        # #2877: hp-zeek-proxy triaged -- a genuine, deliberate NET_RAW/
        # NET_ADMIN grant, never allow-listed here. It runs
        # network_mode: host and sniffs a live honeynet interface via
        # af_packet/libpcap (arcane/home/honeypot-elk/compose.yml), the
        # same real-traffic-capture role sbx-zeek/sbx-suricata/sbx-tcpdump
        # play for sandbox-detonation traffic -- not a regression, a
        # fourth member of the same class this list already exists for.
        sbx-zeek|sbx-suricata|sbx-tcpdump|hp-zeek-proxy) : ;;
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
  bad "could not enumerate containers (docker ps failed)"
fi

# ---------------------------------------------------------------------------
section "Container capability posture (hp-* containers)"
# #2366: the fourth time capability hardening lapsed for a whole generation
# of stacks (#89 -> #118 -> #133 -> #2366), because nothing here ever
# checked capabilities -- a stack could drop every other mitigation and
# still run with Docker's full default capability set (NET_RAW included)
# and this script would say nothing. Every hp-* container now must either
# report cap_drop: ALL, or be named below with the reason it isn't yet --
# an undocumented gap is a hard FAIL from here on, not a silent absence.
# sbx-* sandbox-detonation containers are a different, already-audited
# posture (NET_ADMIN/NET_RAW section above) and are skipped here.
#
# Three tiers, because "hardened or FAIL" alone would make this section
# permanently red on the deployed fleet and therefore ignorable (see warn()'s
# comment above, and #2366's own review):
#
#   OK    -- cap_drop: ALL is actually set on the running container. A
#            justified cap_add alongside it still counts (yara-scanner's
#            DAC_READ_SEARCH, for one): dropping the default set and adding
#            back exactly what was measured IS the target posture.
#   --    CAP_EXCEPTIONS: deliberate and permanent. Not a to-do, will never
#         become an OK, and each entry says why in its own words.
#   WARN  CAP_NOT_YET_HARDENED: a real gap, triaged, with an owner issue.
#         Reported on every run, does not fail the job.
#   FAIL  anything else: nobody has looked at this container's capability
#         posture, which is always actionable -- either harden it or triage
#         it onto one of the two lists above.
#
# Entries are "<container>|<reason>"; the reason is mandatory, and the
# list-hygiene pass at the end of this section surfaces entries that are
# stale (already hardened, or no longer deployed) so neither list can quietly
# rot into a permanent excuse.
CAP_EXCEPTIONS=(
  "hp-tanner-docker|deliberate privileged exception -- runs its own disposable nested Docker daemon on an isolated tanner_local network with a tmpfs /var/lib/docker, and never touches the host socket. Its containment is the network and the throwaway daemon, not its capability set"
  "hp-arcane|the deploy control plane itself -- a third-party manager image that runs as root against the real /var/run/docker.sock, which is root-equivalent by construction. Dropping capabilities inside a container that can create privileged containers on the host buys nothing; the exposure that matters for it is the socket mount, which the 'Stack containers' section above already reports separately, deliberately and by name"
)
CAP_NOT_YET_HARDENED=(
  # #2825, class A: runs as uid 0 and reads/writes the sensor-owned log,
  # state and payload trees (/opt/stacks/apiary/logs/<sensor> is owned by the
  # sensor's own UID at drwxrwsr-x; Dionaea captures are mode 0600). Measured,
  # not assumed: a uid-0 process under cap_drop: ALL has CapEff 0 and so no
  # CAP_DAC_OVERRIDE, and can no longer create, read or unlink in those trees
  # -- a bare cap_drop: ALL would silently break log rotation, pcap sync,
  # disk reporting, payload dedup and the canarytokens log writers. Each needs
  # cap_drop: ALL plus a measured minimal cap_add, the way yara-scanner
  # already carries a justified DAC_READ_SEARCH.
  #
  # #2825 round 2: hp-log-maintenance, hp-disk-space-monitor,
  # hp-canarytokens-frontend, hp-canarytokens-switchboard and
  # hp-payload-dedupe moved off this list -- each now carries
  # cap_drop: ALL + cap_add: [DAC_OVERRIDE] in its compose file, measured
  # live against the real bind mount (a plain touch/write/hard-link failed
  # with no cap_add, and succeeded with DAC_OVERRIDE alone added back --
  # for hp-payload-dedupe this also settles its own prior "possibly
  # FOWNER" guess: not needed). hp-canarytokens-redis moved too, see below.
  # They will FAIL here (deploy drift, same shape as #2877) until the
  # affected projects (honeypot-utilities, honeypot-canarytokens,
  # honeypot-payload-analysis) are actually re-synced and redeployed --
  # that is expected, not a regression.
  "hp-pcap-sync|#2825 class A -- uid 0 copying between the sshfs-backed raw dir and the arkime-pcap volume, needs a measured cap_add"
  "hp-arkime-capture|#2825 class A -- uid 0 reading the sensor-owned arkime-raw tree (offline import, so no NET_RAW is involved), needs a measured cap_add. Round 2 attempted to measure this live (a parallel --skip capture instance against the real ES) and could not get a clean answer inside this round's budget -- the test instance stalled on Elasticsearch readiness before reaching the privilege-drop question. Still unmeasured; do not guess dropUser=nobody's actual capability need from this comment"
  "hp-arkime-viewer|#2825 class A -- uid 0 over the same arkime-raw/arkime-pcap trees, needs a measured cap_add"
  # #2825, class B: the process itself already runs capability-free (redis is
  # uid 999 with CapEff 0 today), but the official entrypoint gets there by
  # chown-ing /data and calling setpriv as root, which needs CHOWN/SETUID/
  # SETGID. Round 2: re-measured live against the real data volume and this
  # was incomplete -- CHOWN+SETUID+SETGID alone still failed ("find:
  # ./appendonlydir: Permission denied") against the existing 700-mode
  # appendonlydir; DAC_OVERRIDE was also required. hp-canarytokens-redis now
  # carries cap_drop: ALL + cap_add: [CHOWN, SETUID, SETGID, DAC_OVERRIDE].
  # #2366 scoped itself to the internet-facing sensor stacks. These are the
  # internal workers and honeypot-init's one-shot jobs it deliberately did not
  # touch, carried over unchanged and now tracked in #2825 rather than in a
  # follow-up that was never filed.
  "hp-attacker-identity-worker|#2825 -- internal worker, out of #2366's internet-facing scope"
  "hp-correlator-worker|#2825 -- internal worker, out of #2366's internet-facing scope"
  "hp-payload-inventory-worker|#2825 -- internal worker, out of #2366's internet-facing scope"
  "hp-persona-apply|#2825 -- honeypot-init job, out of #2366's internet-facing scope"
  "hp-log-init|#2825 -- honeypot-init job, out of #2366's internet-facing scope"
  "hp-elasticsearch-setup|#2825 -- honeypot-init job, out of #2366's internet-facing scope"
  "hp-honeypot-kibana-setup|#2825 -- honeypot-init job, out of #2366's internet-facing scope"
  "hp-arkime-init|#2825 -- honeypot-init job, out of #2366's internet-facing scope"
  "hp-snare-clone|#2825 -- honeypot-init job, out of #2366's internet-facing scope"
  "hp-geoipupdate|#2825 -- honeypot-init refresh job, out of #2366's internet-facing scope"
  "hp-threat-cidrs-refresh|#2825 -- honeypot-init refresh job, out of #2366's internet-facing scope"
)

# Returns the reason string for $1 if it appears in the remaining arguments.
cap_listed_reason() {
  local needle=$1 entry
  shift
  for entry in "$@"; do
    if [ "${entry%%|*}" = "$needle" ]; then
      printf '%s' "${entry#*|}"
      return 0
    fi
  done
  return 1
}

cap_hardened_names=""
if [ -n "${containers:-}" ]; then
  while IFS=$'\t' read -r name _; do
    [ -z "$name" ] && continue
    case "$name" in sbx-*) continue ;; esac
    capdrop=$(docker inspect "$name" --format '{{.HostConfig.CapDrop}}' 2>/dev/null || echo "")
    # Checked before either list, so a service that gets hardened starts
    # reporting OK immediately and its stale list entry is surfaced below --
    # being on a list can never mask real progress.
    if grep -qiE '\ball\b' <<<"$capdrop"; then
      ok "$name has cap_drop: ALL"
      cap_hardened_names="$cap_hardened_names $name"
      continue
    fi
    if cap_why=$(cap_listed_reason "$name" "${CAP_EXCEPTIONS[@]}"); then
      info "$name has no cap_drop: ALL -- documented permanent exception: $cap_why"
      continue
    fi
    if cap_why=$(cap_listed_reason "$name" "${CAP_NOT_YET_HARDENED[@]}"); then
      warn "$name has no cap_drop: ALL -- known gap: $cap_why"
      continue
    fi
    bad "$name has no cap_drop: ALL and is on neither the exception nor the tracked-gap list -- deploy drift (the repo compose has cap_drop but the running container predates it -- #2858/#2877: re-sync and redeploy that project), or the #2366 gap regressed, or this is a new container that shipped unhardened. Check the project's compose file before assuming a regression. Harden it, or triage it onto one of the two lists in this script with a written reason"
  done <<<"$containers"

  # List hygiene. Neither list is allowed to outlive what it excuses: an entry
  # for a container that is now hardened, or that is no longer deployed at
  # all, is dead weight that makes the next reader trust the list less. #2366's
  # own review caught exactly this (an allow-listed worker that wasn't running
  # on the host), so it is now checked rather than assumed. Reported, never
  # fatal -- a stale entry is a tidiness problem, not an isolation failure.
  for entry in "${CAP_EXCEPTIONS[@]}" "${CAP_NOT_YET_HARDENED[@]}"; do
    listed_name="${entry%%|*}"
    if grep -qw -- "$listed_name" <<<"$cap_hardened_names"; then
      info "list hygiene: $listed_name now reports cap_drop: ALL -- drop its entry from this script's lists"
    elif ! grep -qE "^${listed_name}\b" <<<"$containers"; then
      info "list hygiene: $listed_name is listed here but not deployed on this host -- keep it only if the stack is expected back"
    fi
  done
  printf '  (capability posture: %d hardened, %d tracked gaps, see WARN lines)\n' \
    "$(wc -w <<<"$cap_hardened_names")" "$warns"
else
  bad "could not check capability posture (container enumeration failed above)"
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
if [ "$warns" -gt 0 ]; then
  # Deliberately does not affect the exit status: these are triaged gaps with
  # an owner issue, not regressions. They are printed after the verdict so
  # they stay visible without turning the job red forever (#2366 review).
  printf 'isolation-audit: %d triaged gap(s) reported as WARN -- tracked, not failing this run\n' "$warns"
fi
exit "$fail"
