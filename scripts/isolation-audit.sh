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
#
# #3312: every line is prefixed with the category it hit -- OK, FAIL, EXPECT
# (deliberately absent, per a live dated declaration; see standdown_state),
# UNMEAS (could not be measured), WARN (triaged gap) or -- (informational) --
# and the verdict prints the counts. This is not decoration. For the five weeks
# to 2026-09-27 this audit ended 160 consecutive scheduled runs in failure,
# and of the things it named, four were the audit's own blind spots and one
# was a real host fault; a reader of a red run could not tell them apart, so
# the red X meant nothing and #3312 was the result. An expected state that
# cannot be distinguished from a broken one is the same defect as no check.
set -uo pipefail

# #3312: every virsh call below is bare (no -c). As a non-root caller --
# Diagnostics runs this as github-deploy-runner -- libvirt's default URI is
# qemu:///session, the per-user instance, which has no networks or
# nwfilters at all: the sandbox/honeypot-sandbox/nwfilter checks then
# reported "does not exist" for objects that were active on qemu:///system.
# Pin the system instance unless the caller explicitly chose otherwise.
export LIBVIRT_DEFAULT_URI="${LIBVIRT_DEFAULT_URI:-qemu:///system}"

# #3312: every finding below is printed with the CATEGORY it hit, because for
# four days this audit's whole job was indistinguishable from noise: a run
# concluded failure on 2026-08-12 through 2026-09-27, and of the four things it
# named every one was either a check that could not see the object it was
# looking at (bare `virsh` on a non-root caller's qemu:///session, #3312/#3338)
# or a host fault with no category attached to it at all. Nobody could tell
# which was which from the red X, so nobody acted, and a diagnostic that
# cries wolf on a healthy host is worse than no diagnostic.
#
# Four categories, and the label is on every line:
#
#   OK       measured; the invariant holds.
#   FAIL     measured; the invariant is broken. Real, actionable, fatal.
#   EXPECT   the invariant is not measurable as stated because the operator
#            has DECLARED the object deliberately absent -- a dated,
#            issue-referencing declaration (standdown_state below,
#            scripts/sandbox-standdown.sh). Not fatal while the declaration
#            is live, and it never excuses anything except the absence of
#            the object it names.
#   UNMEAS   the check could not run: no privilege, no tool, no daemon. Not
#            fatal for the report-only host-posture observations (the section
#            header already says so), fatal for the isolation barriers, where
#            an unread FORWARD chain is not evidence of a DROP policy -- "could
#            not tell" is never folded into a pass.
#
# The footer prints the counts per category, so a reader can tell at a glance
# whether a red run is a broken host or a broken check.
fails=0
unmeas_fatal=0
warns=0
expected=0
unmeas=0
ok()   { printf '  OK      %s\n' "$*"; }
bad()  { printf '  FAIL    %s\n' "$*"; fails=$((fails + 1)); }
# A known, triaged gap with a named owner issue: visible on every run, but it
# does NOT fail the job. diagnostics.yml exits on this script's status, so a
# finding nobody can act on today would make the whole isolation audit
# permanently red -- and a check that can never go green is a check people
# stop reading, which is the exact failure mode #2366 exists to end. WARN is
# for "triaged, tracked, not yet done"; FAIL stays for "nobody has looked at
# this", which is always actionable.
warn() { printf '  WARN    %s\n' "$*"; warns=$((warns + 1)); }
# Declared-absent, and therefore not a fault. The message always carries the
# owner issue and the expiry, so a reader never has to go looking for why a
# line is not red.
expect() { printf '  EXPECT  %s\n' "$*"; expected=$((expected + 1)); }
# Could not be measured. $1 = '1' when that must fail the run anyway (an
# isolation barrier whose silence would be read as safety), anything else for
# the report-only observations.
unmeasured() {
  if [ "${1:-0}" = "1" ]; then
    printf '  UNMEAS  %s (fatal: this barrier could not be read)\n' "$2"
    unmeas_fatal=$((unmeas_fatal + 1))
  else
    printf '  UNMEAS  %s\n' "$2"
  fi
  unmeas=$((unmeas + 1))
}
info() { printf '  --      %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

# ---------------------------------------------------------------------------
# Declared stand-down of the libvirt-backed sandbox stack (#3312).
#
# The sandbox networks, the nwfilter and libvirt's socket are all *absence*
# invariants: nothing complains when they go missing, which is why this script
# exists at all. But "missing" has two very different causes, and until #3312
# the audit reported both identically:
#
#   broken   -- the 2026-09-23 reboot let the modular per-driver libvirt
#               units win the Conflicts= race against libvirtd and took the
#               socket with them (#3338), or a rebuilt host never re-ran
#               sandbox/install-host.sh, so the Linux lane's network and
#               nwfilter were never restored (#3027).
#   expected -- an operator stood the stack down on purpose, to hand its RAM
#               and CPU to a training/benchmark leg. Freeing host resources
#               for a heavy leg is a standing practice here (#3135).
#
# A dated declaration (scripts/sandbox-standdown.sh writes it; the audit never
# writes it) is what tells them apart. It is deliberately hard to leave lying
# around -- see rule 3 below -- because an exception that outlives its window
# is the failure mode this whole mechanism exists to prevent.
#
# Sets STANDDOWN_ACTIVE=1 and STANDDOWN_WHY to a human sentence when a live
# declaration is present; STANDDOWN_STALE to a reason when one is present but
# does not count. Paths and the max-window are env-overridable so the test
# suite can point them at a tmpfile.
STANDDOWN_FILE="${APIARY_STANDDOWN_FILE:-/etc/apiary/sandbox-standdown}"
STANDDOWN_MAX_DAYS="${APIARY_STANDDOWN_MAX_DAYS:-14}"
standdown_state() {
  STANDDOWN_ACTIVE=0
  STANDDOWN_STALE=''
  STANDDOWN_WHY=''
  [ -f "$STANDDOWN_FILE" ] || return 0
  local sd_issue sd_until sd_reason
  sd_issue=$(sed -n 's/^issue: //p' "$STANDDOWN_FILE" | head -1)
  sd_until=$(sed -n 's/^until: //p' "$STANDDOWN_FILE" | head -1)
  sd_reason=$(sed -n 's/^reason: //p' "$STANDDOWN_FILE" | head -1)
  if [ -z "$sd_issue" ] || [ -z "$sd_until" ] || [ -z "$sd_reason" ]; then
    STANDDOWN_STALE="malformed: issue, until and reason are all mandatory"
    return 0
  fi
  # The writer (scripts/sandbox-standdown.sh declare) refuses anything that
  # does not name an issue, but the audit is what decides pass/fail and root can
  # write anything, so it re-derives the rule rather than trusting the writer.
  # An exception nobody can be held to is the thing that rots into a permanent
  # excuse, and a bare number is the shape that rot arrives in.
  case "$sd_issue" in
    '#'[0-9]*) ;;
    *)
      STANDDOWN_STALE="malformed: issue must be an issue reference like '#1234', got '$sd_issue' -- a stand-down with no issue behind it has no owner to hold it to the window"
      return 0
      ;;
  esac
  local now until_epoch
  now=$(date +%s)
  if ! until_epoch=$(date -d "$sd_until" +%s 2>/dev/null); then
    STANDDOWN_STALE="until is not a date this host can parse: $sd_issue until '$sd_until'"
    return 0
  fi
  if [ "$until_epoch" -le "$now" ]; then
    STANDDOWN_STALE="expired $sd_until ($sd_issue) -- a window that has run out excuses nothing"
    return 0
  fi
  if [ "$until_epoch" -gt $(( now + STANDDOWN_MAX_DAYS * 86400 )) ]; then
    STANDDOWN_STALE="$sd_issue declares a stand-down to $sd_until, more than $STANDDOWN_MAX_DAYS days out -- that is a permanent posture change, not a stand-down"
    return 0
  fi
  STANDDOWN_ACTIVE=1
  STANDDOWN_WHY="declared stand-down, $sd_issue, until $sd_until: $sd_reason"
}
standdown_state

# Reports a sandbox-libvirt object as declared-absent when a live stand-down
# covers it, and as a real fault otherwise. $1 = what is missing, $2 = the
# remediation hint. Kept as one function so no caller can accidentally skip
# the "but is this declared?" question.
standdown_absent() {
  if [ "$STANDDOWN_ACTIVE" = "1" ]; then
    expect "$1 -- EXPECTED, not a fault ($STANDDOWN_WHY)"
  else
    bad "$1 -- $2"
  fi
}

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
# Read first, and loudly: it decides how every sandbox object below is
# categorised, so a reader must never have to infer it from three identical
# absence lines further down.
section "Declared stand-down of the sandbox isolation stack"
if [ -n "$STANDDOWN_STALE" ]; then
  bad "a sandbox stand-down declaration exists at $STANDDOWN_FILE but does not count: $STANDDOWN_STALE. An exception that does not apply is not an exception: clear it (scripts/sandbox-standdown.sh clear) or re-declare it, and read every absent sandbox object below as the regression it is"
elif [ "$STANDDOWN_ACTIVE" = "1" ]; then
  expect "sandbox isolation stack is deliberately absent ($STANDDOWN_WHY). Absent sandbox objects below are EXPECTED, not faults; anything else that breaks below is still a FAIL, and the declaration does not cover it"
else
  info "no stand-down declaration at $STANDDOWN_FILE -- the full sandbox stack is expected here (scripts/sandbox-standdown.sh declare --issue '#NNNN' --until YYYY-MM-DD --reason '...' if it is deliberately down)"
fi

# ---------------------------------------------------------------------------
section "Sandbox libvirt networks: no <forward>"
# 'ghosts' is the one deliberate exception (#331: WAN-permitted by design,
# NAT forward is intentional) -- every OTHER sandbox network must have none.
#
# #3312: a network that is not defined at all is a different question from one
# that is defined and forwards, and a host with the sandbox stack deliberately
# stood down answers the first way. The distinction is the stand-down
# declaration (standdown_absent), not a quieter FAIL.
for entry in "${GUARDED_BRIDGES[@]}"; do
  read -r net _ <<<"$entry"
  if ! virsh net-info "$net" >/dev/null 2>&1; then
    standdown_absent \
      "libvirt network '$net' does not exist (expected active, isolated)" \
      "if the sandbox stack is meant to be up, sandbox/install-host.sh defines it and a stray <forward> is what this check is really for"
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
  unmeasured 1 "iptables is not installed, so the FORWARD barrier cannot be read at all"
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
  unmeasured 1 "could not read the iptables FORWARD chain (sudo -n iptables failed -- it needs the isolation-audit sudoers grant). The default policy is unknown, and unknown is not DROP"
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
  standdown_absent \
    "'honeypot-sandbox-strict' nwfilter is missing" \
    "sandbox/install-host.sh restores it (it was lost the same way in #3027, when a rebuild never re-ran it)"
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
# #3312: `if containers=$(docker ps -a | grep -E '^(hp-|sbx-)')` fused two
# different answers into one FAIL. grep exits 1 when nothing matches, so a host
# with no stack containers at all was reported as "could not enumerate
# containers (docker ps failed)" -- a claim about the tool, printed when the
# truth is a claim about the deployment, and the reader had no way to tell
# which. Enumeration and emptiness are now decided separately.
all_containers=$(docker ps -a --format '{{.Names}}\t{{.Image}}' 2>&1)
if [ $? -ne 0 ]; then
  bad "could not enumerate containers (docker ps failed: ${all_containers//$'\n'/ })"
  containers=''
elif ! containers=$(grep -E '^(hp-|sbx-)' <<<"$all_containers"); then
  bad "no hp-* or sbx-* container exists on this host at all -- the honeypot stack is not deployed here (or every one of its containers was removed). This is not a docker failure"
  containers=''
fi
if [ -n "$containers" ]; then
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
  # #2825's owner issue closed 2026-09-05 with these 14 rows still WARN
  # (#3045). Eleven are now hardened and off this list: hp-pcap-sync,
  # hp-geoipupdate, hp-threat-cidrs-refresh and hp-persona-apply each
  # measured to need cap_drop: ALL + cap_add: [DAC_OVERRIDE] (a plain
  # touch/write against their real bind mount/volume, each owned by a
  # uid other than 0, failed without it and succeeded with only that
  # added back); hp-log-init measured to CHOWN + FOWNER (its whole job is
  # chown -R to per-sensor uids, then chmod on some of what it just
  # chowned away from itself -- CHOWN alone got every chown to succeed
  # but not the chmod); hp-arkime-capture, hp-arkime-viewer,
  # hp-elasticsearch-setup, hp-honeypot-kibana-setup, hp-arkime-init and
  # hp-snare-clone measured to need no cap_add at all, each run for real
  # against the live cluster/host paths rather than assumed from owner
  # bits alone (hp-arkime-capture's privilege drop is enforced by compose's
  # `user: nobody:daemon` -- Docker-level, not advisory -- after #3074
  # found the previous ARKIME__dropUser/dropGroup env vars never took
  # effect in this offline-import mode (upstream's arkime_drop_privileges()
  # is only reached when NOT reading pcap offline) and removed them).
  #
  # Those eleven will FAIL here (deploy drift, same shape as #2877 and as
  # #2825 round 2) until the two projects that own them -- honeypot-elk
  # (hp-pcap-sync, hp-arkime-capture, hp-arkime-viewer) and honeypot-init
  # (the rest) -- are actually re-synced and redeployed. That is expected,
  # not a regression. Five of the eleven still exist as running containers
  # and so are the five that go red; the six one-shot jobs have already
  # exited and contribute nothing. Unlike previous rounds the redeploy is
  # not a few minutes away: it is blocked on #3051 (the Arcane API key is
  # dead), so the window is open-ended. This note exists so that stays a
  # known, dated gap rather than a section everyone learns to ignore --
  # if it is still red once #3051 is unblocked and both projects are
  # redeployed, that IS a regression.
  #
  # The remaining three are internal workers with their own `build:`
  # step (not a pulled image), so they could not be measured inside this
  # round's budget the same way -- still unmeasured, not to be guessed at.
  "hp-attacker-identity-worker|#3045 -- internal worker, out of #2366's internet-facing scope, unmeasured (custom-built image)"
  "hp-correlator-worker|#3045 -- internal worker, out of #2366's internet-facing scope, unmeasured (custom-built image)"
  "hp-payload-inventory-worker|#3045 -- internal worker, out of #2366's internet-facing scope, unmeasured (custom-built image)"
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
    listed_reason="${entry#*|}"
    if grep -qw -- "$listed_name" <<<"$cap_hardened_names"; then
      info "list hygiene: $listed_name now reports cap_drop: ALL -- drop its entry from this script's lists"
    elif ! grep -qE "^${listed_name}\b" <<<"$containers"; then
      info "list hygiene: $listed_name is listed here but not deployed on this host -- keep it only if the stack is expected back"
    fi
    # #3045: #2825 closed with 14 entries still naming it as their owner
    # issue, and nothing here noticed -- a closed owner issue is invisible
    # to the two checks above (the container is neither hardened nor
    # undeployed, so it never got a second look). Best-effort and silent
    # on any failure (gh missing, unauthenticated, or no network): this is
    # a hygiene nicety, not something the audit should ever fail or block
    # on when it can't reach GitHub.
    # Anchored to the *start* of the reason: the owner issue is the one the
    # entry leads with. An unanchored match would take any issue number in
    # the string, so a future entry that cites a closed issue as precedent
    # before naming its own owner would emit a false hygiene line -- in the
    # one check whose whole value is that its hygiene lines can be trusted.
    owner_issue=$(grep -oE '^#[0-9]+' <<<"$listed_reason" | head -1)
    # ...which only works if that convention holds, so the convention is
    # checked too: the tiering above makes an owner issue mandatory for a
    # tracked gap, and an entry that does not open with one is now skipped
    # silently rather than reported. CAP_EXCEPTIONS are exempt by
    # definition -- they are permanent and owned by nobody.
    if [ -z "$owner_issue" ] && cap_listed_reason "$listed_name" "${CAP_NOT_YET_HARDENED[@]}" >/dev/null; then
      info "list hygiene: $listed_name is a tracked gap whose reason does not open with its owner issue -- start it with #NNNN, or its owner can never be checked for closure"
    fi
    if [ -n "$owner_issue" ] && command -v gh >/dev/null 2>&1; then
      # timeout: the only network call in a script that otherwise talks to
      # nothing but the local docker socket. A hung gh must not stall the
      # audit (diagnostics.yml runs it and exits on its status).
      # --repo is not optional, measured rather than assumed: the copy that
      # matters is the deployed one, and it runs with no usable git context
      # in either place it runs from. diagnostics.yml deliberately has no
      # actions/checkout, and /opt/stacks/apiary resolves into root-owned
      # /var/dockge/stacks/apiary, which git refuses as dubious ownership.
      # Without --repo, gh cannot resolve a repository and this whole check
      # silently never fires -- exactly the quiet nothing it exists to end.
      # GITHUB_REPOSITORY is set for free under Actions; the default covers
      # the root systemd timer.
      owner_state=$(timeout 10 gh issue view "${owner_issue#\#}" \
        --repo "${GITHUB_REPOSITORY:-Xore/APIARY}" --json state -q .state 2>/dev/null) || owner_state=""
      if [ "$owner_state" = "CLOSED" ]; then
        info "list hygiene: $listed_name names $owner_issue as its owner issue, and $owner_issue is closed -- repoint this entry at whatever now tracks the gap, or the list will silently rot the way #2825's closure did"
      fi
    fi
  done
  printf '  (capability posture: %d hardened, %d tracked gaps, see WARN lines)\n' \
    "$(wc -w <<<"$cap_hardened_names")" "$warns"
else
  # No second fault for one cause: the Stack containers section above has
  # already reported, with its own category, why there is no inventory (the
  # docker call failed, or the host has no stack containers at all). Two
  # faults for one underlying condition is how a red run stops meaning
  # anything.
  info "no container inventory to audit capability posture -- the Stack containers section above reports why"
fi

# ---------------------------------------------------------------------------
section "Host posture (reports only, does not fix)"
# #3312: this check used to be `if ss_out=$(sudo -n ss -tlnp | grep ':22 ')`.
# That fuses two different outcomes into one branch: "ss could not run" and
# "nothing is listening on :22" both make the pipeline's last stage exit 1, so
# both printed 'could not confirm'. On the live homeserver that line has been
# printing on every run -- an sshd-listen-address check that has never once
# actually answered the question it exists to answer, and an UNMEAS line is
# exactly as easy to overlook as a wrong one. The stages are separated now:
# run ss, and only judge its output if it ran.
if ss_out=$(sudo -n ss -tlnp 2>/dev/null); then
  if ! grep -q ':22 ' <<<"$ss_out"; then
    ok "nothing is listening on :22, so sshd cannot be on a honeypot-facing address"
  elif grep -qE '10\.8\.0\.|10\.10\.10\.' <<<"$ss_out"; then
    bad "sshd appears to be listening on a honeypot-facing address"
  else
    ok "sshd is not listening on a honeypot-facing address"
  fi
else
  unmeasured 0 "could not read the sshd listen address at all (sudo -n ss -tlnp failed -- it needs the isolation-audit sudoers grant, or ss is not on this host's PATH). This check has not run; it is not a pass"
fi

sock_path=/var/run/libvirt/libvirt-sock
if [ -S "$sock_path" ]; then
  # #2976: two different, both legitimate, access-control models exist for
  # this socket, and the check used to only recognize one of them.
  #
  #   Debian/Ubuntu: unix_sock_group defaults to "libvirt" and the socket
  #   ships root:libvirt with no world access -- Unix permissions ARE the
  #   access boundary, so "world-accessible" would be a real hole there.
  #
  #   RHEL/Fedora/Rocky: libvirtd.socket ships SocketMode=0666, root:root,
  #   by vendor default -- confirmed live on the rebuilt homeserver
  #   (2026-09-05), not a local misconfiguration. Access control here is
  #   polkit's job instead: /usr/share/polkit-1/rules.d/50-libvirt.rules
  #   auto-allows only the "libvirt" group for org.libvirt.unix.manage,
  #   and any other caller falls through to the packaged policy's default
  #   (auth_admin_keep -- requires authentication, denied outright with no
  #   agent). A wide-open socket mode is not a gap on this distro family;
  #   treating it as one hard-FAILs every RHEL-family host regardless of
  #   its actual posture, which is the exact false-positive #2951 already
  #   fixed for a different socket.
  mode=$(stat -c '%a' "$sock_path" 2>/dev/null)
  owner=$(stat -c '%U:%G' "$sock_path" 2>/dev/null)
  other_bits=${mode: -1}
  if [ "$owner" = "root:libvirt" ] && [ "$other_bits" = "0" ]; then
    ok "libvirt socket is $mode $owner (root:libvirt, no world access)"
  elif systemctl is-active --quiet polkit 2>/dev/null \
    && [ -f /usr/share/polkit-1/rules.d/50-libvirt.rules ] \
    && grep -q 'org.libvirt.unix.manage' /usr/share/polkit-1/rules.d/50-libvirt.rules 2>/dev/null; then
    ok "libvirt socket is $mode $owner, write/manage access gated by the active polkit org.libvirt.unix.manage rule (RHEL-family default, not a Unix-permission boundary; the read-only socket below is a separate object this rule does not cover)"
  else
    bad "libvirt socket is $mode $owner -- expected root:libvirt with no world access, or an active polkit rule gating org.libvirt.unix.manage"
  fi
else
  standdown_absent \
    "libvirt socket not found at $sock_path" \
    "the monolithic libvirtd.socket is dead: the per-driver modular units (virtqemud, virtnetworkd, virtnwfilterd, ...) each Conflicts= libvirtd and win the race after a reboot unless install-homeserver.sh's monolithic branch disabled all of them (#3338). Enable it with: systemctl enable --now libvirtd.socket"
fi

sock_ro_path=/var/run/libvirt/libvirt-sock-ro
if [ -S "$sock_ro_path" ]; then
  # #3039: this is a distinct socket from libvirt-sock above and the
  # org.libvirt.unix.manage polkit rule that gates the RW socket on
  # RHEL-family hosts does NOT cover it -- confirmed live (2026-09-08):
  # `virsh -c qemu+unix:///system?socket=.../libvirt-sock-ro list --all`
  # succeeded unauthenticated as an unprivileged user with no polkit prompt.
  # World-readable VM enumeration (list/dumpxml, no state-changing actions)
  # may be an acceptable posture for a honeypot host, but it must be a
  # recorded decision rather than a silent gap or a day-one hard-FAIL on
  # every RHEL-family host's shipped default.
  mode=$(stat -c '%a' "$sock_ro_path" 2>/dev/null)
  owner=$(stat -c '%U:%G' "$sock_ro_path" 2>/dev/null)
  other_bits=${mode: -1}
  if [ "$owner" = "root:libvirt" ] && [ "$other_bits" = "0" ]; then
    ok "libvirt read-only socket is $mode $owner (root:libvirt, no world access)"
  else
    warn "libvirt read-only socket is $mode $owner -- unauthenticated read-only VM enumeration is possible (no polkit rule gates the RO monitor actions); accepted as read-only exposure on this honeypot host, tracked in #3039"
  fi
else
  standdown_absent \
    "libvirt read-only socket not found at $sock_ro_path" \
    "it ships with the monolithic libvirtd stack and comes back with it (#3338); if libvirtd is up, the -ro socket should be too"
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
    unmeasured 0 "could not run aa-status (needs the isolation-audit sudoers grant) -- the libvirt/QEMU AppArmor posture is unmeasured, not fine"
  fi
else
  info "AppArmor not installed on this host"
fi

# ---------------------------------------------------------------------------
# The verdict, with its category counts (#3312). The point of printing them is
# that a reader must be able to answer "is this host broken, or is this check
# broken?" from the last five lines, without re-deriving it from the body --
# the failure this file exists to end is a red run whose meaning has to be
# reconstructed by hand.
printf '\n'
# `fail` counts measured violations; `unmeas_fatal` counts barriers that could
# not be read at all. Both are faults, and the second is the more dangerous of
# the two -- an unread FORWARD chain tells you nothing about whether the
# default policy is still DROP.
faults=$(( fails + unmeas_fatal ))
printf 'isolation-audit: categories -- %d unmeasured, %d expected-by-declaration, %d triaged gap(s), %d fault(s)\n' \
  "$unmeas" "$expected" "$warns" "$faults"
if [ "$STANDDOWN_ACTIVE" = "1" ]; then
  printf 'isolation-audit: a declared stand-down is in force (%s) -- the sandbox objects it covers were not checked for presence, and everything else was\n' \
    "$STANDDOWN_WHY"
fi
if [ "$unmeas" -gt 0 ]; then
  # Also non-fatal on its own: the fatal ones are already counted in
  # $faults above, so this line is the count a reader needs, not a verdict.
  printf 'isolation-audit: %d check(s) could not be measured at all -- every UNMEAS line above is an unanswered question, not a pass\n' "$unmeas"
fi
if [ "$faults" -eq 0 ]; then
  printf 'isolation-audit: VERDICT PASS -- every check that could be measured agrees with the invariants (%s)\n' \
    "$([ "$expected" -gt 0 ] && printf '%d object(s) excused by a live declaration' "$expected" || printf 'nothing excused')"
else
  printf 'isolation-audit: VERDICT FAIL -- %d fault(s) above: each is a measured violation, an exception that no longer applies, or a barrier that could not be read (%d of the latter). None of them is a configuration problem with this script\n' \
    "$faults" "$unmeas_fatal"
fi
if [ "$warns" -gt 0 ]; then
  # Deliberately does not affect the exit status: these are triaged gaps with
  # an owner issue, not regressions. They are printed after the verdict so
  # they stay visible without turning the job red forever (#2366 review).
  printf 'isolation-audit: %d triaged gap(s) reported as WARN -- tracked, not failing this run\n' "$warns"
fi
exit "$([ "$faults" -gt 0 ] && echo 1 || echo 0)"
