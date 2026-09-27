#!/usr/bin/env bash
# sandbox-standdown.sh -- declare, inspect or clear a DELIBERATE stand-down of
# the libvirt-backed sandbox isolation stack (#3312).
#
# Why this exists. scripts/isolation-audit.sh asserts that the guarded sandbox
# networks (sandbox, honeypot-sandbox), the honeypot-sandbox-strict nwfilter
# and libvirt's own socket are present. Those assertions were all "FAIL" and
# nothing else, so the audit could not tell two very different hosts apart:
#
#   * a broken one -- e.g. the 2026-09-23 reboot, where the per-driver modular
#     libvirt units (virtqemud/virtnetworkd/... each Conflicts=libvirtd) won
#     the race and left libvirtd.socket dead, taking every sandbox object with
#     it (#3338), or a post-rebuild host where install-host.sh was never re-run
#     and the network and nwfilter were never restored (#3027). Both are real
#     regressions and must stay red.
#   * an expected one -- a host whose operator has deliberately stood the
#     sandbox stack down to free the RAM and CPU it holds for a heavy
#     training or benchmark leg, which is a standing practice (#3135), or any
#     other deliberate, temporary choice.
#
# Before this, both hosts read as the same red line, so a reader could not
# triage it, and a diagnostic that cries wolf identically on a healthy and a
# broken host is a diagnostic whose red X nobody acts on -- which is exactly
# what #3312 was filed about.
#
# The declaration is a small dated file, world-readable and owned by root, at
# /etc/apiary/sandbox-standdown. The audit reads it (see the standdown_state()
# function in isolation-audit.sh) and applies three rules, all of which fail
# CLOSED, i.e. towards "still a fault":
#
#   1. A live declaration excuses ONLY the absence of the objects it names
#      (the guarded networks, the nwfilter, the libvirt socket). It never
#      excuses a <forward> element, a host route, a privileged container or
#      any other invariant -- a stand-down is not an amnesty.
#   2. A declaration is bounded. `until` must be in the future, and at most
#      STANDDOWN_MAX_DAYS ahead, so an exception cannot be declared once and
#      then quietly live forever -- the same anti-rot rule the audit already
#      applies to its capability lists (see the list-hygiene pass).
#   3. A declaration that is present but NOT active -- expired, malformed, or
#      missing a mandatory field -- is itself a FAIL. An expired exception is
#      not an exception, and a typo must never be able to neuter the audit.
#
# This script only writes that file. It changes no libvirt, network or
# container state: standing the stack down and bringing it back is the
# operator's own systemctl/virsh work, and the audit's job is to report what
# the host actually looks like, not to fix it.
set -euo pipefail

STANDDOWN_FILE="${APIARY_STANDDOWN_FILE:-/etc/apiary/sandbox-standdown}"
# Kept in sync with isolation-audit.sh's own copy. Both are overridable by
# env so the audit's test suite can point them at a tmpfile; the constant
# itself is duplicated rather than shared because isolation-audit.sh is
# deployed and run on its own (diagnostics.yml, and the root systemd timer
# its header mentions) and must not depend on a second file being present.
STANDDOWN_MAX_DAYS="${APIARY_STANDDOWN_MAX_DAYS:-14}"

usage() {
  cat >&2 <<EOF
Usage: $0 declare  --issue '#1234' --until YYYY-MM-DD --reason 'why'
       $0 show
       $0 clear

Writes the dated declaration read by scripts/isolation-audit.sh at:
  $STANDDOWN_FILE

  declare   record that the sandbox isolation stack is deliberately down
            until --until (at most $STANDDOWN_MAX_DAYS ahead). Requires root.
  show      print the declaration and whether the audit currently honours it.
  clear     remove the declaration (no root needed only if the file is
            already world-writable; normally root).

Examples:
  # a training leg holds the RAM/CPU the sandbox VMs need, until the leg ends
  sudo $0 declare --issue '#3135' --until 2026-10-04 \\
      --reason 'round-8 training leg: sandbox VMs and libvirt stood down to free 32G'

  # afterwards, and on every scheduled run until then:
  $0 show
EOF
  exit 2
}

[ $# -gt 0 ] || usage
action=$1
shift

case "$action" in
  declare)
    issue='' until='' reason=''
    while [ $# -gt 0 ]; do
      case "$1" in
        --issue) issue=${2:-}; shift 2 ;;
        --until) until=${2:-}; shift 2 ;;
        --reason) reason=${2:-}; shift 2 ;;
        *) echo "unknown argument: $1" >&2; usage ;;
      esac
    done
    [ -n "$issue" ] || { echo "declare needs --issue '#NNNN'" >&2; usage; }
    [ -n "$until" ] || { echo "declare needs --until YYYY-MM-DD" >&2; usage; }
    [ -n "$reason" ] || { echo "declare needs --reason 'why'" >&2; usage; }
    # An owner issue is mandatory and must look like one: the audit's own
    # capability-gap lists work the same way, and an untraceable exception is
    # the thing that rots into a permanent excuse.
    case "$issue" in
      '#'[0-9]*) ;;
      *) echo "--issue must be an issue reference like '#1234', got: $issue" >&2; exit 2 ;;
    esac
    # Validate the date the same way the audit does, before writing anything:
    # a declaration that cannot be parsed is one the audit must treat as a
    # FAIL, and the operator should find that out here instead.
    if ! until_epoch=$(date -d "$until" +%s 2>/dev/null); then
      echo "--until is not a date the host can parse: $until" >&2
      exit 2
    fi
    now_epoch=$(date +%s)
    max_epoch=$(( now_epoch + STANDDOWN_MAX_DAYS * 86400 ))
    if [ "$until_epoch" -le "$now_epoch" ]; then
      echo "--until is in the past ($until): the audit would treat this as an expired exception and fail" >&2
      exit 2
    fi
    if [ "$until_epoch" -gt "$max_epoch" ]; then
      echo "--until is more than $STANDDOWN_MAX_DAYS days out ($until)." >&2
      echo "A stand-down this long is a permanent posture change, not a stand-down:" >&2
      echo "stand the stack down, then leave the audit honest, or open an issue for the change." >&2
      exit 2
    fi
    [ "$(id -u)" = "0" ] || {
      echo "declare must run as root: $STANDDOWN_FILE is root-owned" >&2
      exit 1
    }
    # Only ever create the directory. An existing one (including a bind
    # mount, or /tmp under a test override) is left exactly as it is: a
    # recursive-looking chmod/chown of a parent the operator did not ask us
    # to touch is not this script's business.
    standdown_dir=$(dirname "$STANDDOWN_FILE")
    if [ ! -d "$standdown_dir" ]; then
      install -d -m 0755 -o root -g root "$standdown_dir"
    fi
    # Written to a temp file and moved into place, so a reader (the audit,
    # running as the unprivileged runner user) never sees a half-written
    # declaration and never has to tolerate one.
    tmp=$(mktemp "${STANDDOWN_FILE}.XXXXXX")
    trap 'rm -f "$tmp"' EXIT
    cat > "$tmp" <<EOF
# Sandbox isolation stand-down, written by scripts/sandbox-standdown.sh (#3312).
# Read by scripts/isolation-audit.sh. Remove with: $0 clear
issue: $issue
until: $until
reason: $reason
EOF
    chmod 0644 "$tmp"
    chown root:root "$tmp"
    mv -f "$tmp" "$STANDDOWN_FILE"
    trap - EXIT
    echo "declared a sandbox stand-down until $until ($issue) at $STANDDOWN_FILE"
    ;;
  show)
    if [ ! -f "$STANDDOWN_FILE" ]; then
      echo "no declaration at $STANDDOWN_FILE -- the audit expects the full sandbox stack"
      exit 0
    fi
    cat "$STANDDOWN_FILE"
    issue=$(sed -n 's/^issue: //p' "$STANDDOWN_FILE" | head -1)
    until=$(sed -n 's/^until: //p' "$STANDDOWN_FILE" | head -1)
    reason=$(sed -n 's/^reason: //p' "$STANDDOWN_FILE" | head -1)
    if [ -z "$issue" ] || [ -z "$until" ] || [ -z "$reason" ]; then
      echo "status: INACTIVE (malformed: issue, until and reason are all mandatory)"
      exit 1
    fi
    # Same rule the audit applies on the read side, so `show` never reports
    # ACTIVE for a declaration isolation-audit.sh will treat as malformed.
    case "$issue" in
      '#'[0-9]*) ;;
      *)
        echo "status: INACTIVE (malformed: issue must be an issue reference like '#1234', got '$issue')"
        exit 1
        ;;
    esac
    if ! until_epoch=$(date -d "$until" +%s 2>/dev/null); then
      echo "status: INACTIVE (until is not a date this host can parse: $until)"
      exit 1
    fi
    now_epoch=$(date +%s)
    if [ "$until_epoch" -le "$now_epoch" ]; then
      echo "status: INACTIVE (expired $until -- the audit is failing the sandbox checks again)"
      exit 1
    fi
    if [ "$until_epoch" -gt $(( now_epoch + STANDDOWN_MAX_DAYS * 86400 )) ]; then
      echo "status: INACTIVE (until $until is more than $STANDDOWN_MAX_DAYS days out)"
      exit 1
    fi
    echo "status: ACTIVE until $until ($issue): $reason"
    echo "The audit will report the sandbox stack as EXPECTED, not FAIL, until then."
    ;;
  clear)
    if [ ! -f "$STANDDOWN_FILE" ]; then
      echo "no declaration at $STANDDOWN_FILE -- nothing to clear"
      exit 0
    fi
    [ "$(id -u)" = "0" ] || {
      echo "clear must run as root: $STANDDOWN_FILE is root-owned" >&2
      exit 1
    }
    rm -f "$STANDDOWN_FILE"
    echo "removed $STANDDOWN_FILE -- the audit expects the full sandbox stack again"
    ;;
  *)
    usage
    ;;
esac
