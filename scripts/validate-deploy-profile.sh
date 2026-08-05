#!/usr/bin/env bash
# validate-deploy-profile.sh — check a deploy-profiles/*.txt selection for
# real cross-stack consistency before it's used to deploy anything.
#
# #265 (rescoped to the post-#258 topology, see docs/deploy-profiles/README.md):
# T-Pot's compose/customizer.py walks an operator through a per-service
# choice and fails fast on an invalid combination rather than failing
# silently at runtime. This is the equivalent for this repo's current
# shape -- one compose file per Dockge stack instead of one compose file
# with many services, so the thing being validated is "which stacks" and
# "does EXPECTED_SENSORS agree with them", not "which services within one
# file".
#
# Usage:
#   scripts/validate-deploy-profile.sh deploy-profiles/<name>.txt
#   scripts/validate-deploy-profile.sh --emit-expected-sensors deploy-profiles/<name>.txt
# Run from the repo root (reads docker-compose.dashboard.yml relative to it).
#
# --emit-expected-sensors prints the EXPECTED_SENSORS value this profile
# actually needs, instead of validating against docker-compose.dashboard.yml's
# current one. EXPECTED_SENSORS there is a single hardcoded value assuming
# every sensor is present -- it is NOT profile-aware today, so any profile
# narrower than deploy-profiles/full.txt WILL fail the cross-check below
# until that line is hand-edited (or overridden) to match. This flag exists
# so that edit has a concrete, correct value to copy rather than a guess.

set -euo pipefail

emit_mode=false
if [ "${1:-}" = "--emit-expected-sensors" ]; then
  emit_mode=true
  shift
fi

profile="${1:?Usage: $0 [--emit-expected-sensors] deploy-profiles/<name>.txt}"
[ -f "$profile" ] || { echo "No such profile file: $profile" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dashboard_compose="$repo_root/docker-compose.dashboard.yml"
[ -f "$dashboard_compose" ] || { echo "Cannot find docker-compose.dashboard.yml at $dashboard_compose" >&2; exit 1; }

# Every sensor stack this profile format can name, mapped to the
# EXPECTED_SENSORS name(s) that stack is responsible for. Kept in sync by
# hand with .github/workflows/deploy.yml's own sensor loop and
# docker-compose.dashboard.yml's EXPECTED_SENSORS -- both are cross-checked
# below, so a stale entry here shows up as a mismatch rather than silently
# passing.
declare -A STACK_TO_SENSORS=(
  [cowrie]="cowrie"
  [multipot]="multipot"
  [http]="http api-honeypot"
  [dionaea]="dionaea"
  [dnp3]="dnp3"
  [dicompot]="dicompot"
  [dns-honeypot]="dns-honeypot"
  [citrix-honeypot]="citrix-honeypot"
  [cisco-asa-honeypot]="cisco-asa-honeypot"
  [rdp-honeypot]="rdp-honeypot"
  [tanner]="tanner"
  [conpot]="conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup"
)
# suricata runs on the VPS, unconditionally, regardless of which home
# sensor stacks are enabled -- not tied to any profile entry.
UNCONDITIONAL_SENSORS="suricata"

errors=0
warnings=0
fail()  { echo "FAIL: $*" >&2; errors=$((errors + 1)); }
warn()  { echo "WARN: $*" >&2; warnings=$((warnings + 1)); }
pass()  { echo "ok   - $*"; }

declare -A enabled
while IFS= read -r line; do
  line="${line%%#*}"
  line="$(echo "$line" | tr -d '[:space:]')"
  [ -n "$line" ] || continue
  enabled["$line"]=1
done < "$profile"

has_sensor=false
for stack in "${!STACK_TO_SENSORS[@]}"; do
  [ -v "enabled[$stack]" ] && has_sensor=true
done

if $emit_mode; then
  names=("$UNCONDITIONAL_SENSORS")
  for stack in "${!STACK_TO_SENSORS[@]}"; do
    [ -v "enabled[$stack]" ] || continue
    for name in ${STACK_TO_SENSORS[$stack]}; do names+=("$name"); done
  done
  IFS=','
  echo "EXPECTED_SENSORS=${names[*]}"
  exit 0
fi

# ── structural dependencies ──────────────────────────────────────────────
if $has_sensor; then
  [ -v "enabled[init]" ] || fail "at least one sensor stack is enabled but 'init' is not -- honeypot-init's log-init/persona-apply/elasticsearch-setup jobs are what every sensor's entrypoint waits on."
  [ -v "enabled[elk]" ]  || fail "at least one sensor stack is enabled but 'elk' is not -- nothing ships events to Elasticsearch without Filebeat/honeypot-elk running."
fi
if [ -v "enabled[dashboard]" ]; then
  [ -v "enabled[elk]" ] || fail "'dashboard' is enabled but 'elk' is not -- the dashboard reads several sensors' events from Elasticsearch, not their log files (#403), and always needs it reachable."
fi
if $has_sensor && ! [ -v "enabled[utilities]" ]; then
  warn "'utilities' is not enabled -- no log rotation, disk-space monitoring, or autoheal for this deployment."
fi
if $has_sensor && ! [ -v "enabled[payload-analysis]" ]; then
  warn "'payload-analysis' is not enabled -- no payload dedup or YARA scanning for this deployment."
fi

# ── EXPECTED_SENSORS cross-check, parsed live, not hardcoded ────────────
expected_line="$(grep -o 'EXPECTED_SENSORS=[^[:space:]]*' "$dashboard_compose" | head -n1)"
if [ -z "$expected_line" ]; then
  fail "could not find EXPECTED_SENSORS in $dashboard_compose -- is the format still 'EXPECTED_SENSORS=a,b,c'?"
else
  expected_csv="${expected_line#EXPECTED_SENSORS=}"
  declare -A expected_names
  IFS=',' read -ra names <<< "$expected_csv"
  for n in "${names[@]}"; do expected_names["$n"]=1; done

  # profile stack enabled -> every one of its sensor names must be expected
  for stack in "${!STACK_TO_SENSORS[@]}"; do
    [ -v "enabled[$stack]" ] || continue
    for name in ${STACK_TO_SENSORS[$stack]}; do
      if [ -v "expected_names[$name]" ]; then
        pass "'$stack' is enabled and '$name' is in EXPECTED_SENSORS"
      else
        fail "'$stack' is enabled but '$name' is missing from EXPECTED_SENSORS in $dashboard_compose -- the dashboard would never flag it as expected-but-offline, it'd just be silently absent from health checks."
      fi
    done
  done

  # expected name -> owning stack must be enabled (unless unconditional)
  for name in "${!expected_names[@]}"; do
    case " $UNCONDITIONAL_SENSORS " in *" $name "*) continue ;; esac
    owner=""
    for stack in "${!STACK_TO_SENSORS[@]}"; do
      case " ${STACK_TO_SENSORS[$stack]} " in *" $name "*) owner="$stack" ;; esac
    done
    if [ -z "$owner" ]; then
      warn "'$name' is in EXPECTED_SENSORS but no stack in this script's own STACK_TO_SENSORS map owns it -- this validator's map is stale, update it."
    elif ! [ -v "enabled[$owner]" ]; then
      fail "EXPECTED_SENSORS names '$name' (owned by stack '$owner') but '$owner' is not enabled in this profile -- the dashboard would show '$name' as permanently missing/offline."
    fi
  done
fi

echo
if [ "$errors" -gt 0 ]; then
  echo "$profile: $errors error(s), $warnings warning(s) -- FAIL"
  exit 1
fi
echo "$profile: OK ($warnings warning(s))"
