#!/usr/bin/env bash
# validate-deploy-profile.sh — check a deploy-profiles/*.txt selection for
# real cross-stack consistency before it's used to deploy anything.
#
# #265 (rescoped to the post-#258 topology, see docs/deploy-profiles/README.md):
# T-Pot's compose/customizer.py walks an operator through a per-service
# choice and fails fast on an invalid combination rather than failing
# silently at runtime. This is the equivalent for this repo's current
# shape -- one compose file per stack instead of one compose file with many
# services, so the thing being validated is "which stacks exist" and "do
# their structural dependencies line up", not "which services within one
# file".
#
# History note (#2359): this script used to also cross-check the profile
# against `EXPECTED_SENSORS=` parsed live out of
# arcane/home/honeypot-dashboard/compose.yml, plus an
# --emit-expected-sensors helper that printed that value. Commit 824aa33d
# (#1628) removed the variable during the dashboard cutover completion --
# nothing consumes it anywhere now: source-health derives sensor liveness
# from observed event.sensor values (backend-service/src/health.rs), not
# from a static expectation list. The cross-check asserted against a
# contract with no owner, so both were deleted; what remains is what is
# actually enforceable against the tree today.
#
# Usage:
#   scripts/validate-deploy-profile.sh deploy-profiles/<name>.txt
#
# Design rule bought hard by #2359: every run ends with output. A check
# whose guard message must fire on missing input gets implemented so that
# message can never be killed before it prints (no bare command
# substitution whose failure aborts under set -e before fail() runs).

set -euo pipefail

# Removed-flag tombstone BEFORE any argument parsing that would treat the
# old spelling as a filename.
if [ "${1:-}" = "--emit-expected-sensors" ]; then
  echo "FAIL: --emit-expected-sensors was removed with the EXPECTED_SENSORS contract it printed (commit 824aa33d / #1628 deleted the variable; #2359 removed this flag). No static expectation list is maintained anywhere today -- source-health derives sensor liveness from observed event.sensor values." >&2
  exit 2
fi

profile="${1:?Usage: $0 deploy-profiles/<name>.txt}"
[ -f "$profile" ] || { echo "No such profile file: $profile" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Every sensor stack this profile format can name, used to decide whether a
# profile is sensor-bearing for the structural-dependency rules below.
# (Historically also keyed the EXPECTED_SENSORS cross-check; that consumer
# is gone -- see the history note in the header.)
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
  [beelzebub]="beelzebub"
  [hellpot]="hellpot"
  [elasticpot]="elasticpot"
  [galah]="galah"
  [sentrypeer]="sentrypeer"
  # wordpot retired with its stack (#2381); no profile may name it.
  [mailoney]="mailoney"
  [canarytokens]="canarytokens"
  [tanner]="tanner"
  [conpot]="conpot conpot-s7-1200 conpot-s7-1500 conpot-iec104 conpot-guardian conpot-kamstrup"
  [endlessh]="endlessh"
)

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
  if ! [ -d "$repo_root/arcane/home/honeypot-$line" ]; then
    fail "profile enables '$line' but no arcane/home/honeypot-$line/ stack exists -- typo or retired stack? The authoritative roster is arcane/manifests/home-production.json (#1502)."
  fi
  enabled["$line"]=1
done < "$profile"

has_sensor=false
for stack in "${!STACK_TO_SENSORS[@]}"; do
  [ -v "enabled[$stack]" ] && has_sensor=true
done

# ── structural dependencies ──────────────────────────────────────────────
if $has_sensor; then
  [ -v "enabled[init]" ] || fail "at least one sensor stack is enabled but 'init' is not -- honeypot-init's log-init/persona-apply/elasticsearch-setup jobs are what every sensor's entrypoint waits on."
  [ -v "enabled[elk]" ]  || fail "at least one sensor stack is enabled but 'elk' is not -- nothing ships events to Elasticsearch without Filebeat/honeypot-elk running."
fi
if [ -v "enabled[dashboard]" ]; then
  [ -v "enabled[elk]" ] || fail "'dashboard' is enabled but 'elk' is not -- the dashboard reads several sensors' events from Elasticsearch, not their log files (#403), and always needs it reachable."
  [ -v "enabled[keycloak]" ] || fail "'dashboard' is enabled but 'keycloak' is not -- the target dashboard authentication path uses native Keycloak OIDC."
fi
if $has_sensor && ! [ -v "enabled[utilities]" ]; then
  warn "'utilities' is not enabled -- no log rotation, disk-space monitoring, or autoheal for this deployment."
fi
if $has_sensor && ! [ -v "enabled[payload-analysis]" ]; then
  warn "'payload-analysis' is not enabled -- no payload dedup or YARA scanning for this deployment."
fi

# ── what this script deliberately no longer does ──────────────────────────
# Until #2359 this block cross-checked the profile against EXPECTED_SENSORS=
# parsed live from arcane/home/honeypot-dashboard/compose.yml. Commit 824aa33d
# (#1628) removed that variable when the dashboard cutover completed; the
# modern source-health view (backend-service/src/health.rs) answers
# "is this sensor alive" from observed event.sensor values and container
# topology instead of any static list, so there is nothing left to compare a
# profile against. The old check's own guard also could never speak: parsing
# via bare command substitution meant grep's exit 1 aborted under set -e
# before fail() ran. Both defects die together here; per the header's design
# rule, everything remaining always produces output.

echo
if [ "$errors" -gt 0 ]; then
  echo "$profile: $errors error(s), $warnings warning(s) -- FAIL"
  exit 1
fi
echo "$profile: OK ($warnings warning(s))"
