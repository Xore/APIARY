#!/usr/bin/env bash
# check-denylist.sh <sample-path> <sha256> <denylist-strings> <denylist-cidrs>
#
# Exit 0: safe to publish. Exit 1 with a reason on stderr: refuse. Two
# independent checks, either one is sufficient to block -- see #74's
# retention-denylist decision for the reasoning behind each.
set -euo pipefail

sample=${1:?usage: check-denylist.sh <sample-path> <sha256> <strings> <cidrs>}
sha256=${2:?}
strings_csv=${3:-}
cidrs_csv=${4:-}

# 1. The sample's own bytes must not embed anything that would deanonymize
#    this sensor if a scanner or the public repo ever surfaced it back in a
#    report.
if [[ -n $strings_csv ]]; then
  IFS=',' read -ra needles <<<"$strings_csv"
  for needle in "${needles[@]}"; do
    needle=$(printf '%s' "$needle" | sed -e 's/^ *//' -e 's/ *$//')
    [[ -n $needle ]] || continue
    if grep -qai -- "$needle" "$sample" 2>/dev/null; then
      echo "sample contains denylisted string" >&2
      exit 1
    fi
  done
fi

# 2. The originating session's source IP must not be a private/loopback
#    range. Every real sensor sits behind the WireGuard tunnel from the VPS;
#    a private-range source means test traffic or a misattribution, not a
#    genuine capture. Looked up from the sensor's own JSON log by hash --
#    Dionaea logs the MD5 it stores the file under, everything else logs
#    SHA-256, so try both.
if [[ -n $cidrs_csv ]]; then
  md5=$(md5sum "$sample" 2>/dev/null | cut -d' ' -f1 || true)
  logs_root=${HONEYPOT_LOGS_DIR:-/opt/stacks/honeypot-stack/logs}
  source_ip=""
  for hash in "$sha256" "$md5"; do
    [[ -n $hash ]] || continue
    for log in "$logs_root"/cowrie/cowrie.json "$logs_root"/dionaea/dionaea.json; do
      [[ -f $log ]] || continue
      found=$(grep -F "$hash" "$log" 2>/dev/null | tail -n 1 || true)
      [[ -n $found ]] || continue
      ip=$(printf '%s' "$found" | jq -r '.src_ip // empty' 2>/dev/null || true)
      [[ -n $ip ]] && { source_ip=$ip; break 2; }
    done
  done

  if [[ -n $source_ip ]]; then
    ip_to_int() {
      local a b c d
      IFS='.' read -r a b c d <<<"$1"
      printf '%s\n' "$(( (a << 24) + (b << 16) + (c << 8) + d ))"
    }
    ip_int=$(ip_to_int "$source_ip" 2>/dev/null || echo -1)
    if (( ip_int >= 0 )); then
      IFS=',' read -ra cidrs <<<"$cidrs_csv"
      for cidr in "${cidrs[@]}"; do
        cidr=$(printf '%s' "$cidr" | sed -e 's/^ *//' -e 's/ *$//')
        [[ $cidr == */* ]] || continue
        net=${cidr%/*}; bits=${cidr#*/}
        net_int=$(ip_to_int "$net" 2>/dev/null || echo -1)
        (( net_int >= 0 )) || continue
        mask=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
        if (( (ip_int & mask) == (net_int & mask) )); then
          echo "originating source $source_ip is inside denylisted range $cidr" >&2
          exit 1
        fi
      done
    fi
  fi
  # No log record found for either hash: this is a gap (the sample could not
  # be attributed to a session), not a pass -- but Phase 1 chooses not to
  # block on an attribution miss, since that would also block every
  # legitimate capture whose log line rotated out before publish. Recorded
  # here rather than silently: a future pass could tighten this once log
  # retention and this feature's timing are both well understood together.
fi

exit 0
