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
    # -F: the parameter is documented as strings, and compiled as a regex
    # every needle was two silent failures at once (#2078): an invalid
    # pattern made grep exit 2, which the `if` read as "no match" (needle
    # inert), while valid-but-ERE patterns like a\|b matched something
    # narrower than what the operator typed. Fixed strings eliminate both.
    status=0
    grep -qaiF -- "$needle" "$sample" 2>/dev/null || status=$?
    if (( status == 0 )); then
      echo "sample contains denylisted string" >&2
      exit 1
    elif (( status >= 2 )); then
      # grep could not run the check (unreadable sample, internal error).
      # On the one gate whose job is to refuse, "could not check" must not
      # read as a pass (#2078).
      echo "check-denylist: string check could not run (grep exit $status) -- refusing" >&2
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
  logs_root=${HONEYPOT_LOGS_DIR:-/opt/stacks/apiary/logs}
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
      # Strictly IPv4 before any arithmetic. bash's $(( )) dies on syntax
      # errors -- "2001:db8::1" aborted the whole script outright, and
      # `|| echo -1` cannot catch an expansion error, only a failed
      # command -- so validate the shape first, then force decimal with
      # 10# so an octet like "08" doesn't read as invalid octal (#2078).
      local re='^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' a b c d
      if ! [[ $1 =~ $re ]]; then
        echo -1
        return
      fi
      IFS='.' read -r a b c d <<<"$1"
      if (( 10#$a > 255 || 10#$b > 255 || 10#$c > 255 || 10#$d > 255 )); then
        echo -1
        return
      fi
      printf '%s\n' "$(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))"
    }
    ip_int=$(ip_to_int "$source_ip" 2>/dev/null || echo -1)
    if (( ip_int < 0 )); then
      # The range check cannot apply to what it cannot parse (IPv6 sources
      # today). Log the skip so a future denylist audit starts from visible
      # data, not silence (#2078).
      echo "check-denylist: source '$source_ip' is not parseable as IPv4 -- CIDR check skipped for this sample" >&2
    else
      IFS=',' read -ra cidrs <<<"$cidrs_csv"
      for cidr in "${cidrs[@]}"; do
        cidr=$(printf '%s' "$cidr" | sed -e 's/^ *//' -e 's/ *$//')
        [[ -n $cidr ]] || continue
        # A bare IP is a host entry: treat it as /32 rather than skipping it
        # (#2078) -- an operator writing 203.0.113.5 meant a block, not a
        # no-op that only /32 would have delivered.
        [[ $cidr == */* ]] || cidr+="/32"
        net=${cidr%/*}; bits=${cidr#*/}
        net_int=$(ip_to_int "$net" 2>/dev/null || echo -1)
        if (( net_int < 0 )); then
          echo "check-denylist: denylist entry '$cidr' is not parseable as IPv4 -- skipped, fix the config" >&2
          continue
        fi
        # A negative shift count is another fatal arithmetic abort; keep
        # malformed prefix lengths out of $(( )) entirely (#2078).
        if ! [[ $bits =~ ^[0-9]+$ ]] || (( bits > 32 )); then
          echo "check-denylist: denylist entry '$cidr' has an invalid prefix length -- skipped, fix the config" >&2
          continue
        fi
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
