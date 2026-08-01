#!/bin/sh
# #152: statically compares the public TCP/UDP ports portbridge actually
# forwards (docker-compose.yml's RULES env var) against the ports
# honeypot-firewall.sh opens in ufw. These two lists drifted silently once
# already -- RULES picked up new sensors as they were added, honeypot-
# firewall.sh didn't, and nothing caught it until a docs pass noticed by
# hand. Run this after editing either file; wire it into CI if this repo
# ever adds a VPS-config lint job.
#
# Ports intentionally in RULES but NOT expected in honeypot-firewall.sh (or
# vice versa) go in EXCEPTIONS below as "proto:port:reason" -- none are
# needed as of #152, since portbridge is the sole source of truth for every
# raw (non-Traefik) port this script opens. Admin SSH (2222) and Traefik
# (80/443) are opened by hand per docs/CGNAT-DEPLOYMENT.md and are
# deliberately outside both RULES and this script, so they never appear
# here at all.
set -eu

repo_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
compose_file="${1:-$repo_dir/docker-compose.yml}"
firewall_script="${2:-$repo_dir/honeypot-firewall.sh}"

EXCEPTIONS=""

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

extract_rules_ports() {
    proto="$1"
    grep -oE 'RULES=[^"]*' "$compose_file" \
        | sed 's/^RULES=//' \
        | tr ' ' '\n' \
        | grep "^${proto}:" \
        | cut -d: -f2 \
        | sort -u
}

extract_fw_ports() {
    proto="$1"
    grep -B1 "ufw allow \"\${port}/${proto}\"" "$firewall_script" \
        | grep 'for port in' \
        | grep -oE '[0-9]+' \
        | sort -u
}

is_excepted() {
    proto="$1"
    port="$2"
    for e in $EXCEPTIONS; do
        case "$e" in
            "${proto}:${port}:"*) return 0 ;;
        esac
    done
    return 1
}

report() {
    label="$1"
    proto="$2"
    ports="$3"
    found=0
    for port in $ports; do
        if is_excepted "$proto" "$port"; then
            continue
        fi
        echo "$label: $proto/$port"
        found=1
    done
    return $found
}

status=0

extract_rules_ports tcp > "$tmp/rules_tcp"
extract_rules_ports udp > "$tmp/rules_udp"
extract_fw_ports tcp > "$tmp/fw_tcp"
extract_fw_ports udp > "$tmp/fw_udp"

missing_tcp="$(comm -23 "$tmp/rules_tcp" "$tmp/fw_tcp")"
missing_udp="$(comm -23 "$tmp/rules_udp" "$tmp/fw_udp")"
extra_tcp="$(comm -13 "$tmp/rules_tcp" "$tmp/fw_tcp")"
extra_udp="$(comm -13 "$tmp/rules_udp" "$tmp/fw_udp")"

report "portbridge forwards this but honeypot-firewall.sh does not open it" tcp "$missing_tcp" || status=1
report "portbridge forwards this but honeypot-firewall.sh does not open it" udp "$missing_udp" || status=1
report "honeypot-firewall.sh opens this but portbridge does not forward it" tcp "$extra_tcp" || status=1
report "honeypot-firewall.sh opens this but portbridge does not forward it" udp "$extra_udp" || status=1

if [ "$status" -eq 0 ]; then
    echo "OK: honeypot-firewall.sh matches portbridge's RULES exactly."
fi

exit "$status"
