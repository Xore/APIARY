#!/usr/bin/env bash
set -uo pipefail

# Interactive homeserver status overview. Individual checks are deliberately
# bounded so a failed remote mount or service cannot stall shell login.

if [[ ! -t 1 ]]; then
  exit 0
fi

if [[ -t 1 ]]; then
  bold=$'\e[1m'
  green=$'\e[32m'
  yellow=$'\e[33m'
  red=$'\e[31m'
  reset=$'\e[0m'
else
  bold=
  green=
  yellow=
  red=
  reset=
fi

section() {
  printf '\n%s%s== %s ==%s\n' "$bold" "$green" "$1" "$reset"
}

unit_status() {
  local unit=$1
  local state
  state=$(systemctl is-active "$unit" 2>/dev/null || true)
  case "$state" in
    active) printf '%-52s %s%s%s\n' "$unit" "$green" "$state" "$reset" ;;
    activating) printf '%-52s %s%s%s\n' "$unit" "$yellow" "$state" "$reset" ;;
    *) printf '%-52s %s%s%s\n' "$unit" "$red" "${state:-unknown}" "$reset" ;;
  esac
}

http_status() {
  local name=$1
  local url=$2
  local result
  result=$(timeout 6 curl --silent --show-error --output /dev/null \
    --write-out '%{http_code} %{time_total}s' "$url" 2>/dev/null || true)
  if [[ "$result" =~ ^(200|204|301|302|401|403)[[:space:]] ]]; then
    printf '%-18s %s%-14s%s %s\n' "$name" "$green" "$result" "$reset" "$url"
  else
    printf '%-18s %s%-14s%s %s\n' "$name" "$red" "${result:-unreachable}" \
      "$reset" "$url"
  fi
}

clear
if command -v fastfetch >/dev/null 2>&1; then
  fastfetch
else
  printf '%sfastfetch is not installed%s\n' "$yellow" "$reset"
fi

section "Host resources"
uptime
free --human
df --human-readable --output=source,size,used,avail,pcent,target / /var \
  2>/dev/null | awk '!seen[$0]++'

section "GPU"
if command -v nvidia-smi >/dev/null 2>&1; then
  timeout 8 nvidia-smi \
    --query-gpu=name,driver_version,utilization.gpu,utilization.memory,memory.used,memory.total,temperature.gpu,power.draw \
    --format=csv,noheader
else
  printf '%sNVIDIA utilities unavailable%s\n' "$yellow" "$reset"
fi

section "Network and boot-critical services"
ip -brief -4 address show ens9f0 2>/dev/null || true
ip -brief -4 address show eno2 2>/dev/null || true
ip -brief -4 address show wg0 2>/dev/null || true
ip -4 route show default
unit_status systemd-networkd-wait-online.service
unit_status wg-quick@wg0.service
unit_status docker.service
unit_status honeypot-log-mounts.service
unit_status 'var-dockge-stacks-honeypot\x2dstack-logs-suricata.mount'
unit_status 'var-dockge-stacks-honeypot\x2dstack-logs-portbridge.mount'
if timeout 4 ping -c 1 -W 2 10.8.0.1 >/dev/null 2>&1; then
  printf '%-52s %sreachable%s\n' 'WireGuard peer 10.8.0.1' "$green" "$reset"
else
  printf '%-52s %sunreachable%s\n' 'WireGuard peer 10.8.0.1' "$red" "$reset"
fi

section "Docker containers"
if timeout 6 docker info >/dev/null 2>&1; then
  docker ps --all \
    --format 'table {{.Names}}\t{{.State}}\t{{.Status}}\t{{.Image}}'
else
  printf '%sDocker daemon unavailable or permission denied%s\n' "$red" "$reset"
fi

section "Web service health"
http_status Dockge http://127.0.0.1:5001/
http_status Dashboard http://10.8.0.2:19090/healthz
http_status EveBox http://10.8.0.2:19636/
http_status Kibana http://10.8.0.2:19601/api/status
http_status Arkime http://10.8.0.2:19080/

section "Ingestion freshness"
for source_file in \
  /opt/stacks/honeypot-stack/logs/suricata/eve.json \
  /opt/stacks/honeypot-stack/logs/portbridge/portbridge.json; do
  if [[ -e "$source_file" ]]; then
    stat --format='%y  %s bytes  %n' "$source_file"
  else
    printf '%sMISSING%s %s\n' "$red" "$reset" "$source_file"
  fi
done

section "Failed systemd units"
failed_units=$(systemctl --failed --no-legend --plain 2>/dev/null || true)
if [[ -n "$failed_units" ]]; then
  printf '%s%s%s\n' "$red" "$failed_units" "$reset"
else
  printf '%snone%s\n' "$green" "$reset"
fi

printf '\n'
