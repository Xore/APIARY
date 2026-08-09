#!/usr/bin/env bash
# test-services.sh — VPS service connectivity check
# Tests every port and service exposed by the honeypot-stack on this VPS.
# Run as root or with sudo so nc raw TCP checks work reliably.
#
# Usage:
#   ./test-services.sh [HOST]
#   HOST defaults to localhost (127.0.0.1)
#   Pass a remote IP/hostname to test from outside:
#     ./test-services.sh 1.2.3.4

HOST="${1:-127.0.0.1}"
PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info() { echo -e "${CYAN}$1${NC}"; }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; }

# ── helpers ──────────────────────────────────────────────────────────────────

# tcp_open HOST PORT TIMEOUT
tcp_open() {
  local h="$1" p="$2" t="${3:-3}"
  timeout "$t" bash -c "</dev/tcp/$h/$p" 2>/dev/null
}

# curl_check LABEL URL [extra curl args...]
curl_check() {
  local label="$1"; shift
  local url="$1"; shift
  local http_code
  http_code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "$@" "$url" 2>/dev/null)
  if [[ "$http_code" =~ ^[1-5][0-9]{2}$ ]]; then
    pass "$label — HTTP $http_code"
  else
    fail "$label — no HTTP response (got: '$http_code')"
  fi
}

# tcp_check LABEL PORT
tcp_check() {
  local label="$1" port="$2"
  if tcp_open "$HOST" "$port" 3; then
    pass "$label — TCP:$port open"
  else
    fail "$label — TCP:$port unreachable"
  fi
}

# banner_check LABEL PORT EXPECTED_SUBSTR
banner_check() {
  local label="$1" port="$2" expect="$3"
  local banner
  banner=$(timeout 3 bash -c "cat </dev/tcp/$HOST/$port" 2>/dev/null | head -c 256)
  if echo "$banner" | grep -qi "$expect"; then
    pass "$label — TCP:$port banner contains '$expect'"
  elif tcp_open "$HOST" "$port" 3; then
    pass "$label — TCP:$port open (no expected banner, got: $(echo "$banner" | head -c 60))"
  else
    fail "$label — TCP:$port unreachable"
  fi
}

# udp_check LABEL PORT
udp_check() {
  local label="$1" port="$2"
  if command -v nc &>/dev/null; then
    echo -n '' | nc -u -w2 "$HOST" "$port" &>/dev/null
    pass "$label — UDP:$port packet sent (no ICMP unreach — assumed open)"
  else
    skip "$label — UDP:$port (nc not available)"
  fi
}

# ── main ─────────────────────────────────────────────────────────────────────

echo
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  VPS Service Connectivity Test  ·  host: $HOST${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo

# ── Traefik / reverse proxy ───────────────────────────────────────────────────
info "[Traefik]"
curl_check "HTTP→HTTPS redirect"  "http://$HOST/"          -L --max-redirs 1
curl_check "HTTPS (self-signed)"  "https://$HOST/"         --insecure

# ── socat proxied web services (HTTP) ─────────────────────────────────────────
info "[Socat — web services]"
curl_check "Static site"          "http://$HOST:8080/"
curl_check "Flask API"            "http://$HOST:5000/"
curl_check "Flask+Redis API"      "http://$HOST:5001/"
curl_check "Node.js Express API"  "http://$HOST:3000/"
curl_check "Uptime Kuma"          "http://$HOST:3001/"
curl_check "FileBrowser"          "http://$HOST:8070/"
curl_check "SvelteKit blog"       "http://$HOST:4174/"
curl_check "C# ASP.NET API"       "http://$HOST:5002/"
curl_check "Go key/value API"     "http://$HOST:5003/"
curl_check "Rust Axum API"        "http://$HOST:5004/"
curl_check "Upstream (HA/LAN)"   "http://$HOST:8123/"

# ── Game ports ────────────────────────────────────────────────────────────────
info "[Game ports]"
tcp_check  "Minecraft"            25565
udp_check  "CS2/Valheim UDP"      27015

# ── Honeypot — portbridge TCP services ───────────────────────────────────────
info "[Honeypot — TCP]"
banner_check "SSH honeypot"       22   "SSH"
tcp_check    "Telnet honeypot"    23
banner_check "SMTP honeypot"      25   "220"
tcp_check    "FTP honeypot"       21
tcp_check    "SMB honeypot"       445
tcp_check    "MSSQL honeypot"     1433
tcp_check    "MySQL honeypot"     3306
tcp_check    "PostgreSQL honeypot" 5432
tcp_check    "MongoDB honeypot"   27017
tcp_check    "Redis honeypot"     6379
tcp_check    "Elasticsearch"      9200
tcp_check    "Docker API honeypot" 2375
curl_check   "HTTP honeypot"      "http://$HOST:8081/"
tcp_check    "VNC honeypot"       5900
tcp_check    "PPTP honeypot"      1723
tcp_check    "SIP/VoIP TCP"       5060
tcp_check    "S7/ICS (Siemens)"   102
tcp_check    "Modbus/ICS"         502
tcp_check    "EtherNet/IP"        44818

# ── Honeypot — portbridge UDP services ───────────────────────────────────────
info "[Honeypot — UDP]"
udp_check  "SNMP honeypot"        161
udp_check  "BACnet honeypot"      47808
udp_check  "IPMI honeypot"        623
udp_check  "SIP/VoIP UDP"         5060

# ── Honeypot socat proxied services ───────────────────────────────────────────
info "[Honeypot — socat proxied]"
curl_check "Snare HTTP honeypot"  "http://$HOST:8082/"
curl_check "Honeypot dashboard"   "http://$HOST:8090/"
curl_check "Kibana"               "http://$HOST:5601/"
curl_check "Tanner"               "http://$HOST:8091/"
curl_check "EveBox"               "http://$HOST:5636/"

# ── Suricata (no port — just check the container is running) ──────────────────
info "[Suricata (local only)]"
if docker inspect hp-suricata &>/dev/null 2>&1; then
  STATUS=$(docker inspect -f '{{.State.Status}}' hp-suricata 2>/dev/null)
  if [[ "$STATUS" == "running" ]]; then
    pass "hp-suricata container running"
    RULES=$(docker exec hp-suricata grep -c '' /var/lib/suricata/rules/suricata.rules 2>/dev/null || echo 0)
    pass "Suricata rules loaded: $RULES lines in suricata.rules"
  else
    fail "hp-suricata container status: $STATUS"
  fi
else
  skip "Suricata check (docker not available or not local)"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
TOTAL=$((PASS + FAIL))
echo -e "  Results: ${GREEN}$PASS passed${NC} / ${RED}$FAIL failed${NC} / $TOTAL total"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo

[[ $FAIL -eq 0 ]]
