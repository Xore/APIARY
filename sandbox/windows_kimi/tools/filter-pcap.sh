#!/usr/bin/env bash
# filter-pcap.sh - strip persona noise from a capture, leaving payload traffic.
#
# The noise generator (provision/70-traffic-noise.ps1) tags everything it
# produces three ways:
#   1. DNS/hostnames matching *.mcg-persona.net
#   2. HTTP header  X-Persona-Noise: 1
#   3. User-Agent containing  MCGPersona/1.0
#
# Marker visibility differs by layer, because the https half is REAL TLS
# since #2449 (FakeNet terminates SSL with the static persona CA from
# provision/40-fakenet.ps1; detnode.ini sets UseSSL + static_ca):
#   - On a host-side pcap, 443 sessions are encrypted. Only the
#     *.mcg-persona.net SNI (and the DNS lookups) match here -- clauses
#     (1) and the tls SNI clause below.
#   - The X-Persona-Noise header and the MCGPersona UA travel INSIDE the
#     stream FakeNet itself terminates: visible in FakeNet's own HTTP(S)
#     logs and on the plain-HTTP share of requests (clauses 2/3).
#
# This script builds a display filter from the marker list and writes a clean
# pcap. Usage:
#   ./filter-pcap.sh in.pcap out_clean.pcap [out_noise.pcap]
set -euo pipefail

IN="${1:?usage: filter-pcap.sh in.pcap out_clean.pcap [out_noise.pcap]}"
CLEAN="${2:?output clean pcap required}"
NOISE="${3:-}"

# Truth source for the suffix: the $noiseHosts marker list in
# provision/70-traffic-noise.ps1 -- change it there and here together.
SUFFIX="mcg-persona.net"

# tshark display filter: keep everything EXCEPT noise.
# DNS queries/responses naming the suffix, HTTP requests carrying the marker
# header or UA, and TLS SNI matching the suffix.
NOISE_FILTER=$(cat <<EOF
( dns.qry.name matches "\\.${SUFFIX//./\\.}\$" ) or
( http.request matches "X-Persona-Noise" ) or
( http.user_agent contains "MCGPersona" ) or
( tls.handshake.extensions_server_name matches "${SUFFIX//./\\.}\$" )
EOF
)

echo "[*] Filtering noise ($SUFFIX, X-Persona-Noise, MCGPersona UA) from $IN"
tshark -r "$IN" -Y "not ($NOISE_FILTER)" -w "$CLEAN"
echo "[+] Clean pcap: $CLEAN  ($(du -h "$CLEAN" | cut -f1))"

if [ -n "$NOISE" ]; then
  tshark -r "$IN" -Y "$NOISE_FILTER" -w "$NOISE"
  echo "[+] Noise pcap: $NOISE  (kept for reference / baseline stats)"
fi

# Caveats printed for the analyst:
cat <<'NOTE'

[!] Filtering caveats:
    - Encrypted 443 noise is only matchable by SNI + DNS in a host-side
      pcap (the X-Persona-Noise header and persona UA are inside the TLS
      stream; they are visible in FakeNet's own HTTP logs). TLS without
      SNI visibility (ECH, or non-browser noise) can only be filtered by
      hostname at the DNS layer; correlate by 5-tuple if needed.
    - Noise requests answered by FakeNet inside the guest never hit this pcap
      if you capture on the guest's vnet with restrict=on; capture on the
      host bridge (detnet0/virbrX) to see everything.
    - Payload traffic that happens to reuse the persona UA string is NOT
      filtered (only the exact MCGPersona marker is), so true positives
      survive.
NOTE
