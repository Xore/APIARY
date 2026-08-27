#!/bin/sh
# Protocol-level liveness probe for SentryPeer's SIP/UDP listener (#2337).
#
# A TCP connect (compose's previous check) is not enough: the kernel accept
# backlog completes the handshake without the process -- exactly the wedge
# class #2107/#111 describe for sibling single-threaded reactors -- and
# SentryPeer's entire job here is servicing UDP datagrams that a TCP probe
# never exercises. This probe sends one minimal RFC 3261 OPTIONS request to
# 127.0.0.1:5060/udp and requires any "SIP/" response line back within the
# read window, which only a reactor that is actually scheduling datagrams
# can produce. Same doctrine as cowrie/bin/healthcheck-probe.py (#2107) --
# it just has to be POSIX sh + busybox nc, because this runtime image
# ships no python3 (python exists only in the build stage).
#
# Any reply status counts: 200 OK, 400, 500 -- what matters for liveness is
# that the parser + transaction layer answered at all. The pre-#1424 NUL-
# byte crash can't be re-triggered by this payload (no embedded NULs; see
# sentrypeer/nul_byte_crash_patch.py), and the post-patch handler survives
# arbitrary garbage regardless.
#
# Cost: one loopback datagram every 30s (~2880/day). Probe traffic from
# 127.0.0.1 lands in sentrypeer.json like any other invite, and the ingest
# enrichment auto-marks loopback-src_ip events honeypot.internal_probe
# (ip_enrichment/sensors.rs, same generic path as conpot/cowrie/dionaea),
# which every dashboard consumer excludes (#1677 doctrine).
#
# Usage: healthcheck-probe.sh [port]   (default 5060)
set -u

PORT="${1:-5060}"
WINDOW=2  # below the compose healthcheck's own 5s kill window

request='OPTIONS sip:sentrypeer@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:50701;branch=z9hG4bKhealthcheck\r\nFrom: <sip:probe@127.0.0.1>;tag=healthcheck\r\nTo: <sip:sentrypeer@127.0.0.1>\r\nCall-ID: healthcheck@127.0.0.1\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n'

reply=$(printf '%b' "$request" | nc -u -w "$WINDOW" 127.0.0.1 "$PORT" 2>/dev/null | head -c 256)

case $reply in
    *"SIP/"*)
        exit 0
        ;;
    *)
        echo "probe: no timely SIP response on :$PORT/udp" >&2
        exit 1
        ;;
esac
