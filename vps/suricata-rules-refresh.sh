#!/bin/sh
set -eu

# #116: suricata-update only ever ran once, at deploy time -- the one-shot
# suricata-update service (docker-compose.yml), gated by suricata's
# depends_on: service_completed_successfully so a fresh volume never starts
# Suricata with zero rules. ET Open, OISF TrafficID, abuse.ch SSLBL, and
# tgreen/hunting all publish on their own upstream cadence, independent of
# when this repo happens to deploy -- once deploys space out, the ruleset
# silently goes stale with no signal anywhere.
#
# This is a SEPARATE standing service, not a change to that one-shot:
# turning suricata-update itself into a loop would break its
# service_completed_successfully gate (a loop never exits, so Suricata
# would never start on a fresh deploy/volume). This service's own
# depends_on: suricata: condition: service_started means it plays no part
# in that cold-start guarantee -- it only keeps an already-running
# Suricata's rules current afterward.
#
# Reload: no unix-command control socket is configured in suricata.yaml,
# so suricata-update itself has no live-reload path here (--no-reload is
# kept). The mechanism below -- SIGUSR2, Suricata's own documented
# live-rule-reload signal, sent to PID 1 in the shared namespace this
# container joins via docker-compose.yml's `pid: "service:suricata"` (no
# docker.sock needed) -- is real and was verified working: Suricata logged
# "rule reload starting" then "62843 rules successfully loaded, 0 rules
# failed, 0 rules skipped".
#
# It is disabled by default (ENABLE_LIVE_RELOAD unset) because that same
# live test OOM-killed Suricata a few seconds later: dmesg confirmed a
# cgroup OOM kill against suricata's 768M memory limit
# (docker-compose.yml). A live reload builds the entire new detection
# engine while the old one is still active (no detection gap), so memory
# roughly doubles for the transition -- 768M has no headroom for that with
# today's ~63k-rule set, even though it's enough for steady-state. Docker's
# restart: unless-stopped brought Suricata back within seconds and it
# rejoined the interface cleanly, but repeating that every refresh cycle,
# unattended, on a live IDS is not acceptable. Raise suricata's memory
# limit first (with headroom measured against a real reload, not guessed),
# then set ENABLE_LIVE_RELOAD=1. Until then this service only keeps rules
# fresh on disk -- the next deploy or manual restart picks them up.
enable_live_reload="${ENABLE_LIVE_RELOAD:-}"

interval="${REFRESH_INTERVAL_SECONDS:-21600}"  # 6h -- ET Open and friends do not publish more often than this
start_delay="${START_DELAY:-21600}"            # first refresh well after the deploy-time suricata-update already ran

reload_suricata() {
  if [ -z "$enable_live_reload" ]; then
    echo "suricata-rules-refresh: rules on disk refreshed; live reload is disabled (ENABLE_LIVE_RELOAD unset) -- see this script's header" >&2
    return 0
  fi
  if ! kill -0 1 2>/dev/null; then
    echo "suricata-rules-refresh: no process visible at PID 1, skipping reload" >&2
    return 1
  fi
  kill -USR2 1
  echo "suricata-rules-refresh: sent SIGUSR2 (live rule reload) to suricata (pid 1 in the shared namespace)" >&2
}

sleep "$start_delay"

while true; do
  if suricata-update update-sources \
      && suricata-update enable-source et/open \
      && suricata-update enable-source oisf/trafficid \
      && suricata-update enable-source abuse.ch/sslbl-blacklist \
      && suricata-update enable-source abuse.ch/sslbl-ja3 \
      && suricata-update enable-source etnetera/aggressive \
      && suricata-update enable-source tgreen/hunting \
      && { suricata-update disable-source ptresearch/attackdetection || true; } \
      && suricata-update \
           --local /custom/rules \
           --suricata-conf /custom/suricata.yaml \
           --disable-conf /custom/disable.conf \
           --no-reload
  then
    reload_suricata || echo "suricata-rules-refresh: update succeeded but reload failed -- rules on disk are fresh, the running process is not yet" >&2
  else
    echo "suricata-rules-refresh: suricata-update failed; will retry next interval" >&2
  fi
  sleep "$interval"
done
