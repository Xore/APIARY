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
# kept). Reload is done directly with SIGUSR2, Suricata's own documented
# live-rule-reload signal -- chosen over adding docker.sock access (a much
# bigger privilege grant just to run `docker kill`) because docker-
# compose.yml already gives this service `pid: "service:suricata"`: it
# shares Suricata's PID namespace, so the process is directly visible and
# signalable without touching Suricata's own container isolation or
# granting anything host-wide.

interval="${REFRESH_INTERVAL_SECONDS:-21600}"  # 6h -- ET Open and friends do not publish more often than this
start_delay="${START_DELAY:-21600}"            # first refresh well after the deploy-time suricata-update already ran

reload_suricata() {
  pid="$(pgrep -o -x suricata 2>/dev/null || true)"
  if [ -z "$pid" ]; then
    echo "suricata-rules-refresh: no running suricata process visible, skipping reload" >&2
    return 1
  fi
  kill -USR2 "$pid"
  echo "suricata-rules-refresh: sent SIGUSR2 (live rule reload) to suricata pid $pid" >&2
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
