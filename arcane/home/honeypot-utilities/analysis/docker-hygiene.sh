#!/bin/sh
set -eu

# #252: T-Pot's own daily cron does `docker container prune -f; docker image
# prune -f; docker volume prune -f` plus a full-stack stop/reboot -- not
# something to copy wholesale (this stack's own zero-downtime goals, #212,
# go the other direction). But the underlying problem -- dangling images
# from routine `docker compose build` rebuilds accumulating with nothing
# ever reclaiming them -- is real, and had no equivalent here at all.
#
# Deliberately narrower than T-Pot's version:
#   - container prune only ever removes already-STOPPED containers, safe
#     by construction, never touches anything running.
#   - image prune is age-bounded (--filter until=<hours>h), not blanket --
#     an image built minutes ago for a redeploy in progress is never a
#     target, only ones old enough that nothing still building/deploying
#     could plausibly need them.
#   - volume prune is NOT run here, ever. Several named volumes in this
#     stack (es-data, dionaea-lib, dashboard-state, ...) are deliberately
#     long-lived state; an unattended blanket volume prune risks real data
#     loss if a volume is briefly unmounted/unreferenced during a redeploy
#     window. Volume hygiene, if wanted, needs its own separate, carefully
#     scoped pass -- not bundled into this one.
#
# Talks to docker-socket-proxy (arcane/home/honeypot-utilities/compose.yml), never the raw
# socket -- same trust boundary autoheal already uses, IMAGES=1 added
# alongside its existing CONTAINERS=1/POST=1 grant for this job specifically.

interval="${HYGIENE_INTERVAL:-604800}"   # weekly by default
start_delay="${HYGIENE_START_DELAY:-300}"
image_max_age_hours="${HYGIENE_IMAGE_MAX_AGE_HOURS:-168}"  # 1 week
docker_host="${DOCKER_PROXY_URL:-http://docker-socket-proxy:2375}"

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

log() { echo "docker-hygiene: $*" >&2; }

prune_containers() {
  resp="$(curl -fsS -X POST "$docker_host/containers/prune" 2>/dev/null)" || {
    log "container prune request failed"
    return 0
  }
  reclaimed="$(printf '%s' "$resp" | sed -n 's/.*"SpaceReclaimed":\([0-9]*\).*/\1/p')"
  removed="$(printf '%s' "$resp" | grep -o '"ContainersDeleted":\[[^]]*\]' | grep -o '"[a-f0-9]\{12,64\}"' | wc -l | tr -d ' ')"
  log "containers pruned: ${removed:-0} removed, ${reclaimed:-0} bytes reclaimed"
}

prune_images() {
  # Docker's prune filter takes a JSON-encoded map of string arrays.
  # "dangling":["true"] is explicit, not relied on as an API default --
  # this must never remove a still-tagged, in-use-by-name image, only
  # untagged layers left behind by a rebuild.
  filters="$(printf '{"until":["%sh"],"dangling":["true"]}' "$image_max_age_hours")"
  encoded="$(printf '%s' "$filters" | sed "s/{/%7B/g; s/}/%7D/g; s/\[/%5B/g; s/\]/%5D/g; s/\"/%22/g; s/:/%3A/g; s/,/%2C/g")"
  resp="$(curl -fsS -X POST "$docker_host/images/prune?filters=$encoded" 2>/dev/null)" || {
    log "image prune request failed"
    return 0
  }
  reclaimed="$(printf '%s' "$resp" | sed -n 's/.*"SpaceReclaimed":\([0-9]*\).*/\1/p')"
  removed="$(printf '%s' "$resp" | grep -o '"Deleted":"[a-f0-9:]*"' | wc -l | tr -d ' ')"
  log "images pruned (older than ${image_max_age_hours}h, dangling only): ${removed:-0} removed, ${reclaimed:-0} bytes reclaimed"
}

sleep "$start_delay"

while true; do
  log "starting pass ($(now))"
  prune_containers
  prune_images
  sleep "$interval"
done
