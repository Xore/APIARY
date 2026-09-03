#!/bin/bash
# #2898: dockerd's own restart-manager can fail to bring an `unless-stopped`
# (or `always`/`on-failure`) container back after it exits, and does not retry.
# Confirmed twice on this host from journalctl -u docker:
#   - hp-p0f, 2026-08-27: "restartmanger wait error: failed to create task
#     for container: AlreadyExists: task ...: already exists" -- stayed
#     Exited for 6 days with zero further restart attempts.
#   - hp-traefik-log-rotate, 2026-08-31: "restartmanger wait error: failed
#     to join PID namespace: container ... is not running" during a bulk
#     dockerd restart -- stayed Exited for 2+ days.
# Both are dockerd/containerd race conditions in the restart-manager itself,
# not application bugs, and both are silent: no alert, no crash-loop-visible
# signal, just a container that never comes back. This script is a coarse
# safety net underneath that: anything Docker itself promised to keep
# running (a real restart policy, not `no`) that has been Exited for longer
# than GRACE_SECONDS gets an explicit `docker start`, logged either way so
# `docker logs hp-container-watchdog` (or journalctl, once installed as a
# systemd timer) shows when it had to intervene.
#
# GRACE_SECONDS deliberately allows time for an intentional
# `docker stop <name>` done for maintenance to sit before this forces it back
# up -- not a guarantee against fighting an operator, just a delay long
# enough that a human doing hands-on work notices before it fires.
set -euo pipefail

GRACE_SECONDS="${GRACE_SECONDS:-300}"
now_epoch="$(date -u +%s)"

docker ps -a \
  --filter 'status=exited' \
  --format '{{.ID}}' |
while read -r cid; do
  [ -z "$cid" ] && continue

  read -r name policy finished_at exit_code < <(
    docker inspect "$cid" --format '{{.Name}} {{.HostConfig.RestartPolicy.Name}} {{.State.FinishedAt}} {{.State.ExitCode}}'
  )
  name="${name#/}"

  case "$policy" in
    unless-stopped|always) ;;
    # Docker itself only restarts `on-failure` containers on a non-zero exit,
    # so neither may this -- a one-shot with `restart: on-failure` that
    # completed successfully must stay Exited. Nothing on this host uses the
    # policy today; the guard exists so adding one later does not turn this
    # watchdog into a restart loop.
    on-failure) [ "$exit_code" -ne 0 ] || continue ;;
    *) continue ;;
  esac

  finished_epoch="$(date -u -d "$finished_at" +%s 2>/dev/null || echo "$now_epoch")"
  age=$(( now_epoch - finished_epoch ))

  if [ "$age" -ge "$GRACE_SECONDS" ]; then
    echo "$(date -u -Iseconds) watchdog: $name exited $((age / 60))m ago (restart policy: $policy), forcing docker start" >&2
    if docker start "$cid" >/dev/null 2>&1; then
      echo "$(date -u -Iseconds) watchdog: $name restarted" >&2
    else
      echo "$(date -u -Iseconds) watchdog: $name restart FAILED -- needs manual attention" >&2
    fi
  fi
done
