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
#
# #2907: `docker start` alone cannot repair every case this catches. A
# container that joins another container's PID (or IPC) namespace holds a
# *snapshot* of that container's ID, and once the target has been recreated
# the binding is permanently stale -- `docker start` then fails with
# "failed to join PID namespace: No such container: <stale-id>", forever.
# That is not a compose-level spelling mistake to fix: hp-traefik-log-rotate
# is already declared the by-name way, `pid: "service:traefik"` in
# vps/docker-compose.yml, and Docker still materialises it into
# `container:<id>` at create time (verified live 2026-09-04:
# HostConfig.PidMode is the live traefik container's ID, not a service name).
# There is no form of the declaration that survives the target's recreation.
# Only a full recreate rebinds it -- the `docker compose up -d --no-deps
# traefik-log-rotate` an operator ran by hand on 2026-09-01. So this script
# escalates to exactly that, and only for this error class; every other
# start failure still surfaces as "needs manual attention" rather than
# being silently papered over with a recreate.
set -euo pipefail

GRACE_SECONDS="${GRACE_SECONDS:-300}"

compose_label() {
  docker inspect "$1" --format "{{index .Config.Labels \"$2\"}}" 2>/dev/null
}

# #2907: the escalation described in the header. Returns 0 only when the
# container was actually recreated; every other path returns non-zero so the
# caller still reports the original start failure verbatim.
recreate_stale_namespace_binding() {
  local cid="$1" name="$2" start_error="$3"

  # Narrow on purpose. A generic "start failed, so recreate it" would rebuild
  # containers for unrelated reasons (a bad image, a missing volume, a port
  # already bound) and destroy the evidence of why they failed.
  case "$start_error" in
    *"join PID namespace"*|*"join IPC namespace"*) ;;
    *) return 1 ;;
  esac

  local service workdir config_files
  service="$(compose_label "$cid" com.docker.compose.service)"
  workdir="$(compose_label "$cid" com.docker.compose.project.working_dir)"
  config_files="$(compose_label "$cid" com.docker.compose.project.config_files)"
  # Read from the container's own labels rather than hardcoding /root/vps, so
  # this keeps working if the stack moves and does nothing at all for a
  # container compose did not create.
  if [ -z "$service" ] || [ -z "$workdir" ] || [ -z "$config_files" ]; then
    return 1
  fi
  [ -d "$workdir" ] || return 1

  local -a compose_args=(--project-directory "$workdir")
  local file
  # `project.config_files` is comma-separated when a stack is composed from
  # an overlay, and each entry is already an absolute path.
  while IFS= read -r file; do
    [ -n "$file" ] || continue
    [ -f "$file" ] || return 1
    compose_args+=(-f "$file")
  done <<< "${config_files//,/$'\n'}"

  echo "$(date -u -Iseconds) watchdog: $name has a stale namespace binding; recreating service $service from $config_files" >&2
  docker compose "${compose_args[@]}" up -d --no-deps "$service" >/dev/null 2>&1
}

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
    if start_error="$(docker start "$cid" 2>&1 >/dev/null)"; then
      echo "$(date -u -Iseconds) watchdog: $name restarted" >&2
    elif recreate_stale_namespace_binding "$cid" "$name" "$start_error"; then
      echo "$(date -u -Iseconds) watchdog: $name recreated -- docker start could not repair its stale namespace binding (#2907)" >&2
    else
      echo "$(date -u -Iseconds) watchdog: $name restart FAILED -- needs manual attention: ${start_error}" >&2
    fi
  fi
done
